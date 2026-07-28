import pg from "pg";
import { randomUUID, randomBytes } from "node:crypto";
import { encrypt, decrypt } from "./crypto.js";

let pool: pg.Pool | null = null;
let encKey = "";

export function initStore(databaseUrl: string, tokenEncKey: string): void {
  pool = new pg.Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: false } });
  encKey = tokenEncKey;
}

function getPool(): pg.Pool {
  if (!pool) throw new Error("Store not initialised");
  return pool;
}

/** True when a database is configured — otherwise callers fall back to memory. */
export function storeReady(): boolean {
  return !!pool;
}

export async function ensureSchema(): Promise<void> {
  const p = getPool();
  // Legacy single-account table (one row, id=1). Kept only so existing
  // deployments can migrate their row into google_accounts below.
  await p.query(`
    CREATE TABLE IF NOT EXISTS google_account (
      id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      email       TEXT NOT NULL,
      ref_enc     TEXT NOT NULL,
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Multi-account: the owner of this instance can link several Google accounts
  // (personal / work / ...), each selected per tool-call via the `account` arg.
  await p.query(`
    CREATE TABLE IF NOT EXISTS google_accounts (
      email       TEXT PRIMARY KEY,
      label       TEXT NOT NULL,
      ref_enc     TEXT NOT NULL,
      is_default  BOOLEAN NOT NULL DEFAULT FALSE,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // One-time migration: fold a legacy single account into the new table.
  await p.query(`
    INSERT INTO google_accounts (email, label, ref_enc, is_default)
    SELECT email, 'default', ref_enc, TRUE FROM google_account
    WHERE NOT EXISTS (SELECT 1 FROM google_accounts)
    ON CONFLICT (email) DO NOTHING
  `);
  // MCP OAuth: dynamically registered clients (Claude, etc).
  await p.query(`
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id           TEXT PRIMARY KEY,
      client_secret       TEXT,
      metadata             JSONB NOT NULL,
      issued_at            BIGINT NOT NULL,
      secret_expires_at    BIGINT NOT NULL DEFAULT 0
    )
  `);
  // MCP OAuth: authorization requests waiting on the Google redirect round-trip.
  // `mode` is 'mcp' for the Claude connect flow (mint an MCP code afterwards) or
  // 'dashboard' for the add-another-account flow (just store the account).
  await p.query(`
    CREATE TABLE IF NOT EXISTS oauth_pending (
      nonce         TEXT PRIMARY KEY,
      client_id     TEXT NOT NULL,
      redirect_uri  TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      scopes        TEXT NOT NULL,
      state         TEXT,
      resource      TEXT,
      mode          TEXT NOT NULL DEFAULT 'mcp',
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Older deployments created oauth_pending without `mode`; add it if missing.
  await p.query(`ALTER TABLE oauth_pending ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'mcp'`);
  // MCP OAuth: issued authorization codes (single use, short-lived).
  await p.query(`
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code          TEXT PRIMARY KEY,
      client_id     TEXT NOT NULL,
      redirect_uri  TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      scopes        TEXT NOT NULL,
      resource      TEXT,
      used          BOOLEAN NOT NULL DEFAULT FALSE,
      expires_at    BIGINT NOT NULL
    )
  `);
  // MCP OAuth: issued access/refresh tokens.
  await p.query(`
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      access_token   TEXT PRIMARY KEY,
      refresh_token  TEXT UNIQUE NOT NULL,
      client_id      TEXT NOT NULL,
      scopes         TEXT NOT NULL,
      resource       TEXT,
      expires_at     BIGINT NOT NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Short-lived links that let a client download one attachment itself
  // (see downloads.ts). Rows are disposable — losing them only invalidates
  // links that were already close to expiring.
  await p.query(`
    CREATE TABLE IF NOT EXISTS download_tokens (
      token         TEXT PRIMARY KEY,
      account       TEXT NOT NULL,
      message_id    TEXT NOT NULL,
      attachment_id TEXT NOT NULL,
      name          TEXT NOT NULL,
      mime_type     TEXT NOT NULL,
      size          BIGINT,
      expires_at    BIGINT NOT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // gmail_snooze: archived now, waiting to be un-archived at wake_at. user_token
  // is nullable — onboarded (native-OAuth) deployments have no static per-user
  // token, only an account_label, which is always present and is what the
  // scheduler actually keys off.
  await p.query(`
    CREATE TABLE IF NOT EXISTS email_snoozes (
      id            BIGSERIAL PRIMARY KEY,
      user_token    TEXT,
      account_label TEXT NOT NULL,
      message_id    TEXT NOT NULL,
      subject       TEXT,
      wake_at       TIMESTAMPTZ NOT NULL,
      status        TEXT NOT NULL DEFAULT 'pending',
      error         TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // gmail_schedule_send: the raw RFC 822 message is built and validated (incl.
  // resolving attachments) at schedule time, so the scheduler's job at send_at
  // is just "hand this exact raw string to Gmail" — nothing left to fail on
  // account of stale Drive files or a since-changed body.
  await p.query(`
    CREATE TABLE IF NOT EXISTS scheduled_sends (
      id              BIGSERIAL PRIMARY KEY,
      user_token      TEXT,
      account_label   TEXT NOT NULL,
      raw_message     TEXT NOT NULL,
      to_preview      TEXT NOT NULL,
      subject_preview TEXT NOT NULL,
      send_at         TIMESTAMPTZ NOT NULL,
      status          TEXT NOT NULL DEFAULT 'pending',
      error           TEXT,
      sent_message_id TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

// ---- Download links ----

export interface DownloadTarget {
  /** Account label the attachment belongs to — resolved again when the link is used. */
  account: string;
  messageId: string;
  attachmentId: string;
  name: string;
  mimeType: string;
  size?: number;
  expiresAt: number;
}

export async function saveDownloadToken(token: string, t: DownloadTarget): Promise<void> {
  const p = getPool();
  // Opportunistic cleanup — expired links are worthless, nothing waits on this.
  await p.query(`DELETE FROM download_tokens WHERE expires_at < $1`, [Date.now()]);
  await p.query(
    `INSERT INTO download_tokens (token, account, message_id, attachment_id, name, mime_type, size, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [token, t.account, t.messageId, t.attachmentId, t.name, t.mimeType, t.size ?? null, t.expiresAt],
  );
}

/** Returns the target for a still-valid token, or null when unknown/expired. */
export async function getDownloadToken(token: string): Promise<DownloadTarget | null> {
  const p = getPool();
  const res = await p.query(`SELECT * FROM download_tokens WHERE token = $1 AND expires_at > $2`, [
    token,
    Date.now(),
  ]);
  if (!res.rows.length) return null;
  const row = res.rows[0];
  return {
    account: row.account,
    messageId: row.message_id,
    attachmentId: row.attachment_id,
    name: row.name,
    mimeType: row.mime_type,
    size: row.size === null ? undefined : Number(row.size),
    expiresAt: Number(row.expires_at),
  };
}

// ---- Google accounts (multi-account, one owner per instance) ----

export interface GoogleAccount {
  email: string;
  label: string;
  isDefault: boolean;
  refreshToken: string;
}

export interface GoogleAccountMeta {
  email: string;
  label: string;
  isDefault: boolean;
}

/** Derive a starting label from an email (local-part), deduped against existing labels. */
function deriveLabel(email: string, taken: Set<string>): string {
  const base = (email.split("@")[0] || "account").replace(/[^a-zA-Z0-9._-]/g, "") || "account";
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) {
    const cand = `${base}${i}`;
    if (!taken.has(cand)) return cand;
  }
}

/**
 * Link (or re-link) a Google account for this instance. Keyed by verified email:
 * re-authorizing the same account refreshes its token and keeps its label. The
 * first account ever added becomes the default.
 */
export async function addGoogleAccount(email: string, refreshToken: string): Promise<GoogleAccountMeta> {
  const p = getPool();
  const enc = encrypt(refreshToken, encKey);
  const existing = await p.query(`SELECT label, is_default FROM google_accounts WHERE email = $1`, [email]);
  if (existing.rows.length) {
    await p.query(`UPDATE google_accounts SET ref_enc = $2, updated_at = NOW() WHERE email = $1`, [email, enc]);
    return { email, label: existing.rows[0].label, isDefault: existing.rows[0].is_default };
  }
  const all = await p.query(`SELECT label FROM google_accounts`);
  const taken = new Set<string>(all.rows.map((r) => r.label));
  const label = deriveLabel(email, taken);
  const isDefault = all.rows.length === 0;
  await p.query(
    `INSERT INTO google_accounts (email, label, ref_enc, is_default) VALUES ($1, $2, $3, $4)`,
    [email, label, enc, isDefault],
  );
  return { email, label, isDefault };
}

/** All accounts (metadata only — no secrets), default first then by creation. */
export async function listGoogleAccounts(): Promise<GoogleAccountMeta[]> {
  if (!pool) return [];
  const p = getPool();
  const res = await p.query(
    `SELECT email, label, is_default FROM google_accounts ORDER BY is_default DESC, created_at ASC`,
  );
  return res.rows.map((r) => ({ email: r.email, label: r.label, isDefault: r.is_default }));
}

/** All accounts including decrypted refresh tokens — for building Google clients. */
export async function getGoogleAccounts(): Promise<GoogleAccount[]> {
  if (!pool) return [];
  const p = getPool();
  const res = await p.query(
    `SELECT email, label, is_default, ref_enc FROM google_accounts ORDER BY is_default DESC, created_at ASC`,
  );
  return res.rows.map((r) => ({
    email: r.email,
    label: r.label,
    isDefault: r.is_default,
    refreshToken: decrypt(r.ref_enc, encKey),
  }));
}

/** The stored refresh token for one email, or undefined when not linked yet. */
export async function getRefreshTokenByEmail(email: string): Promise<string | undefined> {
  if (!pool) return undefined;
  const p = getPool();
  const res = await p.query(`SELECT ref_enc FROM google_accounts WHERE email = $1`, [email]);
  if (!res.rows.length) return undefined;
  return decrypt(res.rows[0].ref_enc, encKey);
}

/** Remove an account. If it was the default, promote the oldest remaining one. */
export async function removeGoogleAccount(email: string): Promise<boolean> {
  const p = getPool();
  const del = await p.query(`DELETE FROM google_accounts WHERE email = $1 RETURNING is_default`, [email]);
  if (!del.rows.length) return false;
  if (del.rows[0].is_default) {
    await p.query(
      `UPDATE google_accounts SET is_default = TRUE
       WHERE email = (SELECT email FROM google_accounts ORDER BY created_at ASC LIMIT 1)`,
    );
  }
  return true;
}

/** Make `email` the sole default. */
export async function setDefaultAccount(email: string): Promise<boolean> {
  const p = getPool();
  const hit = await p.query(`SELECT 1 FROM google_accounts WHERE email = $1`, [email]);
  if (!hit.rows.length) return false;
  await p.query(`UPDATE google_accounts SET is_default = (email = $1)`, [email]);
  return true;
}

/** Rename an account's label (must stay unique). */
export async function renameAccount(email: string, label: string): Promise<boolean> {
  const p = getPool();
  const clean = label.trim().replace(/[^a-zA-Z0-9._-]/g, "");
  if (!clean) return false;
  const clash = await p.query(`SELECT 1 FROM google_accounts WHERE label = $1 AND email <> $2`, [clean, email]);
  if (clash.rows.length) return false;
  const res = await p.query(`UPDATE google_accounts SET label = $2, updated_at = NOW() WHERE email = $1`, [email, clean]);
  return (res.rowCount ?? 0) > 0;
}

// ---- OAuth clients (RFC 7591 dynamic client registration) ----

export interface StoredClient {
  client_id: string;
  client_secret?: string;
  client_id_issued_at: number;
  client_secret_expires_at: number;
  [key: string]: unknown;
}

export async function saveClient(client: StoredClient): Promise<void> {
  const p = getPool();
  await p.query(
    `INSERT INTO oauth_clients (client_id, client_secret, metadata, issued_at, secret_expires_at)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (client_id) DO UPDATE SET client_secret = $2, metadata = $3, issued_at = $4, secret_expires_at = $5`,
    [client.client_id, client.client_secret ?? null, JSON.stringify(client), client.client_id_issued_at, client.client_secret_expires_at],
  );
}

export async function getClient(clientId: string): Promise<StoredClient | undefined> {
  const p = getPool();
  const res = await p.query(`SELECT metadata FROM oauth_clients WHERE client_id = $1`, [clientId]);
  if (!res.rows.length) return undefined;
  return res.rows[0].metadata as StoredClient;
}

// ---- Pending authorization (waiting on Google redirect) ----

export type PendingMode = "mcp" | "dashboard";

export interface PendingAuth {
  nonce: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  state?: string;
  resource?: string;
  mode: PendingMode;
}

export async function savePendingAuth(p1: PendingAuth): Promise<void> {
  const p = getPool();
  await p.query(
    `INSERT INTO oauth_pending (nonce, client_id, redirect_uri, code_challenge, scopes, state, resource, mode)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [p1.nonce, p1.clientId, p1.redirectUri, p1.codeChallenge, p1.scopes.join(" "), p1.state ?? null, p1.resource ?? null, p1.mode],
  );
}

export async function takePendingAuth(nonce: string): Promise<PendingAuth | null> {
  const p = getPool();
  const res = await p.query(`DELETE FROM oauth_pending WHERE nonce = $1 RETURNING *`, [nonce]);
  if (!res.rows.length) return null;
  const row = res.rows[0];
  return {
    nonce: row.nonce,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    scopes: row.scopes.split(" ").filter(Boolean),
    state: row.state ?? undefined,
    resource: row.resource ?? undefined,
    mode: (row.mode as PendingMode) ?? "mcp",
  };
}

// ---- Authorization codes ----

export interface IssuedCode {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
}

const CODE_TTL_MS = 10 * 60 * 1000;

export async function issueCode(args: Omit<IssuedCode, "code">): Promise<string> {
  const p = getPool();
  const code = randomBytes(32).toString("base64url");
  await p.query(
    `INSERT INTO oauth_codes (code, client_id, redirect_uri, code_challenge, scopes, resource, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [code, args.clientId, args.redirectUri, args.codeChallenge, args.scopes.join(" "), args.resource ?? null, Date.now() + CODE_TTL_MS],
  );
  return code;
}

/** Consumes a code (marks used); returns null if missing, already used, or expired. */
export async function consumeCode(code: string): Promise<IssuedCode | null> {
  const p = getPool();
  const res = await p.query(
    `UPDATE oauth_codes SET used = TRUE WHERE code = $1 AND used = FALSE AND expires_at > $2 RETURNING *`,
    [code, Date.now()],
  );
  if (!res.rows.length) return null;
  const row = res.rows[0];
  return {
    code: row.code,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    scopes: row.scopes.split(" ").filter(Boolean),
    resource: row.resource ?? undefined,
  };
}

export async function peekCodeChallenge(code: string): Promise<string | null> {
  const p = getPool();
  const res = await p.query(`SELECT code_challenge FROM oauth_codes WHERE code = $1 AND used = FALSE`, [code]);
  return res.rows[0]?.code_challenge ?? null;
}

// ---- Access/refresh tokens ----

export interface IssuedTokens {
  accessToken: string;
  refreshToken: string;
  clientId: string;
  scopes: string[];
  resource?: string;
  expiresAt: number; // seconds since epoch
}

const ACCESS_TOKEN_TTL_SEC = 60 * 60; // 1 hour

export async function issueTokens(clientId: string, scopes: string[], resource?: string): Promise<IssuedTokens> {
  const p = getPool();
  const accessToken = randomBytes(32).toString("base64url");
  const refreshToken = randomBytes(32).toString("base64url");
  const expiresAt = Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_SEC;
  await p.query(
    `INSERT INTO oauth_tokens (access_token, refresh_token, client_id, scopes, resource, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [accessToken, refreshToken, clientId, scopes.join(" "), resource ?? null, expiresAt],
  );
  return { accessToken, refreshToken, clientId, scopes, resource, expiresAt };
}

export async function findByAccessToken(accessToken: string): Promise<IssuedTokens | null> {
  const p = getPool();
  const res = await p.query(`SELECT * FROM oauth_tokens WHERE access_token = $1`, [accessToken]);
  if (!res.rows.length) return null;
  const row = res.rows[0];
  return {
    accessToken: row.access_token,
    refreshToken: row.refresh_token,
    clientId: row.client_id,
    scopes: row.scopes.split(" ").filter(Boolean),
    resource: row.resource ?? undefined,
    expiresAt: Number(row.expires_at),
  };
}

export async function findByRefreshToken(refreshToken: string): Promise<IssuedTokens | null> {
  const p = getPool();
  const res = await p.query(`SELECT * FROM oauth_tokens WHERE refresh_token = $1`, [refreshToken]);
  if (!res.rows.length) return null;
  const row = res.rows[0];
  return {
    accessToken: row.access_token,
    refreshToken: row.refresh_token,
    clientId: row.client_id,
    scopes: row.scopes.split(" ").filter(Boolean),
    resource: row.resource ?? undefined,
    expiresAt: Number(row.expires_at),
  };
}

/** Rotates: deletes the old row, caller inserts a new one via issueTokens. */
export async function deleteTokenByRefresh(refreshToken: string): Promise<void> {
  const p = getPool();
  await p.query(`DELETE FROM oauth_tokens WHERE refresh_token = $1`, [refreshToken]);
}

export async function deleteTokenByAccess(accessToken: string): Promise<void> {
  const p = getPool();
  await p.query(`DELETE FROM oauth_tokens WHERE access_token = $1`, [accessToken]);
}

// ---- Snoozed emails (wake up + return to Inbox at wake_at) ----

export interface SnoozeRow {
  id: number;
  userToken: string | null;
  accountLabel: string;
  messageId: string;
  subject: string | null;
  wakeAt: Date;
}

export async function addSnooze(row: {
  userToken: string | null;
  accountLabel: string;
  messageId: string;
  subject?: string;
  wakeAt: Date;
}): Promise<void> {
  const p = getPool();
  await p.query(
    `INSERT INTO email_snoozes (user_token, account_label, message_id, subject, wake_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [row.userToken, row.accountLabel, row.messageId, row.subject ?? null, row.wakeAt],
  );
}

/** All still-pending snoozes for an account, soonest first — for a future "list snoozed" tool. */
export async function listPendingSnoozes(accountLabel: string): Promise<SnoozeRow[]> {
  const p = getPool();
  const res = await p.query(
    `SELECT * FROM email_snoozes WHERE account_label = $1 AND status = 'pending' ORDER BY wake_at ASC`,
    [accountLabel],
  );
  return res.rows.map(rowToSnooze);
}

/**
 * Atomically claims every snooze whose wake_at has arrived, flipping it to
 * 'processing' in the same statement — so two overlapping poller ticks (or
 * two server instances) can never both act on the same row.
 */
export async function claimDueSnoozes(now: Date): Promise<SnoozeRow[]> {
  const p = getPool();
  const res = await p.query(
    `UPDATE email_snoozes SET status = 'processing'
     WHERE id IN (SELECT id FROM email_snoozes WHERE status = 'pending' AND wake_at <= $1 FOR UPDATE SKIP LOCKED)
     RETURNING *`,
    [now],
  );
  return res.rows.map(rowToSnooze);
}

export async function markSnoozeDone(id: number): Promise<void> {
  const p = getPool();
  await p.query(`UPDATE email_snoozes SET status = 'done' WHERE id = $1`, [id]);
}

export async function markSnoozeFailed(id: number, error: string): Promise<void> {
  const p = getPool();
  // Back to 'pending' (not a terminal 'failed') so the next tick retries —
  // transient Google errors (rate limit, blip) shouldn't strand a snooze forever.
  await p.query(`UPDATE email_snoozes SET status = 'pending', error = $2 WHERE id = $1`, [id, error]);
}

function rowToSnooze(row: {
  id: number;
  user_token: string | null;
  account_label: string;
  message_id: string;
  subject: string | null;
  wake_at: Date;
}): SnoozeRow {
  return {
    id: Number(row.id),
    userToken: row.user_token,
    accountLabel: row.account_label,
    messageId: row.message_id,
    subject: row.subject,
    wakeAt: new Date(row.wake_at),
  };
}

// ---- Scheduled sends (send this exact raw message at send_at) ----

export interface ScheduledSendRow {
  id: number;
  userToken: string | null;
  accountLabel: string;
  rawMessage: string;
  toPreview: string;
  subjectPreview: string;
  sendAt: Date;
}

export async function addScheduledSend(row: {
  userToken: string | null;
  accountLabel: string;
  rawMessage: string;
  toPreview: string;
  subjectPreview: string;
  sendAt: Date;
}): Promise<number> {
  const p = getPool();
  const res = await p.query(
    `INSERT INTO scheduled_sends (user_token, account_label, raw_message, to_preview, subject_preview, send_at)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [row.userToken, row.accountLabel, row.rawMessage, row.toPreview, row.subjectPreview, row.sendAt],
  );
  return Number(res.rows[0].id);
}

/** Pending scheduled sends for an account, soonest first. */
export async function listScheduledSends(accountLabel: string): Promise<ScheduledSendRow[]> {
  const p = getPool();
  const res = await p.query(
    `SELECT * FROM scheduled_sends WHERE account_label = $1 AND status = 'pending' ORDER BY send_at ASC`,
    [accountLabel],
  );
  return res.rows.map(rowToScheduledSend);
}

/** Cancels a still-pending send. Returns false if it was already sent, canceled, or unknown. */
export async function cancelScheduledSend(id: number, accountLabel: string): Promise<boolean> {
  const p = getPool();
  const res = await p.query(
    `UPDATE scheduled_sends SET status = 'canceled'
     WHERE id = $1 AND account_label = $2 AND status = 'pending'`,
    [id, accountLabel],
  );
  return (res.rowCount ?? 0) > 0;
}

/** Same claim-and-lock pattern as claimDueSnoozes — see its comment. */
export async function claimDueSends(now: Date): Promise<ScheduledSendRow[]> {
  const p = getPool();
  const res = await p.query(
    `UPDATE scheduled_sends SET status = 'sending'
     WHERE id IN (SELECT id FROM scheduled_sends WHERE status = 'pending' AND send_at <= $1 FOR UPDATE SKIP LOCKED)
     RETURNING *`,
    [now],
  );
  return res.rows.map(rowToScheduledSend);
}

export async function markSendSent(id: number, sentMessageId: string): Promise<void> {
  const p = getPool();
  await p.query(`UPDATE scheduled_sends SET status = 'sent', sent_message_id = $2 WHERE id = $1`, [
    id,
    sentMessageId,
  ]);
}

export async function markSendFailed(id: number, error: string): Promise<void> {
  const p = getPool();
  // Unlike a snoozed email (safe to retry — modify() is idempotent), retrying a
  // send risks a DUPLICATE email if the first attempt actually went through but
  // the response was lost. Fail terminally and surface the error instead.
  await p.query(`UPDATE scheduled_sends SET status = 'failed', error = $2 WHERE id = $1`, [id, error]);
}

function rowToScheduledSend(row: {
  id: number;
  user_token: string | null;
  account_label: string;
  raw_message: string;
  to_preview: string;
  subject_preview: string;
  send_at: Date;
}): ScheduledSendRow {
  return {
    id: Number(row.id),
    userToken: row.user_token,
    accountLabel: row.account_label,
    rawMessage: row.raw_message,
    toPreview: row.to_preview,
    subjectPreview: row.subject_preview,
    sendAt: new Date(row.send_at),
  };
}

export { randomUUID };
