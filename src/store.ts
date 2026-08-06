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
  // Resumable-upload session URIs Google handed THIS server (see
  // uploadSessions.ts). Kept server-side precisely so the address never has to
  // come back IN from a tool argument — gmail_confirm_upload takes an opaque
  // `sessionId` and looks the real address up here. Rows are disposable: a
  // Drive session dies after ~a week anyway.
  await p.query(`
    CREATE TABLE IF NOT EXISTS upload_sessions (
      id            TEXT PRIMARY KEY,
      account       TEXT NOT NULL,
      upload_url    TEXT NOT NULL,
      drive_file_id TEXT,
      name          TEXT,
      mime_type     TEXT NOT NULL,
      size_bytes    BIGINT,
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
  // When a send is claimed it flips to 'sending'; if the process dies before
  // it records a result, the row is stranded there forever — invisible to a
  // pending-only list and never re-claimed. sending_since lets the reaper find
  // and fail such rows (see reapStuckSends). Older deployments lack the column.
  await p.query(`ALTER TABLE scheduled_sends ADD COLUMN IF NOT EXISTS sending_since TIMESTAMPTZ`);

  // ---- Consent gate (packages A1/A2/A3, mcp-development-standard/references
  // /gate.md §3). ONE physical Postgres is shared by all 5 MCP servers
  // (gmail/sheets/calendar/docs/drive) — `server` isolates rows per server
  // ($self, never a tool argument). DDL is FROZEN ahead of stage-3 T2 (the
  // port to the other 4 repos): once T2 starts, any DDL change here must be
  // applied to all 5 `ensureSchema()` copies in the same pass, or `CREATE
  // TABLE IF NOT EXISTS` silently lets them drift apart (plan §0.4).
  //
  // Times are epoch-milliseconds (BIGINT), not TIMESTAMPTZ — consent.ts's
  // `ConsentManifestRow`/`ConsentAuditEntry` types declare plain `number`
  // fields (it injects a fake `now()` for offline unit tests, which only
  // works cleanly against numbers), same convention as oauth_codes.expires_at.
  await p.query(`
    CREATE TABLE IF NOT EXISTS consent_manifests (
      id            TEXT PRIMARY KEY,
      server        TEXT NOT NULL,
      tool          TEXT NOT NULL,
      account_label TEXT NOT NULL,
      payload       JSONB NOT NULL,
      object_hash   TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'AWAITING_CONSENT',
      created_at    BIGINT NOT NULL,
      expires_at    BIGINT NOT NULL,
      consumed_at   BIGINT,
      user_reply    TEXT
    )
  `);
  await p.query(
    `CREATE INDEX IF NOT EXISTS consent_manifests_cleanup_idx ON consent_manifests (server, status, expires_at)`,
  );
  // Append-only audit trail. Written in two phases (plan §0.4/[R:полнота-3]):
  // appendConsentAudit() at the gate DECISION (confirmed/refused/invalidated),
  // then updateConsentAuditOutcome() fills in what the MUTATION actually did
  // (post-verify, error) — a package downstream of A1 (A3) calls the second
  // half after it has actually sent/trashed/whatever. pre_snapshot/
  // post_verify_result/error stay NULL until something populates them; see
  // the honesty note on updateConsentAuditOutcome() below.
  await p.query(`
    CREATE TABLE IF NOT EXISTS consent_audit (
      id                 TEXT PRIMARY KEY,
      ts                 BIGINT NOT NULL,
      server             TEXT NOT NULL,
      tool               TEXT NOT NULL,
      account_label      TEXT NOT NULL,
      manifest_id        TEXT,
      object_hash        TEXT,
      user_reply         TEXT NOT NULL,
      checks             JSONB NOT NULL,
      outcome            TEXT NOT NULL,
      refusal_reason     TEXT,
      actor              TEXT NOT NULL DEFAULT 'human',
      pre_snapshot       JSONB,
      post_verify_result TEXT,
      error              TEXT
    )
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS consent_audit_server_ts_idx ON consent_audit (server, ts DESC)`);

  // ---- Optional Telegram-approval layer (package P1, plan-tg-approval.md
  // §2/§7). Purely ADDITIVE — consent_manifests/consent_audit above are FROZEN
  // and untouched. Off by default (TG_APPROVAL_ENABLED=false): this table is
  // created unconditionally (cheap, keeps schema identical between a fork with
  // and without the Telegram bot configured) but stays empty when the feature
  // is off, since consent.ts's `tg` branch is never invoked in that case.
  // Times are epoch-milliseconds (BIGINT), same convention as consent_manifests.
  await p.query(`
    CREATE TABLE IF NOT EXISTS tg_approvals (
      manifest_id TEXT PRIMARY KEY,
      server      TEXT NOT NULL,
      chat_id     TEXT NOT NULL,
      message_id  BIGINT,
      status      TEXT NOT NULL DEFAULT 'PENDING',
      created_at  BIGINT NOT NULL,
      expires_at  BIGINT NOT NULL,
      decided_at  BIGINT
    )
  `);
  await p.query(
    `CREATE INDEX IF NOT EXISTS tg_approvals_cleanup_idx ON tg_approvals (server, status, expires_at)`,
  );
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

// ---- Resumable upload sessions ----

/** One resumable-upload session as THIS server remembers it. `uploadUrl` is
 * the address Google itself handed back; it is deliberately never accepted
 * from a tool argument (see uploadSessions.ts). */
export interface UploadSessionRecord {
  account: string;
  uploadUrl: string;
  /** The staged Drive placeholder the bytes are being PATCHed into. */
  driveFileId: string | null;
  name: string | null;
  mimeType: string;
  sizeBytes: number | null;
  expiresAt: number;
}

export async function saveUploadSession(id: string, s: UploadSessionRecord): Promise<void> {
  const p = getPool();
  // Opportunistic cleanup — an expired session URI is worthless to anyone.
  await p.query(`DELETE FROM upload_sessions WHERE expires_at < $1`, [Date.now()]);
  await p.query(
    `INSERT INTO upload_sessions (id, account, upload_url, drive_file_id, name, mime_type, size_bytes, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [id, s.account, s.uploadUrl, s.driveFileId, s.name, s.mimeType, s.sizeBytes, s.expiresAt],
  );
}

/** Returns a still-valid session, or null when unknown/expired. */
export async function getUploadSession(id: string): Promise<UploadSessionRecord | null> {
  const p = getPool();
  const res = await p.query(`SELECT * FROM upload_sessions WHERE id = $1 AND expires_at > $2`, [
    id,
    Date.now(),
  ]);
  if (!res.rows.length) return null;
  const row = res.rows[0];
  return {
    account: row.account,
    uploadUrl: row.upload_url,
    driveFileId: row.drive_file_id ?? null,
    name: row.name ?? null,
    mimeType: row.mime_type,
    sizeBytes: row.size_bytes === null ? null : Number(row.size_bytes),
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
  status: string;
  error: string | null;
  sentMessageId: string | null;
  sendingSince: Date | null;
}

/** Statuses a caller may filter scheduled sends by; 'all' means no filter. */
export type ScheduledSendStatus = "pending" | "failed" | "sending" | "sent" | "canceled" | "all";

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

/**
 * Scheduled sends for an account, soonest first, filtered by status (default
 * 'pending'). 'all' returns every non-null status so failed/stuck rows are
 * finally visible — the fix for incident 1, where a failed row was invisible to
 * every tool.
 */
export async function listScheduledSends(
  accountLabel: string,
  status: ScheduledSendStatus = "pending",
): Promise<ScheduledSendRow[]> {
  const p = getPool();
  const res =
    status === "all"
      ? await p.query(`SELECT * FROM scheduled_sends WHERE account_label = $1 ORDER BY send_at ASC`, [accountLabel])
      : await p.query(
          `SELECT * FROM scheduled_sends WHERE account_label = $1 AND status = $2 ORDER BY send_at ASC`,
          [accountLabel, status],
        );
  return res.rows.map(rowToScheduledSend);
}

/** How many scheduled sends an account has in a given status (e.g. 'failed'). */
export async function countScheduledSends(accountLabel: string, status: string): Promise<number> {
  const p = getPool();
  const res = await p.query(
    `SELECT COUNT(*)::int AS n FROM scheduled_sends WHERE account_label = $1 AND status = $2`,
    [accountLabel, status],
  );
  return res.rows[0]?.n ?? 0;
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
  // Stamp sending_since alongside the status flip, so a crash between here and
  // the result write leaves a timestamped 'sending' row the reaper can find.
  const res = await p.query(
    `UPDATE scheduled_sends SET status = 'sending', sending_since = NOW()
     WHERE id IN (SELECT id FROM scheduled_sends WHERE status = 'pending' AND send_at <= $1 FOR UPDATE SKIP LOCKED)
     RETURNING *`,
    [now],
  );
  return res.rows.map(rowToScheduledSend);
}

/**
 * Fails rows stuck in 'sending' longer than `olderThanMinutes` — a process that
 * died mid-send. NEVER re-sends: Gmail has no idempotency key, so a retry could
 * duplicate a mail that actually went out (see markSendFailed). The row is
 * marked failed with an explicit "check Sent manually" note and becomes visible
 * via listScheduledSends(status='failed'). Returns how many were reaped.
 */
export async function reapStuckSends(olderThanMinutes: number): Promise<number> {
  const p = getPool();
  const res = await p.query(
    `UPDATE scheduled_sends
       SET status = 'failed',
           error = 'процесс перезапустился во время отправки — статус неизвестен, проверьте отправленные вручную'
     WHERE status = 'sending'
       AND sending_since IS NOT NULL
       AND sending_since < NOW() - ($1 || ' minutes')::interval
     RETURNING id`,
    [String(olderThanMinutes)],
  );
  return res.rowCount ?? 0;
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
  status?: string;
  error?: string | null;
  sent_message_id?: string | null;
  sending_since?: Date | null;
}): ScheduledSendRow {
  return {
    id: Number(row.id),
    userToken: row.user_token,
    accountLabel: row.account_label,
    rawMessage: row.raw_message,
    toPreview: row.to_preview,
    subjectPreview: row.subject_preview,
    sendAt: new Date(row.send_at),
    status: row.status ?? "pending",
    error: row.error ?? null,
    sentMessageId: row.sent_message_id ?? null,
    sendingSince: row.sending_since ? new Date(row.sending_since) : null,
  };
}

// ---- Consent gate: manifests + audit (package A1) --------------------------
//
// These functions implement `ConsentStore` from `src/consent.ts` SIGNATURE-FOR-
// SIGNATURE (checked below via `satisfies`/type annotation in server.ts) — this
// file does not import consent.ts (store.ts stays a leaf module; consent.ts is
// the generic, portable one). `server` is always the caller's own constant
// ($self, e.g. "gmail") — every query filters on it so the 5 servers sharing
// this Postgres can never see each other's manifests/audit rows.

export interface ConsentManifestRow {
  id: string;
  server: string;
  tool: string;
  accountLabel: string;
  payload: unknown;
  objectHash: string;
  status: "AWAITING_CONSENT" | "DONE" | "INVALIDATED";
  createdAt: number;
  expiresAt: number;
  consumedAt: number | null;
  userReply: string | null;
}

export interface ConsentAuditEntry {
  id: string;
  ts: number;
  server: string;
  tool: string;
  accountLabel: string;
  manifestId?: string | null;
  objectHash?: string | null;
  userReply: string;
  checks: Record<string, string>;
  outcome: "confirmed" | "refused" | "invalidated";
  refusalReason?: string | null;
  actor: string;
}

function rowToManifest(row: {
  id: string;
  server: string;
  tool: string;
  account_label: string;
  payload: unknown;
  object_hash: string;
  status: string;
  created_at: string | number;
  expires_at: string | number;
  consumed_at: string | number | null;
  user_reply: string | null;
}): ConsentManifestRow {
  return {
    id: row.id,
    server: row.server,
    tool: row.tool,
    accountLabel: row.account_label,
    payload: row.payload,
    objectHash: row.object_hash,
    status: row.status as ConsentManifestRow["status"],
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    consumedAt: row.consumed_at === null ? null : Number(row.consumed_at),
    userReply: row.user_reply,
  };
}

/** Inserts a new manifest in AWAITING_CONSENT. Opportunistically sweeps this
 * server's own expired-but-still-AWAITING rows first (same pattern as
 * download_tokens above) — nothing waits on the sweep, it just keeps the
 * shared table from growing unboundedly across all 5 servers. */
export async function createManifest(input: {
  id: string;
  server: string;
  tool: string;
  accountLabel: string;
  payload: unknown;
  objectHash: string;
  createdAt: number;
  expiresAt: number;
}): Promise<void> {
  const p = getPool();
  await p.query(
    `DELETE FROM consent_manifests WHERE server = $1 AND status = 'AWAITING_CONSENT' AND expires_at < $2`,
    [input.server, Date.now()],
  );
  await p.query(
    `INSERT INTO consent_manifests
       (id, server, tool, account_label, payload, object_hash, status, created_at, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, 'AWAITING_CONSENT', $7, $8)`,
    [
      input.id,
      input.server,
      input.tool,
      input.accountLabel,
      JSON.stringify(input.payload),
      input.objectHash,
      input.createdAt,
      input.expiresAt,
    ],
  );
}

/** Reads a manifest scoped to `server`; null if missing OR belongs to another server. */
export async function getManifest(id: string, server: string): Promise<ConsentManifestRow | null> {
  const p = getPool();
  const res = await p.query(`SELECT * FROM consent_manifests WHERE id = $1 AND server = $2`, [id, server]);
  if (!res.rows.length) return null;
  return rowToManifest(res.rows[0]);
}

/**
 * Atomic one-shot consume — the eventual `[R:полнота]` proof against the double-
 * execute race, same shape as `consumeCode` above: a single `UPDATE … WHERE …
 * RETURNING` closes the race in the database, not in JS. Succeeds only if the
 * row is still AWAITING_CONSENT, belongs to `server`, AND has not expired
 * (checked against the SAME `now` value used to stamp `consumed_at`, so there's
 * no window between the compare and the write). Returns null on any miss
 * (unknown id, wrong server, already DONE/INVALIDATED, or expired) — the
 * caller (consent.ts) treats every one of those the same way: refuse.
 */
export async function consumeManifest(
  id: string,
  server: string,
  userReply: string,
): Promise<ConsentManifestRow | null> {
  const p = getPool();
  const now = Date.now();
  const res = await p.query(
    `UPDATE consent_manifests
        SET status = 'DONE', consumed_at = $4, user_reply = $3
      WHERE id = $1 AND server = $2 AND status = 'AWAITING_CONSENT' AND expires_at > $4
      RETURNING *`,
    [id, server, userReply, now],
  );
  if (!res.rows.length) return null;
  return rowToManifest(res.rows[0]);
}

/** Marks a manifest INVALIDATED (explicit user negation). No-op if it's not
 * currently AWAITING_CONSENT for this server (already consumed/expired/invalidated). */
export async function invalidateManifest(id: string, server: string, userReply: string): Promise<void> {
  const p = getPool();
  await p.query(
    `UPDATE consent_manifests SET status = 'INVALIDATED', user_reply = $3
      WHERE id = $1 AND server = $2 AND status = 'AWAITING_CONSENT'`,
    [id, server, userReply],
  );
}

/** Append-only: one row per gate decision (confirmed/refused/invalidated). */
export async function appendConsentAudit(entry: ConsentAuditEntry): Promise<void> {
  const p = getPool();
  await p.query(
    `INSERT INTO consent_audit
       (id, ts, server, tool, account_label, manifest_id, object_hash, user_reply, checks, outcome, refusal_reason, actor)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      entry.id,
      entry.ts,
      entry.server,
      entry.tool,
      entry.accountLabel,
      entry.manifestId ?? null,
      entry.objectHash ?? null,
      entry.userReply,
      JSON.stringify(entry.checks),
      entry.outcome,
      entry.refusalReason ?? null,
      entry.actor,
    ],
  );
}

/**
 * Phase 2 of the audit row: fills in what the MUTATION actually did, called by
 * whichever package wires the gate into a real tool (A3) AFTER it has sent/
 * trashed/whatever — never by consent.ts itself. Matches `ConsentStore`'s
 * 2-argument contract exactly; `preSnapshot` is an EXTRA optional field beyond
 * that contract (consent.ts's `ConsentAuditEntry`/`updateConsentAuditOutcome`
 * types carry no pre-snapshot field at all — see the honest gap noted in the
 * A1 handoff). It's additive and optional, so passing it or not both satisfy
 * `ConsentStore` structurally; A3 can start using it whenever it's ready
 * without any further change here.
 */
export async function updateConsentAuditOutcome(
  auditId: string,
  outcome: {
    outcome?: "confirmed" | "failed";
    postVerify?: string | null;
    error?: string | null;
    preSnapshot?: unknown;
  },
): Promise<void> {
  const p = getPool();
  await p.query(
    `UPDATE consent_audit SET
       outcome = COALESCE($2, outcome),
       post_verify_result = COALESCE($3, post_verify_result),
       error = COALESCE($4, error),
       pre_snapshot = COALESCE($5, pre_snapshot)
     WHERE id = $1`,
    [
      auditId,
      outcome.outcome ?? null,
      outcome.postVerify ?? null,
      outcome.error ?? null,
      outcome.preSnapshot !== undefined ? JSON.stringify(outcome.preSnapshot) : null,
    ],
  );
}

export interface ConsentAuditFilters {
  server: string;
  since?: number;
  until?: number;
  accountLabel?: string;
  tool?: string;
  outcome?: string;
}

export interface ConsentAuditRow extends ConsentAuditEntry {
  postVerifyResult: string | null;
  error: string | null;
  preSnapshot: unknown;
}

/** Shared WHERE-clause builder for `listConsentAudit`/`countConsentAudit`, so
 * the two can never drift apart on which rows they mean by "matching the
 * filters" (a `total` from one query and rows from a different filter set
 * would be a worse lie than no total at all). */
function buildAuditWhere(filters: ConsentAuditFilters): { where: string; params: unknown[] } {
  const conds: string[] = [`server = $1`];
  const params: unknown[] = [filters.server];
  if (filters.since != null) {
    params.push(filters.since);
    conds.push(`ts >= $${params.length}`);
  }
  if (filters.until != null) {
    params.push(filters.until);
    conds.push(`ts <= $${params.length}`);
  }
  if (filters.accountLabel) {
    params.push(filters.accountLabel);
    conds.push(`account_label = $${params.length}`);
  }
  if (filters.tool) {
    params.push(filters.tool);
    conds.push(`tool = $${params.length}`);
  }
  if (filters.outcome) {
    params.push(filters.outcome);
    conds.push(`outcome = $${params.length}`);
  }
  return { where: conds.join(" AND "), params };
}

/** Read path for A4's `gmail_consent_audit` — "разбор инцидента без ssh"
 * (limits-audit.md §11). `server` is required and always the caller's own
 * constant; `limit` is capped to 100 regardless of what's asked (limits-audit
 * §10.1), default 20. `offset` powers pagination through older rows (§10.1
 * "показано N из M" — never a silent truncation); newest first. */
export async function listConsentAudit(
  filters: ConsentAuditFilters,
  limit = 20,
  offset = 0,
): Promise<ConsentAuditRow[]> {
  const p = getPool();
  const cap = Math.min(Math.max(Math.trunc(limit) || 20, 1), 100);
  const off = Math.max(Math.trunc(offset) || 0, 0);
  const { where, params } = buildAuditWhere(filters);
  params.push(cap);
  const limitIdx = params.length;
  params.push(off);
  const offsetIdx = params.length;
  const res = await p.query(
    `SELECT * FROM consent_audit WHERE ${where} ORDER BY ts DESC LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
    params,
  );
  return res.rows.map((row) => ({
    id: row.id,
    ts: Number(row.ts),
    server: row.server,
    tool: row.tool,
    accountLabel: row.account_label,
    manifestId: row.manifest_id ?? null,
    objectHash: row.object_hash ?? null,
    userReply: row.user_reply,
    checks: row.checks ?? {},
    outcome: row.outcome,
    refusalReason: row.refusal_reason ?? null,
    actor: row.actor,
    postVerifyResult: row.post_verify_result ?? null,
    error: row.error ?? null,
    preSnapshot: row.pre_snapshot ?? null,
  }));
}

/** Total rows matching `filters` (ignoring limit/offset) — lets `gmail_consent_audit`
 * say "shown 20 of 143" honestly (limits-audit.md §10.1: silent truncation is
 * never allowed) and tell the caller whether another page exists. */
export async function countConsentAudit(filters: ConsentAuditFilters): Promise<number> {
  const p = getPool();
  const { where, params } = buildAuditWhere(filters);
  const res = await p.query(`SELECT COUNT(*)::int AS n FROM consent_audit WHERE ${where}`, params);
  return res.rows[0]?.n ?? 0;
}

// ---- Optional Telegram-approval layer (package P1) --------------------------
//
// Implements `TgApprovalStore` from `src/tg_approval.ts` SIGNATURE-FOR-
// SIGNATURE (checked via `: TgApprovalStore` in server.ts, same discipline as
// `consentStoreAdapter` above). `server` is always the caller's own constant
// ($self) — every query filters on it so the 5 servers sharing this Postgres
// can never cross-read each other's approval rows.

export interface TgApprovalRow {
  manifestId: string;
  server: string;
  chatId: string;
  messageId: number | null;
  status: "PENDING" | "APPROVED" | "REJECTED";
  createdAt: number;
  expiresAt: number;
  decidedAt: number | null;
}

function rowToTgApproval(row: {
  manifest_id: string;
  server: string;
  chat_id: string;
  message_id: string | number | null;
  status: string;
  created_at: string | number;
  expires_at: string | number;
  decided_at: string | number | null;
}): TgApprovalRow {
  return {
    manifestId: row.manifest_id,
    server: row.server,
    chatId: row.chat_id,
    messageId: row.message_id === null ? null : Number(row.message_id),
    status: row.status as TgApprovalRow["status"],
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    decidedAt: row.decided_at === null ? null : Number(row.decided_at),
  };
}

/** Inserts a new PENDING approval row. `manifest_id` is a fresh UUID minted by
 * consent.ts's plan phase — collisions are not expected, so this is a plain
 * INSERT (not upsert), matching consent_manifests' createManifest above. */
export async function createTgApproval(input: {
  manifestId: string;
  server: string;
  chatId: string;
  messageId: number | null;
  createdAt: number;
  expiresAt: number;
}): Promise<void> {
  const p = getPool();
  await p.query(
    `INSERT INTO tg_approvals (manifest_id, server, chat_id, message_id, status, created_at, expires_at)
     VALUES ($1, $2, $3, $4, 'PENDING', $5, $6)`,
    [input.manifestId, input.server, input.chatId, input.messageId, input.createdAt, input.expiresAt],
  );
}

/** Reads an approval row scoped to `server`; null if missing OR belongs to another server. */
export async function getTgApproval(manifestId: string, server: string): Promise<TgApprovalRow | null> {
  const p = getPool();
  const res = await p.query(`SELECT * FROM tg_approvals WHERE manifest_id = $1 AND server = $2`, [
    manifestId,
    server,
  ]);
  if (!res.rows.length) return null;
  return rowToTgApproval(res.rows[0]);
}

/**
 * Atomic one-shot decision, same shape as `consumeManifest` above: a single
 * `UPDATE … WHERE status = 'PENDING' … RETURNING` closes the double-tap /
 * replay race in the database. Returns null on any miss (unknown manifest,
 * wrong server, already APPROVED/REJECTED, OR the approval row's OWN TTL has
 * expired) — the webhook handler treats a miss as "already handled, no-op"
 * (idempotent against Telegram retries). The TTL check is checked against the
 * SAME `now` value used to stamp `decided_at`, so there's no window between
 * the compare and the write (mirrors `consumeManifest`'s `expires_at > $4`
 * guard on consent_manifests). Without this, a button tapped after the
 * approval row's own TTL — but while the underlying CONSENT manifest is still
 * AWAITING_CONSENT — would record a decision `checkApproval` had already
 * started treating as "none" (TTL-expired), which is a self-inconsistent
 * result even though `notifyPlan` caps the row's `expiresAt` at the consent
 * manifest's own expiry (their windows coincide by default, but must not be
 * assumed to always coincide — this table's TTL is independently
 * configurable via `TG_APPROVAL_TTL_MS`, see `tg_approval.ts`'s
 * `notifyPlan`).
 */
export async function consumeTgDecision(
  manifestId: string,
  server: string,
  status: "APPROVED" | "REJECTED",
): Promise<TgApprovalRow | null> {
  const p = getPool();
  const now = Date.now();
  const res = await p.query(
    `UPDATE tg_approvals SET status = $3, decided_at = $4
      WHERE manifest_id = $1 AND server = $2 AND status = 'PENDING' AND expires_at > $4
      RETURNING *`,
    [manifestId, server, status, now],
  );
  if (!res.rows.length) return null;
  return rowToTgApproval(res.rows[0]);
}

/**
 * Server-agnostic sibling of `consumeTgDecision` above — same atomic
 * `UPDATE … WHERE status = 'PENDING' … RETURNING` shape, but WITHOUT the
 * `server` filter. Exists for the shared-bot webhook path (see
 * `tg_approval.ts`'s `handleWebhook` + `TgApprovalStore.
 * consumeTgDecisionAnyServer`): one Telegram bot token is now shared across
 * several MCP servers (gmail/sheets/calendar/docs/drive/ticktick), but only
 * ONE of them physically owns `/tg/webhook` (`TG_WEBHOOK_OWNER=true` —
 * `registerWebhook`'s guard). That one server's webhook handler receives
 * button taps for manifests belonging to ANY of the servers, and it does not
 * know in advance which one — it only has `manifest_id` from `callback_data`.
 * Filtering by `server` there (the old behaviour) silently returned zero rows
 * for every manifest that did not belong to the webhook-owning server,
 * leaving those approvals stuck PENDING forever.
 *
 * This is safe precisely because `manifest_id` is `tg_approvals`' PRIMARY KEY
 * (`ensureSchema()` above) — globally unique across every server sharing this
 * one physical Postgres, not scoped per row. There is no server-scoping being
 * bypassed here, only a redundant filter being dropped for the one call site
 * that cannot supply it. Returns the row's real `server` field so the caller
 * (`handleWebhook`) can log which server's approval was actually decided.
 *
 * `getTgApproval`/`checkApproval` (the EXECUTE-phase read path, called by
 * each server for its OWN manifests only) still filter by `server` — that
 * filter stays correct and is untouched: a server must never read another
 * server's approval status, it just cannot avoid writing through the shared
 * webhook.
 */
export async function consumeTgDecisionAnyServer(
  manifestId: string,
  status: "APPROVED" | "REJECTED",
): Promise<TgApprovalRow | null> {
  const p = getPool();
  const now = Date.now();
  const res = await p.query(
    `UPDATE tg_approvals SET status = $2, decided_at = $3
      WHERE manifest_id = $1 AND status = 'PENDING' AND expires_at > $3
      RETURNING *`,
    [manifestId, status, now],
  );
  if (!res.rows.length) return null;
  return rowToTgApproval(res.rows[0]);
}

/**
 * Sweep queries (package: TG-approval hygiene, Максим's ask 2026-08-05):
 * "кнопки по таймауту прям удалять" / "такой же таймаут делать для удаления
 * экрана после отказать" — two cleanup classes, ONE periodic sweep, run ONLY
 * by the webhook-owning server (gmail-mcp — see http.ts's setInterval), since
 * it's the sole holder of a working Telegram write path for every server's
 * rows (this table is shared across all 6 — see consumeTgDecisionAnyServer's
 * own comment on why cross-server reads are safe here specifically).
 *
 *  1. `status='PENDING'` past its own `expires_at` (nobody tapped the button
 *     in time) — button must come off, message otherwise left alone.
 *  2. `status IN ('APPROVED','REJECTED')` whose OWN TTL window (expires_at,
 *     already TTL-capped at plan time) has passed since being decided — the
 *     whole message is deleted, so the bot's chat stays empty of stale
 *     screens by default (Максим's stated design goal).
 * Both classes read cheaply off the same `tg_approvals_cleanup_idx`.
 */
export interface StalePendingRow {
  manifestId: string;
  chatId: string;
  messageId: number | null;
}

export interface StaleDecidedRow {
  manifestId: string;
  chatId: string;
  messageId: number | null;
}

/** Class 1 candidates — still PENDING, TTL passed. Marks them 'EXPIRED' in the
 * SAME statement (atomic claim) so a concurrent sweep tick / crash-retry never
 * double-processes the same row (Telegram edit is not naturally idempotent
 * against rate limits, so this matters more than it looks). */
export async function claimExpiredPendingApprovals(nowMs: number, limit = 50): Promise<StalePendingRow[]> {
  const p = getPool();
  const res = await p.query(
    `UPDATE tg_approvals SET status = 'EXPIRED'
      WHERE manifest_id IN (
        SELECT manifest_id FROM tg_approvals
        WHERE status = 'PENDING' AND expires_at <= $1
        ORDER BY expires_at ASC LIMIT $2
      )
      RETURNING manifest_id, chat_id, message_id`,
    [nowMs, limit],
  );
  return res.rows.map((r) => ({
    manifestId: r.manifest_id, chatId: r.chat_id,
    messageId: r.message_id === null ? null : Number(r.message_id),
  }));
}

/** Class 2 candidates — already decided, own TTL window elapsed since
 * decision. Deletes the row in the SAME statement (this table is purely
 * operational for the Telegram UI layer, not an audit log — consent_audit is
 * the durable record — so nothing is lost by not keeping DONE rows around). */
export async function claimStaleDecidedApprovals(nowMs: number, limit = 50): Promise<StaleDecidedRow[]> {
  const p = getPool();
  const res = await p.query(
    `DELETE FROM tg_approvals
      WHERE manifest_id IN (
        SELECT manifest_id FROM tg_approvals
        WHERE status IN ('APPROVED', 'REJECTED') AND expires_at <= $1
        ORDER BY expires_at ASC LIMIT $2
      )
      RETURNING manifest_id, chat_id, message_id`,
    [nowMs, limit],
  );
  return res.rows.map((r) => ({
    manifestId: r.manifest_id, chatId: r.chat_id,
    messageId: r.message_id === null ? null : Number(r.message_id),
  }));
}

/**
 * Кандидаты на авто-исполнение по кнопке (Максим, 2026-08-05 — см.
 * `consent.ts`'s `tryAutoExecute` doc-comment). JOIN по `manifest_id`
 * (общий PRIMARY KEY в обеих таблицах): манифест этого сервера ещё
 * AWAITING_CONSENT и не истёк, а его approval-строка уже APPROVED.
 * Server-scoped по `consent_manifests.server` — сервер видит и исполняет
 * ТОЛЬКО свои манифесты, даже если решение по кнопке принял общий вебхук
 * другого сервера (см. `consumeTgDecisionAnyServer`'s комментарий про
 * server-agnostic консюм самого решения — это другой шаг).
 */
export interface AutoExecuteCandidateRow {
  manifestId: string;
  tool: string;
  accountLabel: string;
  chatId: string;
  messageId: number | null;
}

export async function listApprovedUnexecuted(server: string, nowMs: number, limit = 20): Promise<AutoExecuteCandidateRow[]> {
  const p = getPool();
  const res = await p.query(
    `SELECT m.id AS manifest_id, m.tool, m.account_label, a.chat_id, a.message_id
       FROM consent_manifests m
       JOIN tg_approvals a ON a.manifest_id = m.id
      WHERE m.server = $1 AND m.status = 'AWAITING_CONSENT' AND m.expires_at > $2
        AND a.status = 'APPROVED'
      ORDER BY m.created_at ASC
      LIMIT $3`,
    [server, nowMs, limit],
  );
  return res.rows.map((r) => ({
    manifestId: r.manifest_id,
    tool: r.tool,
    accountLabel: r.account_label,
    chatId: r.chat_id,
    messageId: r.message_id === null ? null : Number(r.message_id),
  }));
}

/**
 * Точечный сиблинг `listApprovedUnexecuted` — ОДИН кандидат по `manifest_id`
 * (Максим, 2026-08-06: «исполнять прямо в обработчике нажатия, не дожидаясь
 * опроса»). Тот же JOIN и те же условия, включая server-scoping по
 * `consent_manifests.server`: вебхук-владелец получает нажатия по манифестам
 * ВСЕХ серверов, но исполнять имеет право только свои — чужие остаются их
 * собственным поллерам (у этого процесса нет ни их инструментов, ни их
 * Google-клиентов). Возвращает null, когда манифеста нет, он не наш, уже
 * потреблён/истёк или кнопка ещё не в APPROVED — вызывающий молча пропускает.
 *
 * НЕ является «захватом»: захват (одноразовость) по-прежнему делает атомарный
 * `consumeManifest` внутри `tryAutoExecute`. Этот SELECT — только чтение
 * адресации (tool/account/chat/message), чтобы собрать вызов.
 */
export async function getApprovedUnexecuted(
  manifestId: string,
  server: string,
  nowMs: number,
): Promise<AutoExecuteCandidateRow | null> {
  const p = getPool();
  const res = await p.query(
    `SELECT m.id AS manifest_id, m.tool, m.account_label, a.chat_id, a.message_id
       FROM consent_manifests m
       JOIN tg_approvals a ON a.manifest_id = m.id
      WHERE m.id = $1 AND m.server = $2 AND m.status = 'AWAITING_CONSENT' AND m.expires_at > $3
        AND a.status = 'APPROVED'
      LIMIT 1`,
    [manifestId, server, nowMs],
  );
  if (!res.rows.length) return null;
  const r = res.rows[0];
  return {
    manifestId: r.manifest_id,
    tool: r.tool,
    accountLabel: r.account_label,
    chatId: r.chat_id,
    messageId: r.message_id === null ? null : Number(r.message_id),
  };
}

export { randomUUID };
