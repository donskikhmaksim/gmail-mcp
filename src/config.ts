/**
 * Centralised configuration. Reads everything from environment variables so the
 * server can be deployed to Railway (or anywhere) by just setting env vars.
 *
 * Model: the server has one or more USERS (selected by bearer token), and each
 * user has one or more named ACCOUNTS (selected per tool-call via the `account`
 * argument — e.g. "work" / "personal").
 *
 * Configuration modes:
 *   - Single user, single account : GOOGLE_OAUTH_* / GOOGLE_SERVICE_ACCOUNT_*.
 *   - Single user, many accounts  : GOOGLE_ACCOUNTS = JSON object {name: creds}.
 *   - Many users (each many accts): MCP_USERS = JSON array.
 */

export interface OAuthConfig {
  mode: "oauth";
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}

export interface ServiceAccountConfig {
  mode: "service_account";
  credentials: Record<string, unknown>;
}

export type GoogleAuthConfig = OAuthConfig | ServiceAccountConfig;

export interface Account {
  name: string;
  auth: GoogleAuthConfig;
  /** Optional Gmail search fragment ANDed into every gmail_search for this account. */
  gmailQuery?: string;
  /**
   * The account's real email address, when known (onboarded deployments carry
   * it from the DB). Used so an "unknown account" error and send previews can
   * show `work (maksim@…)`, not just an opaque label. Absent for env-only
   * accounts — the label is then shown alone (fail-soft).
   */
  email?: string;
}

export interface User {
  /** Human-friendly label (logs only). */
  name?: string;
  /** Bearer token that selects this user. undefined => no auth (single-user only). */
  token?: string;
  accounts: Account[];
  defaultAccount: string;
}

/**
 * Self-service onboarding: native MCP OAuth (RFC 8414/9728) that federates
 * login to Google. Enabled only when every required piece is present;
 * otherwise the server runs env-users only.
 */
export interface OnboardingConfig {
  enabled: boolean;
  databaseUrl?: string;
  /** Public base URL of this server, e.g. https://app.up.railway.app (no trailing slash). */
  publicBaseUrl?: string;
  /** Shared OAuth client used for everyone's consent flow. */
  googleClientId?: string;
  googleClientSecret?: string;
  /**
   * Optional token-blind OAuth relay. When set, Google's redirect_uri points at
   * `${relayUrl}/relay/callback` (a single pre-registered URI shared by everyone)
   * instead of this server's own callback — so a person's random Railway domain
   * never has to be registered in the Google console. The relay forwards the
   * one-time code back here; this server exchanges it. Requires relaySecret.
   * When unset, the server federates to Google using its own callback (needs
   * its own domain registered — the legacy behaviour).
   */
  relayUrl?: string;
  /** Shared HMAC secret used to sign the OAuth `state` the relay verifies. */
  relaySecret?: string;
  /**
   * Unguessable path segment protecting the account-management dashboard at
   * `/dashboard/<secret>`. When unset, the dashboard is disabled.
   */
  dashboardSecret?: string;
  /**
   * Allowlist of Google account emails (lower-cased) permitted to LINK a NEW
   * account through onboarding (dashboard "add account" or the MCP connect
   * flow's first-ever consent). Already-linked accounts are never affected —
   * this only gates new additions. When unset, linking is unrestricted
   * (fail-open, so self-hosted forks without this env var keep working as
   * before).
   */
  ownerEmails?: string[];
}

export interface Config {
  transport: "http" | "stdio";
  port: number;
  /** When true, every /mcp request must carry a matching bearer token. */
  requireAuth: boolean;
  users: User[];
  onboarding: OnboardingConfig;
  /**
   * A scheduled send stuck in 'sending' longer than this many minutes is
   * reaped to 'failed' by the poller (a process that died mid-send). Env
   * SENDING_STUCK_MINUTES, default 10.
   */
  sendingStuckMinutes: number;
}

function loadOnboarding(): OnboardingConfig {
  const databaseUrl = process.env.DATABASE_URL?.trim();
  // Railway injects RAILWAY_PUBLIC_DOMAIN automatically once public networking
  // is on, so PUBLIC_BASE_URL only needs to be set manually off-Railway.
  const railwayDomain = process.env.RAILWAY_PUBLIC_DOMAIN?.trim();
  const publicBaseUrl =
    process.env.PUBLIC_BASE_URL?.trim() || (railwayDomain ? `https://${railwayDomain}` : undefined);
  const googleClientId =
    process.env.ONBOARDING_GOOGLE_CLIENT_ID?.trim() || process.env.GOOGLE_OAUTH_CLIENT_ID?.trim();
  const googleClientSecret =
    process.env.ONBOARDING_GOOGLE_CLIENT_SECRET?.trim() ||
    process.env.GOOGLE_OAUTH_CLIENT_SECRET?.trim();
  const hasEncKey = !!process.env.TOKEN_ENC_KEY?.trim();
  const relayUrl = process.env.OAUTH_RELAY_URL?.trim().replace(/\/+$/, "") || undefined;
  const relaySecret = process.env.OAUTH_RELAY_SECRET?.trim() || undefined;
  const dashboardSecret = process.env.DASHBOARD_SECRET?.trim() || undefined;
  const ownerEmailsRaw = process.env.OWNER_EMAILS?.trim();
  const ownerEmails = ownerEmailsRaw
    ? ownerEmailsRaw
        .split(",")
        .map((e) => e.trim().toLowerCase())
        .filter(Boolean)
    : undefined;

  const enabled = !!(
    databaseUrl &&
    publicBaseUrl &&
    googleClientId &&
    googleClientSecret &&
    hasEncKey
  );
  return {
    enabled,
    databaseUrl,
    publicBaseUrl,
    googleClientId,
    googleClientSecret,
    // A relay without its shared secret is unusable — ignore it so we fall back
    // to the direct self-callback rather than signing with an empty key.
    relayUrl: relayUrl && relaySecret ? relayUrl : undefined,
    relaySecret: relayUrl && relaySecret ? relaySecret : undefined,
    dashboardSecret,
    ownerEmails,
  };
}

export const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/spreadsheets",
  "https://www.googleapis.com/auth/documents",
  "https://www.googleapis.com/auth/drive",
  // Calendar: list calendars, read/write events, free-busy.
  "https://www.googleapis.com/auth/calendar",
  // Gmail: read, send, modify labels, archive, trash (move to Trash).
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.send",
];

function decodeServiceAccount(
  raw: string | undefined,
  b64: string | undefined,
): Record<string, unknown> | undefined {
  let text: string | undefined;
  if (b64 && b64.trim()) text = Buffer.from(b64.trim(), "base64").toString("utf8");
  else if (raw && raw.trim()) text = raw.trim();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error("Service account value is not valid JSON: " + (err as Error).message);
  }
}

/** Builds a GoogleAuthConfig from a generic record of credential fields. */
function authFromFields(src: Record<string, unknown>, where: string): GoogleAuthConfig {
  const get = (...keys: string[]): string | undefined => {
    for (const k of keys) {
      const v = src[k];
      if (typeof v === "string" && v.trim()) return v.trim();
    }
    return undefined;
  };

  const clientId = get("clientId", "client_id", "GOOGLE_OAUTH_CLIENT_ID");
  const clientSecret = get("clientSecret", "client_secret", "GOOGLE_OAUTH_CLIENT_SECRET");
  const refreshToken = get("refreshToken", "refresh_token", "GOOGLE_OAUTH_REFRESH_TOKEN");

  if (clientId && clientSecret && refreshToken) {
    return { mode: "oauth", clientId, clientSecret, refreshToken };
  }

  const credentials = decodeServiceAccount(
    get("serviceAccountJson", "service_account_json", "GOOGLE_SERVICE_ACCOUNT_JSON"),
    get("serviceAccountBase64", "service_account_base64", "GOOGLE_SERVICE_ACCOUNT_BASE64"),
  );
  if (credentials) return { mode: "service_account", credentials };

  throw new Error(
    `No usable Google credentials for ${where}: provide client_id/client_secret/refresh_token ` +
      `or service_account_base64.`,
  );
}

/**
 * Parses the account(s) for one user/server from a record that either:
 *   - has an `accounts` object: { "work": {creds}, "personal": {creds} }, or
 *   - carries a single set of credential fields inline (=> one "default" account).
 */
function parseAccounts(
  obj: Record<string, unknown>,
  where: string,
): { accounts: Account[]; defaultAccount: string } {
  const str = (x: unknown): string | undefined =>
    typeof x === "string" && x.trim() ? x.trim() : undefined;
  // A parent-level gmailQuery acts as the default for accounts without their own.
  const parentQuery = str(obj.gmailQuery) ?? str(obj.gmail_query);

  const accs = obj.accounts;
  if (accs && typeof accs === "object" && !Array.isArray(accs)) {
    const entries = Object.entries(accs as Record<string, unknown>);
    if (entries.length === 0) throw new Error(`${where}: "accounts" is empty.`);
    const accounts: Account[] = entries.map(([name, val]) => {
      if (typeof val !== "object" || val === null) {
        throw new Error(`${where}: account "${name}" must be an object.`);
      }
      const v = val as Record<string, unknown>;
      return {
        name,
        auth: authFromFields(v, `${where} account "${name}"`),
        gmailQuery: str(v.gmailQuery) ?? str(v.gmail_query) ?? parentQuery,
      };
    });
    const def =
      (typeof obj.defaultAccount === "string" && obj.defaultAccount) ||
      (typeof obj.default_account === "string" && obj.default_account) ||
      accounts[0].name;
    if (!accounts.some((a) => a.name === def)) {
      throw new Error(`${where}: defaultAccount "${def}" is not one of the accounts.`);
    }
    return { accounts, defaultAccount: def };
  }

  // Inline single-account credentials.
  return {
    accounts: [{ name: "default", auth: authFromFields(obj, where), gmailQuery: parentQuery }],
    defaultAccount: "default",
  };
}

function loadMultiUser(json: string): User[] {
  let arr: unknown;
  try {
    arr = JSON.parse(json);
  } catch (err) {
    throw new Error("MCP_USERS is not valid JSON: " + (err as Error).message);
  }
  if (!Array.isArray(arr) || arr.length === 0) {
    throw new Error("MCP_USERS must be a non-empty JSON array.");
  }
  const users: User[] = arr.map((raw, i) => {
    if (typeof raw !== "object" || raw === null) {
      throw new Error(`MCP_USERS[${i}] must be an object.`);
    }
    const obj = raw as Record<string, unknown>;
    const token = typeof obj.token === "string" ? obj.token.trim() : "";
    if (!token) throw new Error(`MCP_USERS[${i}] is missing a non-empty "token".`);
    const name = typeof obj.name === "string" ? obj.name : `user${i + 1}`;
    const { accounts, defaultAccount } = parseAccounts(obj, `MCP_USERS[${i}] (${name})`);
    return { name, token, accounts, defaultAccount };
  });

  const tokens = new Set(users.map((u) => u.token));
  if (tokens.size !== users.length) {
    throw new Error("MCP_USERS contains duplicate tokens; each user needs a unique token.");
  }
  return users;
}

function loadSingleUser(): User {
  const token = process.env.MCP_AUTH_TOKEN?.trim() || undefined;

  // Single user with several accounts via GOOGLE_ACCOUNTS = {name: creds}.
  const accountsJson = process.env.GOOGLE_ACCOUNTS?.trim();
  if (accountsJson) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(accountsJson);
    } catch (err) {
      throw new Error("GOOGLE_ACCOUNTS is not valid JSON: " + (err as Error).message);
    }
    const { accounts, defaultAccount } = parseAccounts(
      {
        accounts: parsed,
        defaultAccount: process.env.GOOGLE_DEFAULT_ACCOUNT,
        gmailQuery: process.env.GMAIL_DEFAULT_QUERY,
      },
      "GOOGLE_ACCOUNTS",
    );
    return { name: "default", token, accounts, defaultAccount };
  }

  // Legacy single account from individual env vars.
  const { accounts, defaultAccount } = parseAccounts(
    {
      GOOGLE_OAUTH_CLIENT_ID: process.env.GOOGLE_OAUTH_CLIENT_ID,
      GOOGLE_OAUTH_CLIENT_SECRET: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      GOOGLE_OAUTH_REFRESH_TOKEN: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
      GOOGLE_SERVICE_ACCOUNT_JSON: process.env.GOOGLE_SERVICE_ACCOUNT_JSON,
      GOOGLE_SERVICE_ACCOUNT_BASE64: process.env.GOOGLE_SERVICE_ACCOUNT_BASE64,
      gmailQuery: process.env.GMAIL_DEFAULT_QUERY,
    },
    "the server",
  );
  return { name: "default", token, accounts, defaultAccount };
}

/**
 * Consent-gate config (packages A1/A2/A3, `mcp-development-standard/
 * references/gate.md`). Standalone from the rest of `Config`/`loadConfig()`
 * on purpose — it's pure env, no user/onboarding parsing, so `server.ts` can
 * read it once at module scope without re-running the heavier account setup.
 */
export interface ConsentGateConfig {
  /** Constant identifying THIS server in the shared consent_manifests/
   * consent_audit tables (all 5 MCP servers share one physical Postgres —
   * plan §0.4). `$self`, never a tool argument. Env CONSENT_SERVER, default "gmail". */
  server: string;
  /** Manifest TTL in ms. Env CONSENT_TTL_MS, default 1h. */
  consentTtlMs: number;
  /** Minimum gap between plan and execute in ms — anti-doublet check
   * (gate.md §3.3(2)): catches a model calling plan then execute in the same
   * turn, before a human could have answered. Env MIN_CONSENT_GAP_MS, default
   * 10000 — Maksim's decision (Q3, 2026-08-04) specifically for mail; NOT the
   * generic 5000 used elsewhere in the plan/tests. */
  minConsentGapMs: number;
  /** Cap on items per manifest/batch — one manifest is one radius of consent
   * (plan §0.2/[R:полнота-7]); over the cap, the tool refuses with "split it
   * up" instead of creating a manifest. Env SEND_BATCH_MAX, default 10. */
  sendBatchMax: number;
}

function positiveIntEnv(name: string, fallback: number): number {
  const raw = Number(process.env[name]);
  return Number.isFinite(raw) && raw > 0 ? raw : fallback;
}

export function loadConsentGateConfig(): ConsentGateConfig {
  return {
    server: process.env.CONSENT_SERVER?.trim() || "gmail",
    consentTtlMs: positiveIntEnv("CONSENT_TTL_MS", 3_600_000),
    minConsentGapMs: positiveIntEnv("MIN_CONSENT_GAP_MS", 10_000),
    sendBatchMax: positiveIntEnv("SEND_BATCH_MAX", 10),
  };
}

/**
 * Optional Telegram-approval layer (`src/tg_approval.ts`, plan-tg-approval.md).
 * OFF by default — a fork without a Telegram bot behaves exactly as before
 * this feature existed. Standalone from `ConsentGateConfig` on purpose (same
 * reasoning as that interface's own doc comment): pure env, no account setup.
 */
export interface TgApprovalConfig {
  /** Env TG_APPROVAL_ENABLED, default false. */
  enabled: boolean;
  /** Env TG_BOT_TOKEN_OVERRIDE if set, else TG_BOT_TOKEN. Required when enabled. */
  botToken: string;
  /** Env TG_OWNER_CHAT_ID — the only chat id the webhook accepts callbacks from. */
  ownerChatId: string;
  /** Env TG_APPROVAL_WEBHOOK_SECRET — Telegram's X-Telegram-Bot-Api-Secret-Token. */
  webhookSecret: string;
  /** Public base URL this server is reachable at (for setWebhook). Reuses
   * PUBLIC_BASE_URL / RAILWAY_PUBLIC_DOMAIN, same resolution as onboarding's. */
  publicBaseUrl: string;
  /** `$self` — reuses CONSENT_SERVER so tg_approvals rows key off the same
   * per-server identity as consent_manifests/consent_audit. */
  server: string;
  /** Env TG_APPROVAL_TOOLS (csv). null = every gated write tool requires the
   * button; a non-empty set = only those tool names. */
  toolsAllowlist: Set<string> | null;
  /** Approval-request TTL, ms. Env TG_APPROVAL_TTL_MS, default 1h (mirrors
   * CONSENT_TTL_MS's default so the two layers don't silently diverge unless
   * a deployer explicitly wants that). */
  ttlMs: number;
  /**
   * Env TG_WEBHOOK_OWNER, default false. ONE Telegram bot token can be shared
   * across several MCP servers (gmail/sheets/calendar/docs/drive-mcp +
   * ticktick-mcp) — but Telegram routes every update for a bot to exactly one
   * webhook URL, the one the most recent `setWebhook` call registered. Set
   * `true` on exactly the ONE server that should own `/tg/webhook` and call
   * `setWebhook` at startup; every other server sharing the same TG_BOT_TOKEN
   * must leave this unset (default false), or their `setWebhook` calls will
   * silently overwrite each other and approvals for whoever registered last
   * stop reaching anyone. See `registerWebhook` in tg_approval.ts, which
   * self-guards on this field (defense-in-depth beyond the call-site check).
   */
  webhookOwner: boolean;
  /**
   * Env TG_BOT_TOKEN_OVERRIDE, default false (unset). Per-server escape hatch
   * from the shared-bot model above: when set, THIS server talks to its OWN
   * Telegram bot (its own token, its own chat, its own webhook) instead of
   * the bot every MCP server shares by default via TG_BOT_TOKEN. `botToken`
   * already resolves to the override when present (see loadTgApprovalConfig),
   * so every existing call site that just reads `cfg.botToken` keeps working
   * unchanged — `ownBot` exists ONLY to flip the two behaviours that assume
   * "one bot, many servers" and would otherwise be wrong for an own-bot
   * server: (1) the `/tg/webhook` route gate in http.ts (an own-bot server
   * must accept its webhook even without TG_WEBHOOK_OWNER — that flag is
   * about the SHARED bot, not this one), and (2) `handleWebhook`'s decision
   * consume in tg_approval.ts (an own-bot server's webhook only ever carries
   * ITS OWN manifests, so it must consume server-scoped via `consumeTgDecision`,
   * not the shared `consumeTgDecisionAnyServer` — a global manifest_id lookup
   * across the shared table would be both unnecessary and, if that Postgres
   * happens to be shared too, would let this server react to callback taps
   * that were never meant for it).
   *
   * UNSET (default) => false => every existing server (gmail-mcp today, plus
   * whichever of sheets/calendar/docs/drive/ticktick adopt this same file
   * later) behaves byte-for-byte as before this field existed: shared bot,
   * shared webhook ownership via TG_WEBHOOK_OWNER, shared-table consume via
   * consumeTgDecisionAnyServer. Rollback is just unsetting the env var — no
   * redeploy of code, no migration.
   */
  ownBot: boolean;
}

export function loadTgApprovalConfig(consentServer: string): TgApprovalConfig {
  const enabled = process.env.TG_APPROVAL_ENABLED?.trim().toLowerCase() === "true";
  const botTokenOverride = process.env.TG_BOT_TOKEN_OVERRIDE?.trim() || "";
  const botToken = botTokenOverride || process.env.TG_BOT_TOKEN?.trim() || "";
  const ownBot = !!botTokenOverride;
  const ownerChatId = process.env.TG_OWNER_CHAT_ID?.trim() || "";
  const webhookSecret = process.env.TG_APPROVAL_WEBHOOK_SECRET?.trim() || "";
  const railwayDomain = process.env.RAILWAY_PUBLIC_DOMAIN?.trim();
  const publicBaseUrl =
    process.env.PUBLIC_BASE_URL?.trim() || (railwayDomain ? `https://${railwayDomain}` : "");
  const toolsRaw = process.env.TG_APPROVAL_TOOLS?.trim();
  const toolsAllowlist = toolsRaw
    ? new Set(
        toolsRaw
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      )
    : null;
  const ttlMs = positiveIntEnv("TG_APPROVAL_TTL_MS", 3_600_000);
  const webhookOwner = process.env.TG_WEBHOOK_OWNER?.trim().toLowerCase() === "true";

  // Loud, fail-fast startup check (plan §2, package P0 "Готово" criterion):
  // ENABLED=true without every required piece must NOT silently disable the
  // feature or serve mutations without the second factor it claims to enforce.
  if (enabled && (!botToken || !ownerChatId || !webhookSecret || !publicBaseUrl)) {
    const missing = [
      !botToken && "TG_BOT_TOKEN (or TG_BOT_TOKEN_OVERRIDE)",
      !ownerChatId && "TG_OWNER_CHAT_ID",
      !webhookSecret && "TG_APPROVAL_WEBHOOK_SECRET",
      !publicBaseUrl && "PUBLIC_BASE_URL (or RAILWAY_PUBLIC_DOMAIN)",
    ]
      .filter(Boolean)
      .join(", ");
    throw new Error(
      `TG_APPROVAL_ENABLED=true, but missing: ${missing}. The Telegram-approval layer cannot start ` +
        `without all of them — set them, or unset TG_APPROVAL_ENABLED to run without this layer.`,
    );
  }

  return {
    enabled,
    botToken,
    ownerChatId,
    webhookSecret,
    publicBaseUrl,
    server: consentServer,
    toolsAllowlist,
    ttlMs,
    webhookOwner,
    ownBot,
  };
}

export function loadConfig(): Config {
  const transport =
    (process.env.MCP_TRANSPORT as "http" | "stdio" | undefined) ??
    (process.env.PORT ? "http" : "stdio");
  const port = Number(process.env.PORT ?? 3000);

  const onboarding = loadOnboarding();

  let users: User[];
  try {
    if (process.env.MCP_USERS && process.env.MCP_USERS.trim()) {
      users = loadMultiUser(process.env.MCP_USERS.trim());
    } else {
      users = [loadSingleUser()];
    }
  } catch (err) {
    // With onboarding enabled, env users are optional — everyone comes from the
    // database instead, so an absence of env credentials is fine. But if
    // MCP_AUTH_TOKEN is set, keep a token-holder user with an EMPTY account
    // list (rather than dropping the token entirely) so a static-token caller
    // can still authenticate and handleMcp can fill their accounts in from the
    // Postgres-backed onboarding store instead.
    if (onboarding.enabled) {
      const token = process.env.MCP_AUTH_TOKEN?.trim() || undefined;
      users = token ? [{ name: "default", token, accounts: [], defaultAccount: "default" }] : [];
    } else {
      throw new Error(
        (err as Error).message +
          "\n\nSet ONE of:\n" +
          "  Single account : GOOGLE_OAUTH_CLIENT_ID / _SECRET / _REFRESH_TOKEN (+ optional MCP_AUTH_TOKEN)\n" +
          '  Many accounts  : GOOGLE_ACCOUNTS={"work":{...},"personal":{...}} (+ optional MCP_AUTH_TOKEN)\n' +
          '  Many users     : MCP_USERS=[{"token":"...","accounts":{"work":{...},"personal":{...}}}, ...]',
      );
    }
  }

  const requireAuth = onboarding.enabled || users.length > 1 || users.some((u) => !!u.token);
  const stuckRaw = Number(process.env.SENDING_STUCK_MINUTES);
  const sendingStuckMinutes = Number.isFinite(stuckRaw) && stuckRaw > 0 ? stuckRaw : 10;
  return { transport, port, requireAuth, users, onboarding, sendingStuckMinutes };
}
