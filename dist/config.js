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
function loadOnboarding() {
    const databaseUrl = process.env.DATABASE_URL?.trim();
    const telegramBotToken = process.env.TELEGRAM_BOT_TOKEN?.trim();
    const publicBaseUrl = process.env.PUBLIC_BASE_URL?.trim();
    const googleClientId = process.env.ONBOARDING_GOOGLE_CLIENT_ID?.trim() || process.env.GOOGLE_OAUTH_CLIENT_ID?.trim();
    const googleClientSecret = process.env.ONBOARDING_GOOGLE_CLIENT_SECRET?.trim() ||
        process.env.GOOGLE_OAUTH_CLIENT_SECRET?.trim();
    const hasEncKey = !!process.env.TOKEN_ENC_KEY?.trim();
    const enabled = !!(databaseUrl &&
        telegramBotToken &&
        publicBaseUrl &&
        googleClientId &&
        googleClientSecret &&
        hasEncKey);
    return {
        enabled,
        databaseUrl,
        telegramBotToken,
        publicBaseUrl,
        googleClientId,
        googleClientSecret,
    };
}
export const GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/drive",
    // Gmail: read, send, modify labels, archive, trash (move to Trash).
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
];
function decodeServiceAccount(raw, b64) {
    let text;
    if (b64 && b64.trim())
        text = Buffer.from(b64.trim(), "base64").toString("utf8");
    else if (raw && raw.trim())
        text = raw.trim();
    if (!text)
        return undefined;
    try {
        return JSON.parse(text);
    }
    catch (err) {
        throw new Error("Service account value is not valid JSON: " + err.message);
    }
}
/** Builds a GoogleAuthConfig from a generic record of credential fields. */
function authFromFields(src, where) {
    const get = (...keys) => {
        for (const k of keys) {
            const v = src[k];
            if (typeof v === "string" && v.trim())
                return v.trim();
        }
        return undefined;
    };
    const clientId = get("clientId", "client_id", "GOOGLE_OAUTH_CLIENT_ID");
    const clientSecret = get("clientSecret", "client_secret", "GOOGLE_OAUTH_CLIENT_SECRET");
    const refreshToken = get("refreshToken", "refresh_token", "GOOGLE_OAUTH_REFRESH_TOKEN");
    if (clientId && clientSecret && refreshToken) {
        return { mode: "oauth", clientId, clientSecret, refreshToken };
    }
    const credentials = decodeServiceAccount(get("serviceAccountJson", "service_account_json", "GOOGLE_SERVICE_ACCOUNT_JSON"), get("serviceAccountBase64", "service_account_base64", "GOOGLE_SERVICE_ACCOUNT_BASE64"));
    if (credentials)
        return { mode: "service_account", credentials };
    throw new Error(`No usable Google credentials for ${where}: provide client_id/client_secret/refresh_token ` +
        `or service_account_base64.`);
}
/**
 * Parses the account(s) for one user/server from a record that either:
 *   - has an `accounts` object: { "work": {creds}, "personal": {creds} }, or
 *   - carries a single set of credential fields inline (=> one "default" account).
 */
function parseAccounts(obj, where) {
    const str = (x) => typeof x === "string" && x.trim() ? x.trim() : undefined;
    // A parent-level gmailQuery acts as the default for accounts without their own.
    const parentQuery = str(obj.gmailQuery) ?? str(obj.gmail_query);
    const accs = obj.accounts;
    if (accs && typeof accs === "object" && !Array.isArray(accs)) {
        const entries = Object.entries(accs);
        if (entries.length === 0)
            throw new Error(`${where}: "accounts" is empty.`);
        const accounts = entries.map(([name, val]) => {
            if (typeof val !== "object" || val === null) {
                throw new Error(`${where}: account "${name}" must be an object.`);
            }
            const v = val;
            return {
                name,
                auth: authFromFields(v, `${where} account "${name}"`),
                gmailQuery: str(v.gmailQuery) ?? str(v.gmail_query) ?? parentQuery,
            };
        });
        const def = (typeof obj.defaultAccount === "string" && obj.defaultAccount) ||
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
function loadMultiUser(json) {
    let arr;
    try {
        arr = JSON.parse(json);
    }
    catch (err) {
        throw new Error("MCP_USERS is not valid JSON: " + err.message);
    }
    if (!Array.isArray(arr) || arr.length === 0) {
        throw new Error("MCP_USERS must be a non-empty JSON array.");
    }
    const users = arr.map((raw, i) => {
        if (typeof raw !== "object" || raw === null) {
            throw new Error(`MCP_USERS[${i}] must be an object.`);
        }
        const obj = raw;
        const token = typeof obj.token === "string" ? obj.token.trim() : "";
        if (!token)
            throw new Error(`MCP_USERS[${i}] is missing a non-empty "token".`);
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
function loadSingleUser() {
    const token = process.env.MCP_AUTH_TOKEN?.trim() || undefined;
    // Single user with several accounts via GOOGLE_ACCOUNTS = {name: creds}.
    const accountsJson = process.env.GOOGLE_ACCOUNTS?.trim();
    if (accountsJson) {
        let parsed;
        try {
            parsed = JSON.parse(accountsJson);
        }
        catch (err) {
            throw new Error("GOOGLE_ACCOUNTS is not valid JSON: " + err.message);
        }
        const { accounts, defaultAccount } = parseAccounts({
            accounts: parsed,
            defaultAccount: process.env.GOOGLE_DEFAULT_ACCOUNT,
            gmailQuery: process.env.GMAIL_DEFAULT_QUERY,
        }, "GOOGLE_ACCOUNTS");
        return { name: "default", token, accounts, defaultAccount };
    }
    // Legacy single account from individual env vars.
    const { accounts, defaultAccount } = parseAccounts({
        GOOGLE_OAUTH_CLIENT_ID: process.env.GOOGLE_OAUTH_CLIENT_ID,
        GOOGLE_OAUTH_CLIENT_SECRET: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
        GOOGLE_OAUTH_REFRESH_TOKEN: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
        GOOGLE_SERVICE_ACCOUNT_JSON: process.env.GOOGLE_SERVICE_ACCOUNT_JSON,
        GOOGLE_SERVICE_ACCOUNT_BASE64: process.env.GOOGLE_SERVICE_ACCOUNT_BASE64,
        gmailQuery: process.env.GMAIL_DEFAULT_QUERY,
    }, "the server");
    return { name: "default", token, accounts, defaultAccount };
}
export function loadConfig() {
    const transport = process.env.MCP_TRANSPORT ??
        (process.env.PORT ? "http" : "stdio");
    const port = Number(process.env.PORT ?? 3000);
    const onboarding = loadOnboarding();
    let users;
    try {
        if (process.env.MCP_USERS && process.env.MCP_USERS.trim()) {
            users = loadMultiUser(process.env.MCP_USERS.trim());
        }
        else {
            users = [loadSingleUser()];
        }
    }
    catch (err) {
        // With onboarding enabled, env users are optional — everyone comes from the
        // database instead, so an absence of env credentials is fine.
        if (onboarding.enabled) {
            users = [];
        }
        else {
            throw new Error(err.message +
                "\n\nSet ONE of:\n" +
                "  Single account : GOOGLE_OAUTH_CLIENT_ID / _SECRET / _REFRESH_TOKEN (+ optional MCP_AUTH_TOKEN)\n" +
                '  Many accounts  : GOOGLE_ACCOUNTS={"work":{...},"personal":{...}} (+ optional MCP_AUTH_TOKEN)\n' +
                '  Many users     : MCP_USERS=[{"token":"...","accounts":{"work":{...},"personal":{...}}}, ...]');
        }
    }
    const requireAuth = onboarding.enabled || users.length > 1 || users.some((u) => !!u.token);
    return { transport, port, requireAuth, users, onboarding };
}
