#!/usr/bin/env node
/**
 * Offline check of the credential-source-selection fix (2026-08-04):
 *
 *   1. config.ts loadConfig(): when onboarding is enabled but no usable env
 *      Google credentials are present, a static MCP_AUTH_TOKEN must still
 *      produce a token-holder user (empty account list) instead of being
 *      silently dropped.
 *   2. http.ts selectLegacyOrOnboardingUser(): a static-token request must
 *      prefer live Postgres-backed (onboarding) accounts over the
 *      env-configured ones, falling back to env only when onboarding has
 *      nothing linked, and failing closed (null) when neither has anything.
 *   3. oauthProvider.ts checkOwnerAllowlist(): OWNER_EMAILS blocks linking a
 *      brand-new account for an email outside the list, but never blocks an
 *      already-linked email, and is a no-op when unset.
 *
 * No database, no network, no real Google account — loadConfig() only reads
 * process.env, and the other two functions are pure. This is why they were
 * pulled out of handleMcp/handleGoogleCallback as standalone exports.
 *
 * Usage:
 *   npm test                              # builds, then runs all test scripts
 *   node scripts/test-credential-source.mjs
 */
import { loadConfig } from "../dist/config.js";
import { selectLegacyOrOnboardingUser } from "../dist/http.js";
import { checkOwnerAllowlist } from "../dist/oauthProvider.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

// ---- 1. config.ts: token-holder fallback --------------------------------

const ONBOARDING_ENV_KEYS = [
  "DATABASE_URL",
  "PUBLIC_BASE_URL",
  "RAILWAY_PUBLIC_DOMAIN",
  "ONBOARDING_GOOGLE_CLIENT_ID",
  "ONBOARDING_GOOGLE_CLIENT_SECRET",
  "GOOGLE_OAUTH_CLIENT_ID",
  "GOOGLE_OAUTH_CLIENT_SECRET",
  "GOOGLE_OAUTH_REFRESH_TOKEN",
  "GOOGLE_SERVICE_ACCOUNT_JSON",
  "GOOGLE_SERVICE_ACCOUNT_BASE64",
  "GOOGLE_ACCOUNTS",
  "MCP_USERS",
  "MCP_AUTH_TOKEN",
  "TOKEN_ENC_KEY",
  "MCP_TRANSPORT",
  "PORT",
];
const savedEnv = new Map(ONBOARDING_ENV_KEYS.map((k) => [k, process.env[k]]));
function resetEnv() {
  for (const k of ONBOARDING_ENV_KEYS) {
    const v = savedEnv.get(k);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}
function clearEnv() {
  for (const k of ONBOARDING_ENV_KEYS) delete process.env[k];
}

try {
  // Onboarding fully configured, no env Google creds at all, token set.
  clearEnv();
  process.env.DATABASE_URL = "postgres://fake/db";
  process.env.PUBLIC_BASE_URL = "https://example.up.railway.app";
  process.env.ONBOARDING_GOOGLE_CLIENT_ID = "cid";
  process.env.ONBOARDING_GOOGLE_CLIENT_SECRET = "csecret";
  process.env.TOKEN_ENC_KEY = "enckey";
  process.env.MCP_AUTH_TOKEN = "tok123";

  const cfg1 = loadConfig();
  check("onboarding is enabled in this scenario", cfg1.onboarding.enabled === true, cfg1.onboarding);
  check(
    "no-env-creds + MCP_AUTH_TOKEN set => one token-holder user survives",
    cfg1.users.length === 1 && cfg1.users[0].token === "tok123",
    cfg1.users,
  );
  check("token-holder user has an EMPTY account list", cfg1.users[0]?.accounts.length === 0, cfg1.users[0]);

  // Same, but no MCP_AUTH_TOKEN at all => no token to hold onto, users stays empty.
  delete process.env.MCP_AUTH_TOKEN;
  const cfg2 = loadConfig();
  check("no-env-creds + no token => users is empty (unchanged pre-fix behaviour)", cfg2.users.length === 0, cfg2.users);

  // Onboarding disabled (missing TOKEN_ENC_KEY) + no creds => old throwing path unchanged.
  delete process.env.TOKEN_ENC_KEY;
  process.env.MCP_AUTH_TOKEN = "tok123";
  let threw = false;
  try {
    loadConfig();
  } catch {
    threw = true;
  }
  check("onboarding disabled + no creds still throws (no silent fallback)", threw);
} finally {
  resetEnv();
}

// ---- 2. http.ts: selectLegacyOrOnboardingUser ---------------------------

const envUser = { name: "default", token: "tok", accounts: [{ name: "default", auth: {} }], defaultAccount: "default" };
const emptyLegacyUser = { name: "default", token: "tok", accounts: [], defaultAccount: "default" };
const onboardingUser = { name: "me@gmail.com", accounts: [{ name: "personal", auth: {} }], defaultAccount: "personal" };

{
  const result = await selectLegacyOrOnboardingUser(envUser, false, async () => {
    throw new Error("must not be called when onboarding is disabled");
  });
  check("onboarding disabled => env user passes through untouched", result === envUser, result);
}
{
  const result = await selectLegacyOrOnboardingUser(envUser, true, async () => onboardingUser);
  check("onboarding enabled + has accounts => onboarding user preferred over env", result === onboardingUser, result);
}
{
  const result = await selectLegacyOrOnboardingUser(envUser, true, async () => null);
  check("onboarding enabled + nothing linked => falls back to env user", result === envUser, result);
}
{
  const result = await selectLegacyOrOnboardingUser(emptyLegacyUser, true, async () => null);
  check("onboarding enabled + nothing linked + no env creds => fails closed (null)", result === null, result);
}

// ---- 3. oauthProvider.ts: checkOwnerAllowlist ---------------------------

{
  let threw = false;
  try {
    checkOwnerAllowlist("new@example.com", false, undefined);
  } catch {
    threw = true;
  }
  check("OWNER_EMAILS unset => new account never blocked (fail-open)", !threw);
}
{
  let threw = false;
  try {
    checkOwnerAllowlist("new@example.com", false, ["owner@example.com"]);
  } catch {
    threw = true;
  }
  check("new account, email NOT in allowlist => rejected", threw);
}
{
  let threw = false;
  try {
    checkOwnerAllowlist("Owner@Example.com", false, ["owner@example.com"]);
  } catch {
    threw = true;
  }
  check("new account, email in allowlist (case-insensitive) => allowed", !threw);
}
{
  let threw = false;
  try {
    checkOwnerAllowlist("someone-else@example.com", true, ["owner@example.com"]);
  } catch {
    threw = true;
  }
  check("ALREADY-linked account, email not in allowlist => never blocked", !threw);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
