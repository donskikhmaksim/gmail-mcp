#!/usr/bin/env node
/**
 * S5 — fail-closed /mcp when no auth is configured (plan `[R:приоритеты-3]`).
 *
 * Before this fix, a deployment with neither MCP_AUTH_TOKEN nor onboarding
 * OAuth set (`config.requireAuth === false`) served EVERY /mcp request as
 * `config.users[0]` with zero authentication — including the 4 consent-gated
 * send tools, where an external caller could just supply its own
 * `user_reply` and walk straight through the gate. Three scenarios, each its
 * own real `startHttpServer` instance on its own port (no mocking of
 * express/http — this exercises the real listener):
 *
 *   1. No auth configured, no opt-out  -> /mcp refuses with 503, no request
 *      reaches the MCP transport at all.
 *   2. Auth configured (MCP_AUTH_TOKEN) -> unchanged: no token -> 401;
 *      correct token -> the request goes all the way through a real MCP
 *      client handshake (initialize + tools/list).
 *   3. Explicit MCP_ALLOW_UNAUTHENTICATED=true opt-out -> old permissive
 *      behaviour returns (server-supplied user_reply reaches for the doubt:
 *      this is documented as a local-dev-only hole), AND a loud warning is
 *      printed every time the server decides this.
 *
 * No database, no real Google account: the fake account's oauth credentials
 * are never used for a network call — MCP initialize/tools-list only needs
 * `buildMcpServer(user)` to construct, not call, the Google clients.
 *
 * Usage: node scripts/test-s5-failclosed.mjs
 */
import { startHttpServer } from "../dist/http.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

const fakeAccount = {
  name: "default",
  auth: { mode: "oauth", clientId: "test-cid", clientSecret: "test-secret", refreshToken: "test-refresh" },
};

function baseConfig(port, overrides = {}) {
  return {
    transport: "http",
    port,
    requireAuth: false,
    users: [{ name: "default", accounts: [fakeAccount], defaultAccount: "default" }],
    onboarding: { enabled: false },
    sendingStuckMinutes: 10,
    ...overrides,
  };
}

/** Raw POST to /mcp, just to inspect the HTTP status — no MCP framing needed
 * for the pre-transport auth checks (401/503 happen before the body is even
 * parsed as JSON-RPC). */
async function rawPost(port, headers = {}) {
  return fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
  });
}

/** A full real MCP handshake (initialize + tools/list) through the given
 * Authorization header, to prove the request didn't just avoid 401/503 but
 * actually reached a working server. */
async function mcpToolsList(port, headers = {}) {
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
    requestInit: { headers },
  });
  const client = new Client({ name: "s5-test-client", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  const { tools } = await client.listTools();
  await client.close();
  return tools;
}

function withCapturedConsole(fn) {
  const calls = { warn: [], error: [] };
  const origWarn = console.warn;
  const origError = console.error;
  console.warn = (...args) => { calls.warn.push(args.join(" ")); origWarn(...args); };
  console.error = (...args) => { calls.error.push(args.join(" ")); origError(...args); };
  return fn().finally(() => {
    console.warn = origWarn;
    console.error = origError;
  }).then(() => calls);
}

try {
  // ---- Scenario 1: no auth configured, no opt-out => fail-closed 503 -----

  console.log("\n[1] No auth configured, no MCP_ALLOW_UNAUTHENTICATED => 503");
  delete process.env.MCP_ALLOW_UNAUTHENTICATED;
  const port1 = 34901;
  const calls1 = await withCapturedConsole(() => startHttpServer(baseConfig(port1)));
  check(
    "startup logs the fail-closed explanation (not the old 'endpoint is PUBLIC')",
    calls1.error.some((l) => /fail-closed/i.test(l) || /503/.test(l)),
    calls1.error,
  );

  const res1 = await rawPost(port1);
  check("POST /mcp with no auth-configuration at all => 503", res1.status === 503, res1.status);
  const body1 = await res1.json();
  check(
    "503 body explains why (mentions MCP_AUTH_TOKEN and the consent gate)",
    /MCP_AUTH_TOKEN/.test(body1?.error?.message ?? "") && /user_reply/.test(body1?.error?.message ?? ""),
    body1,
  );

  const res1b = await rawPost(port1, { Authorization: "Bearer whatever-i-want" });
  check("supplying a made-up bearer token doesn't help — still 503", res1b.status === 503, res1b.status);

  // ---- Scenario 2: MCP_AUTH_TOKEN configured => unchanged legacy behaviour ----

  console.log("\n[2] MCP_AUTH_TOKEN configured => 401 without it, real MCP round-trip with it");
  delete process.env.MCP_ALLOW_UNAUTHENTICATED;
  const port2 = 34902;
  const token = "s5-test-token-abc123";
  await startHttpServer(
    baseConfig(port2, {
      requireAuth: true,
      users: [{ name: "default", token, accounts: [fakeAccount], defaultAccount: "default" }],
    }),
  );

  const res2NoAuth = await rawPost(port2);
  check("no Authorization header => 401 (unchanged)", res2NoAuth.status === 401, res2NoAuth.status);

  const res2WrongAuth = await rawPost(port2, { Authorization: "Bearer not-the-token" });
  check("wrong token => 401 (unchanged)", res2WrongAuth.status === 401, res2WrongAuth.status);

  const tools2 = await mcpToolsList(port2, { Authorization: `Bearer ${token}` });
  check(
    "correct token => real MCP handshake succeeds, tools are listed",
    Array.isArray(tools2) && tools2.length > 0,
    tools2?.length,
  );
  check(
    "gmail_send is among the tools (proves the full server, not a stub, is being served)",
    tools2.some((t) => t.name === "gmail_send"),
    tools2.map((t) => t.name),
  );

  // ---- Scenario 3: explicit opt-out => old permissive behaviour + loud warning ----

  console.log("\n[3] MCP_ALLOW_UNAUTHENTICATED=true => works unauthenticated, but warns loudly");
  process.env.MCP_ALLOW_UNAUTHENTICATED = "true";
  const port3 = 34903;
  const calls3 = await withCapturedConsole(() => startHttpServer(baseConfig(port3)));
  check(
    "startup prints a loud opt-out warning naming the env var",
    calls3.warn.some((l) => /MCP_ALLOW_UNAUTHENTICATED/.test(l)),
    calls3.warn,
  );

  const tools3 = await mcpToolsList(port3);
  check(
    "opt-out: unauthenticated request still gets a real MCP handshake (documented local-dev hole)",
    Array.isArray(tools3) && tools3.length > 0,
    tools3?.length,
  );

  delete process.env.MCP_ALLOW_UNAUTHENTICATED;
} catch (err) {
  console.error("Unexpected error:", err);
  failures++;
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
