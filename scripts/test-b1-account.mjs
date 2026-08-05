#!/usr/bin/env node
/**
 * B1 — account email in errors + fail-fast label validation.
 *
 * Covers ТЗ B.1: an unknown account label is refused AT CALL TIME (not an hour
 * later in the scheduler), and the error names BOTH labels and emails so a typo
 * like "maksim.donskikh" is obviously part of work's email, not a label. Also
 * covers extractEmail, accountEmail (users.getProfile + cache), and that the
 * `account ?? default` → `canonicalName` fix no longer stores a bogus "" label.
 *
 * No network: buildUserClients only constructs google client objects (no calls
 * happen until a method is invoked), and the schedule_send harness uses a fake
 * store + fake clients.
 *
 * Usage: node scripts/test-b1-account.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools, extractEmail, accountEmail } from "../dist/tools/gmail.js";
import { buildUserClients } from "../dist/accounts.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

// --- 1. extractEmail -------------------------------------------------------

console.log("\n[1] extractEmail — pulls the bare address, lower-cased");
check('«Name <A@B.com>» → a@b.com', extractEmail("Maksim <A@B.com>") === "a@b.com", extractEmail("Maksim <A@B.com>"));
check("plain a@b.com", extractEmail("a@b.com") === "a@b.com", extractEmail("a@b.com"));
check("first of comma list", extractEmail("a@b.com, c@d.com") === "a@b.com", extractEmail("a@b.com, c@d.com"));
check("no address → ''", extractEmail("just a name") === "", extractEmail("just a name"));
check("empty → ''", extractEmail("") === "");

// --- 2. accountEmail: getProfile + cache -----------------------------------

console.log("\n[2] accountEmail — users.getProfile, cached, fail-soft");
let profileCalls = 0;
const gOk = { gmail: { users: { getProfile: async () => { profileCalls++; return { data: { emailAddress: "work@x.com" } }; } } } };
const cache = new Map();
check("first call returns email", (await accountEmail(gOk, "work", cache)) === "work@x.com");
check("getProfile hit once", profileCalls === 1, String(profileCalls));
check("second call served from cache", (await accountEmail(gOk, "work", cache)) === "work@x.com" && profileCalls === 1, String(profileCalls));
const gErr = { gmail: { users: { getProfile: async () => { throw new Error("boom"); } } } };
check("error → undefined (fail-soft), never throws", (await accountEmail(gErr, "other", new Map())) === undefined);

// --- 3. buildUserClients: unknown label error names labels AND emails ------

console.log("\n[3] unknown account error lists labels + emails");
const user = {
  name: "owner",
  defaultAccount: "work",
  accounts: [
    { name: "personal", email: "donskikh.ms@gmail.com", auth: { mode: "oauth", clientId: "x", clientSecret: "y", refreshToken: "z" } },
    { name: "work", email: "maksim.donskikh@fixandrollgarage.com", auth: { mode: "oauth", clientId: "x", clientSecret: "y", refreshToken: "z" } },
  ],
};
const clients = buildUserClients(user);
let err = "";
try { clients.resolve("maksim.donskikh"); } catch (e) { err = e.message; }
check("resolve() throws on unknown", err.length > 0, err);
check("error names the bad label", err.includes("maksim.donskikh"), err);
check("error lists label personal", err.includes("personal"), err);
check("error lists email donskikh.ms@gmail.com", err.includes("donskikh.ms@gmail.com"), err);
check("error lists work's email", err.includes("maksim.donskikh@fixandrollgarage.com"), err);
check("emailFor(work) resolves", clients.emailFor("work") === "maksim.donskikh@fixandrollgarage.com", clients.emailFor("work"));

console.log("\n[4] canonicalName — '' and omitted resolve to the default, unknown throws");
check("'' → default (no bogus empty label)", clients.canonicalName("") === "work");
check("omitted → default", clients.canonicalName() === "work");
check("'  ' whitespace → default", clients.canonicalName("   ") === "work");
let cErr = "";
try { clients.canonicalName("nope"); } catch (e) { cErr = e.message; }
check("unknown throws with emails", cErr.includes("nope") && cErr.includes("donskikh.ms@gmail.com"), cErr);

// --- 4. env-only account (no email) shows label alone (fail-soft) ----------

console.log("\n[5] env-only account without email → label shown alone");
const envUser = {
  defaultAccount: "default",
  accounts: [{ name: "default", auth: { mode: "oauth", clientId: "x", clientSecret: "y", refreshToken: "z" } }],
};
const envClients = buildUserClients(envUser);
let eErr = "";
try { envClients.resolve("bogus"); } catch (e) { eErr = e.message; }
check("error still thrown", eErr.includes("bogus"), eErr);
check("no email shown when unknown (label alone)", eErr.includes("default") && !eErr.includes("("), eErr);
check("emailFor undefined for env account", envClients.emailFor("default") === undefined);

// --- 5. schedule_send fail-fast: unknown label queues NOTHING --------------

console.log("\n[6] schedule_send with an unknown label — refused, nothing queued");
const scheduled = [];
const store = {
  addSnooze: async () => {},
  addScheduledSend: async (a) => { scheduled.push(a); return 1; },
  listScheduledSends: async () => [],
  cancelScheduledSend: async () => false,
  countScheduledSends: async () => 0,
};
const known = new Set(["personal"]);
const keyFor = (n) => (n && n.trim() ? n.trim() : "personal");
const sendCalls = [];
const fakeClients = {
  names: ["personal"],
  defaultName: "personal",
  multi: false,
  resolve: (n) => {
    if (!known.has(keyFor(n))) throw new Error(`❌ Неизвестный аккаунт "${keyFor(n)}". Доступные: personal (me@x.com).`);
    return { gmail: { users: { getProfile: async () => ({ data: { emailAddress: "me@x.com" } }), messages: { send: async (a) => { sendCalls.push(a); return { data: { id: "X" } }; } } } } };
  },
  canonicalName: (n) => {
    if (!known.has(keyFor(n))) throw new Error(`❌ Неизвестный аккаунт "${keyFor(n)}". Доступные: personal (me@x.com).`);
    return keyFor(n);
  },
  emailFor: () => "me@x.com",
  baseGmailQuery: () => "",
};
// gmail_schedule_send is now consent-gated (package A3) too — supply a
// (trivial, unused-in-this-path) fake consentStore so the tool gets past its
// own "no consent storage" refusal and actually reaches account resolution,
// which is what this test is really checking.
const consentStore = {
  createManifest: async () => {},
  getManifest: async () => null,
  consumeManifest: async () => null,
  invalidateManifest: async () => {},
  appendConsentAudit: async () => {},
  updateConsentAuditOutcome: async () => {},
};
const consentCfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 10_000, sendBatchMax: 10 };
const server = new McpServer({ name: "b1-test", version: "0" });
registerGmailTools(server, fakeClients, { store, userToken: null, consentStore, consentCfg });
const cli = new Client({ name: "c", version: "0" });
const [a, b] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(b), cli.connect(a)]);
const res = await cli.callTool({
  name: "gmail_schedule_send",
  arguments: { account: "maksim.donskikh", messages: [{ to: "x@y.com", subject: "s", body: "b", sendAt: "2099-01-01T00:00:00Z" }] },
});
check("tool-level error (not per-item)", res.isError === true, JSON.stringify(res.content?.[0]?.text));
check("error names the bad label + emails", /maksim\.donskikh/.test(res.content[0].text) && /me@x\.com/.test(res.content[0].text), res.content[0].text);
check("NOTHING queued to the store", scheduled.length === 0, String(scheduled.length));
check("NOTHING sent", sendCalls.length === 0, String(sendCalls.length));

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
