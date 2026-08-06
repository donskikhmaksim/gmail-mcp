#!/usr/bin/env node
/**
 * B2 — visibility of failed/sending scheduled sends + the stuck-send reaper.
 *
 * Covers ТЗ B.2 (the load-bearing fix for incident 1):
 *  - gmail_list_scheduled_sends takes a `status` param (pending/failed/…/all);
 *    for failed rows it prints the full `error`.
 *  - a failed count is surfaced even on a default (pending) call, so a
 *    silently-failed send cannot hide.
 *  - the scheduler reaper flips rows stuck in 'sending' to 'failed', NEVER
 *    re-sending, at startup and every N ticks.
 *
 * No DB, no network: a fake PgStore stands in for Postgres and the reaper is
 * exercised through scheduler.ts's injectable deps.
 *
 * Usage: node scripts/test-b2-visibility.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";
import { reapStuckSends } from "../dist/scheduler.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};
const parse = (r) => r.structuredContent ?? JSON.parse(r.content[0].text);

// --- fake store with a mix of statuses -------------------------------------

const rows = [
  { id: 1, accountLabel: "personal", toPreview: "a@x.com", subjectPreview: "Pending one", sendAt: new Date("2099-01-01T00:00:00Z"), status: "pending", error: null, sentMessageId: null },
  { id: 2, accountLabel: "personal", toPreview: "sales@instockgaragedoors.com", subjectPreview: "Lost one", sendAt: new Date("2099-01-02T00:00:00Z"), status: "failed", error: 'Unknown account "maksim.donskikh". Available accounts: personal, work, admin.', sentMessageId: null },
  { id: 3, accountLabel: "personal", toPreview: "b@x.com", subjectPreview: "Went out", sendAt: new Date("2098-01-01T00:00:00Z"), status: "sent", error: null, sentMessageId: "SENT99" },
];
const store = {
  addSnooze: async () => {},
  addScheduledSend: async () => 1,
  listScheduledSends: async (accountName, status = "pending") =>
    rows.filter((r) => r.accountLabel === accountName && (status === "all" || r.status === status)),
  countScheduledSends: async (accountName, status) =>
    rows.filter((r) => r.accountLabel === accountName && r.status === status).length,
  cancelScheduledSend: async () => false,
};

const fakeClients = {
  names: ["personal"],
  defaultName: "personal",
  multi: false,
  resolve: () => ({ gmail: { users: {} } }),
  canonicalName: (n) => (n && n.trim() ? n.trim() : "personal"),
  emailFor: () => "me@x.com",
  baseGmailQuery: () => "",
};

async function harness() {
  const server = new McpServer({ name: "b2-test", version: "0" });
  registerGmailTools(server, fakeClients, { store, userToken: null });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);
  return cli;
}

const cli = await harness();

// --- 1. default (pending) call: only pending, but warns about failed -------

console.log("\n[1] default list — pending only, but flags the failed one");
let out = parse(await cli.callTool({ name: "gmail_list_scheduled_sends", arguments: {} }));
check("only pending rows listed", out.results.length === 1 && out.results[0].id === 1, JSON.stringify(out.results));
check("failed count surfaced in a note even on pending call", /провал/i.test(out.note ?? ""), JSON.stringify(out.note));

// --- 2. status='failed' shows the full error -------------------------------

console.log("\n[2] status='failed' — the lost send is finally visible, with its error");
out = parse(await cli.callTool({ name: "gmail_list_scheduled_sends", arguments: { status: "failed" } }));
check("failed row visible", out.results.length === 1 && out.results[0].id === 2, JSON.stringify(out.results));
check("full error included", /Unknown account "maksim\.donskikh"/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
check("no redundant failed-note when already asking for failed", out.note === undefined, JSON.stringify(out.note));

// --- 3. status='all' shows everything --------------------------------------

console.log("\n[3] status='all' — every row regardless of status");
out = parse(await cli.callTool({ name: "gmail_list_scheduled_sends", arguments: { status: "all" } }));
check("all three rows listed", out.results.length === 3, JSON.stringify(out.results.map((r) => r.id)));
check("sent row carries its sent id", out.results.find((r) => r.id === 3)?.sentMessageId === "SENT99", JSON.stringify(out.results));

// --- 4. status='sent' filter -----------------------------------------------

console.log("\n[4] status='sent' — filter isolates one");
out = parse(await cli.callTool({ name: "gmail_list_scheduled_sends", arguments: { status: "sent" } }));
check("exactly the sent row", out.results.length === 1 && out.results[0].id === 3, JSON.stringify(out.results));

// --- 5. reaper: stuck 'sending' → failed, never re-sent --------------------

console.log("\n[5] reaper — flips stuck 'sending' rows to failed, never re-sends");
let reapArgs = [];
const deps = {
  reapStuckSends: async (mins) => { reapArgs.push(mins); return 2; },
};
const config = { sendingStuckMinutes: 10 };
const n = await reapStuckSends(config, deps);
check("reaper returns the count reaped", n === 2, String(n));
check("reaper called with configured minutes", reapArgs.length === 1 && reapArgs[0] === 10, JSON.stringify(reapArgs));

console.log("\n[6] reaper honours SENDING_STUCK_MINUTES override");
reapArgs = [];
await reapStuckSends({ sendingStuckMinutes: 3 }, { reapStuckSends: async (m) => { reapArgs.push(m); return 0; } });
check("uses the override value", reapArgs[0] === 3, JSON.stringify(reapArgs));

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
