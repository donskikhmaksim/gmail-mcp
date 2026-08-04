#!/usr/bin/env node
/**
 * Offline check of gmail_snooze (fixed), gmail_schedule_send,
 * gmail_list_scheduled_sends and gmail_cancel_scheduled_send.
 *
 * A fake PgStore stands in for Postgres, so this needs no database and no
 * network. It specifically covers the bug this session found: gmail_snooze
 * used to silently skip persisting whenever userToken was null (the exact
 * case in onboarded/native-OAuth deployments) — these tests fail loudly if
 * that regresses.
 *
 * Usage:
 *   npm test                            # builds, then runs both test scripts
 *   node scripts/test-schedule-send.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";

// --- fake store --------------------------------------------------------

const snoozeCalls = [];
const scheduledRows = new Map();
let nextId = 1;

function makeStore() {
  return {
    addSnooze: async (args) => {
      snoozeCalls.push(args);
    },
    addScheduledSend: async (args) => {
      const id = nextId++;
      scheduledRows.set(id, { id, ...args, canceled: false });
      return id;
    },
    listScheduledSends: async (accountName) =>
      [...scheduledRows.values()]
        .filter((r) => r.accountName === accountName && !r.canceled)
        .map((r) => ({ id: r.id, toPreview: r.toPreview, subjectPreview: r.subjectPreview, sendAt: r.sendAt })),
    cancelScheduledSend: async (id, accountName) => {
      const row = scheduledRows.get(id);
      if (!row || row.accountName !== accountName || row.canceled) return false;
      row.canceled = true;
      return true;
    },
  };
}

// --- fake Gmail/Drive clients -------------------------------------------

const modifyCalls = [];
const sendCalls = [];

const keyFor = (n) => (n && n.trim() ? n.trim() : "personal");
const known = new Set(["personal"]);
const fakeClients = {
  names: ["personal"],
  defaultName: "personal",
  multi: false,
  resolve: (n) => {
    const key = keyFor(n);
    if (!known.has(key)) throw new Error(`❌ Неизвестный аккаунт "${key}". Доступные: personal (me@personal.test).`);
    return {
      docs: {},
      drive: {},
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: "me@personal.test" } }),
          messages: {
            modify: async (args) => {
              modifyCalls.push(args);
              return { data: {} };
            },
            send: async (args) => {
              sendCalls.push(args);
              return { data: { id: "SENTID", threadId: "THREAD1" } };
            },
            get: async () => ({ data: { payload: {}, labelIds: ["SENT"] } }),
            attachments: { get: async () => ({ data: { data: "", size: 0 } }) },
          },
        },
      },
      accessToken: async () => "ya29.FAKE",
    };
  },
  canonicalName: (n) => {
    const key = keyFor(n);
    if (!known.has(key)) throw new Error(`❌ Неизвестный аккаунт "${key}". Доступные: personal (me@personal.test).`);
    return key;
  },
  emailFor: (n) => (known.has(keyFor(n)) ? "me@personal.test" : undefined),
  baseGmailQuery: () => "",
};

async function buildHarness(snoozeCtx) {
  const server = new McpServer({ name: "gmail-mcp-test", version: "0" });
  registerGmailTools(server, fakeClients, snoozeCtx);
  const client = new Client({ name: "test-client", version: "0" });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  return client;
}

const parse = (r) => JSON.parse(r.content[0].text);

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

// --- 1. tool registration ------------------------------------------------

console.log("\n[1] tool registration");
let client = await buildHarness({ store: null, userToken: null });
const names = (await client.listTools()).tools.map((t) => t.name);
for (const t of ["gmail_snooze", "gmail_schedule_send", "gmail_list_scheduled_sends", "gmail_cancel_scheduled_send"]) {
  check(`${t} registered`, names.includes(t));
}

// --- 2. THE bug this session found: snooze with store but NO userToken ---

console.log("\n[2] snooze persists even when userToken is null (onboarded deployments)");
snoozeCalls.length = 0;
client = await buildHarness({ store: makeStore(), userToken: null });
let out = parse(
  await client.callTool({
    name: "gmail_snooze",
    arguments: { items: [{ messageId: "MSG1", unsnoozeAt: "2099-01-01T09:00:00Z" }] },
  }),
);
check("archived (INBOX label removed)", modifyCalls.at(-1)?.requestBody?.removeLabelIds?.includes("INBOX"));
check("addSnooze WAS called despite userToken being null", snoozeCalls.length === 1, String(snoozeCalls.length));
check("userToken null is passed through as null, not skipped", snoozeCalls[0]?.userToken === null, JSON.stringify(snoozeCalls[0]));
check("accountLabel recorded", snoozeCalls[0]?.accountName === "personal", JSON.stringify(snoozeCalls[0]));
check("result says persisted: true", out.results[0].persisted === true, JSON.stringify(out.results[0]));

console.log("\n[3] snooze without a store at all — archives, says so honestly");
snoozeCalls.length = 0;
modifyCalls.length = 0;
client = await buildHarness({ store: null, userToken: null });
out = parse(
  await client.callTool({
    name: "gmail_snooze",
    arguments: { items: [{ messageId: "MSG2", unsnoozeAt: "2099-01-01T09:00:00Z" }] },
  }),
);
check("still archived", modifyCalls.length === 1);
check("nothing to persist to", snoozeCalls.length === 0);
check("result says persisted: false — no false advertising", out.results[0].persisted === false, JSON.stringify(out.results[0]));

console.log("\n[4] snooze validation: bad/past dates rejected before archiving");
modifyCalls.length = 0;
out = parse(
  await client.callTool({ name: "gmail_snooze", arguments: { items: [{ messageId: "MSG3", unsnoozeAt: "not-a-date" }] } }),
);
check("unparsable date rejected", /Cannot parse date/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
out = parse(
  await client.callTool({ name: "gmail_snooze", arguments: { items: [{ messageId: "MSG4", unsnoozeAt: "2000-01-01T00:00:00Z" }] } }),
);
check("past date rejected", /already in the past/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
check("no archiving happened for either rejected item", modifyCalls.length === 0, String(modifyCalls.length));

// --- 5-9. gmail_schedule_send ---------------------------------------------

console.log("\n[5] schedule_send without a store — refuses plainly, sends nothing");
sendCalls.length = 0;
client = await buildHarness({ store: null, userToken: null });
let raw = await client.callTool({
  name: "gmail_schedule_send",
  arguments: { messages: [{ to: "a@b.com", subject: "Hi", body: "text", sendAt: "2099-01-01T08:00:00-07:00" }] },
});
check("tool-level error, not a per-item one", raw.isError === true && /DATABASE_URL/.test(raw.content[0].text), raw.content[0].text);
check("nothing sent immediately", sendCalls.length === 0);

console.log("\n[6] schedule_send — builds and validates the raw message NOW, stores it, sends NOTHING yet");
const store = makeStore();
client = await buildHarness({ store, userToken: null });
out = parse(
  await client.callTool({
    name: "gmail_schedule_send",
    arguments: {
      messages: [{ to: "boss@x.com", subject: "Отчёт", body: "Готово", sendAt: "2099-01-01T08:00:00-07:00" }],
    },
  }),
);
let r = out.results[0];
check("id assigned", typeof r.id === "number", JSON.stringify(r));
check("to/subject echoed", r.to === "boss@x.com" && r.subject === "Отчёт", JSON.stringify(r));
check("sendAt normalised to ISO", r.sendAt === new Date("2099-01-01T08:00:00-07:00").toISOString(), r.sendAt);
check("NOT sent yet — send() never called", sendCalls.length === 0, String(sendCalls.length));
const stored = [...scheduledRows.values()][0];
check("raw RFC822 message stored", stored.rawMessage.length > 0, String(stored.rawMessage?.length));
check("account recorded", stored.accountName === "personal", stored.accountName);

console.log("\n[7] schedule_send validation: bad/past sendAt rejected, per item");
out = parse(
  await client.callTool({
    name: "gmail_schedule_send",
    arguments: {
      messages: [
        { to: "a@b.com", subject: "s1", body: "b1", sendAt: "garbage" },
        { to: "c@d.com", subject: "s2", body: "b2", sendAt: "2000-01-01T00:00:00Z" },
        { to: "good@x.com", subject: "s3", body: "b3", sendAt: "2099-06-01T00:00:00Z" },
      ],
    },
  }),
);
check("unparsable sendAt rejected", /Cannot parse date/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
check("past sendAt rejected", /already in the past/.test(out.results[1].error ?? ""), JSON.stringify(out.results[1]));
check("good item still scheduled despite siblings failing", typeof out.results[2].id === "number", JSON.stringify(out.results[2]));

console.log("\n[8] list_scheduled_sends — sees queued, not canceled, scoped to account");
out = parse(await client.callTool({ name: "gmail_list_scheduled_sends", arguments: {} }));
check("lists the scheduled items", out.results.some((x) => x.subject === "Отчёт"), JSON.stringify(out.results));
check("soonest-relevant fields present", out.results.every((x) => "id" in x && "sendAt" in x));

console.log("\n[9] cancel_scheduled_send — cancels once, refuses a repeat, isolates unknown ids");
const idToCancel = [...scheduledRows.values()].find((r) => r.subjectPreview === "Отчёт").id;
out = parse(await client.callTool({ name: "gmail_cancel_scheduled_send", arguments: { ids: [idToCancel] } }));
check("canceled", out.results[0].canceled === true, JSON.stringify(out.results[0]));
out = parse(await client.callTool({ name: "gmail_cancel_scheduled_send", arguments: { ids: [idToCancel, 999999] } }));
check("re-canceling the same id fails cleanly", out.results[0].canceled === false, JSON.stringify(out.results[0]));
check("unknown id fails cleanly, not an exception", out.results[1].canceled === false, JSON.stringify(out.results[1]));
out = parse(await client.callTool({ name: "gmail_list_scheduled_sends", arguments: {} }));
check("canceled item no longer listed", !out.results.some((x) => x.id === idToCancel), JSON.stringify(out.results));

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
