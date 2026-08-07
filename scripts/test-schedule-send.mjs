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
    // Status-aware: gmail_cancel_scheduled_send's post-verify re-reads the
    // 'canceled' bucket, so a fake that only ever answers 'pending' would make
    // a real cancellation look unverifiable.
    listScheduledSends: async (accountName, status = "pending") =>
      [...scheduledRows.values()]
        .filter((r) => r.accountName === accountName)
        .filter((r) => (status === "all" ? true : status === "canceled" ? r.canceled : status === "pending" ? !r.canceled : false))
        .map((r) => ({
          id: r.id,
          toPreview: r.toPreview,
          subjectPreview: r.subjectPreview,
          sendAt: r.sendAt,
          status: r.canceled ? "canceled" : "pending",
        })),
    countScheduledSends: async () => 0,
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

const parse = (r) => r.structuredContent ?? JSON.parse(r.content[0].text);

// gmail_schedule_send is now consent-gated (package A3): a bare call with
// `messages` only builds a plan, nothing is queued. Sections 5-7 below drive
// the two-phase flow with a tiny in-memory ConsentStore — minConsentGapMs=0
// skips the anti-doublet wait since that's covered by scripts/test-consent.mjs
// / scripts/test-a3-gate.mjs, not the point of this file.
function makeConsentStore() {
  const manifests = new Map();
  const audits = new Map();
  return {
    async createManifest(input) {
      manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null });
    },
    async getManifest(id, server) {
      const r = manifests.get(id);
      return r && r.server === server ? { ...r } : null;
    },
    async consumeManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (!r || r.server !== server || r.status !== "AWAITING_CONSENT") return null;
      r.status = "DONE";
      r.consumedAt = Date.now();
      r.userReply = userReply;
      return { ...r };
    },
    async invalidateManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (r && r.server === server && r.status === "AWAITING_CONSENT") {
        r.status = "INVALIDATED";
        r.userReply = userReply;
      }
    },
    async appendConsentAudit(entry) {
      audits.set(entry.id, { ...entry });
    },
    async updateConsentAuditOutcome(auditId, outcome) {
      const a = audits.get(auditId);
      if (a) Object.assign(a, outcome);
    },
  };
}
const CONSENT_CFG = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 0, sendBatchMax: 10 };
function extractManifestId(previewText) {
  const m = previewText.match(/план `([^`]+)`/);
  if (!m) throw new Error("no manifest id found in plan preview: " + previewText);
  return m[1];
}
/** Drives any gated tool's plan → confirm in one call; returns the parsed
 * execute-phase result. gmail_snooze (package T1) uses this too now — same
 * two-phase mechanics as gmail_schedule_send (package A3), just a different
 * tool name. */
async function planThenExecute(client, name, args, userReply = "да, отправляй") {
  const planResp = await client.callTool({ name, arguments: args });
  const manifestId = extractManifestId(planResp.content[0].text);
  return parse(await client.callTool({ name, arguments: { manifest_id: manifestId, user_reply: userReply } }));
}
async function scheduleThroughGate(client, args) {
  return planThenExecute(client, "gmail_schedule_send", args);
}

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
client = await buildHarness({ store: makeStore(), userToken: null, consentStore: makeConsentStore(), consentCfg: CONSENT_CFG });
let out = await planThenExecute(client, "gmail_snooze", {
  items: [{ messageId: "MSG1", unsnoozeAt: "2099-01-01T09:00:00Z" }],
});
check("archived (INBOX label removed)", modifyCalls.at(-1)?.requestBody?.removeLabelIds?.includes("INBOX"));
check("addSnooze WAS called despite userToken being null", snoozeCalls.length === 1, String(snoozeCalls.length));
check("userToken null is passed through as null, not skipped", snoozeCalls[0]?.userToken === null, JSON.stringify(snoozeCalls[0]));
check("accountLabel recorded", snoozeCalls[0]?.accountName === "personal", JSON.stringify(snoozeCalls[0]));
check("result says persisted: true", out.results[0].persisted === true, JSON.stringify(out.results[0]));

console.log("\n[3] snooze without a store at all — archives, says so honestly");
snoozeCalls.length = 0;
modifyCalls.length = 0;
client = await buildHarness({ store: null, userToken: null, consentStore: makeConsentStore(), consentCfg: CONSENT_CFG });
out = await planThenExecute(client, "gmail_snooze", {
  items: [{ messageId: "MSG2", unsnoozeAt: "2099-01-01T09:00:00Z" }],
});
check("still archived", modifyCalls.length === 1);
check("nothing to persist to", snoozeCalls.length === 0);
check("result says persisted: false — no false advertising", out.results[0].persisted === false, JSON.stringify(out.results[0]));

console.log("\n[4] snooze validation: bad/past dates rejected before archiving");
modifyCalls.length = 0;
out = await planThenExecute(client, "gmail_snooze", { items: [{ messageId: "MSG3", unsnoozeAt: "not-a-date" }] });
check("unparsable date rejected", /Cannot parse date/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
out = await planThenExecute(client, "gmail_snooze", { items: [{ messageId: "MSG4", unsnoozeAt: "2000-01-01T00:00:00Z" }] });
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
client = await buildHarness({ store, userToken: null, consentStore: makeConsentStore(), consentCfg: CONSENT_CFG });
out = await scheduleThroughGate(client, {
  messages: [{ to: "boss@x.com", subject: "Отчёт", body: "Готово", sendAt: "2099-01-01T08:00:00-07:00" }],
});
let r = out.results[0];
check("id assigned", typeof r.id === "number", JSON.stringify(r));
check("to/subject echoed", r.to === "boss@x.com" && r.subject === "Отчёт", JSON.stringify(r));
check("sendAt normalised to ISO", r.sendAt === new Date("2099-01-01T08:00:00-07:00").toISOString(), r.sendAt);
check("NOT sent yet — send() never called", sendCalls.length === 0, String(sendCalls.length));
const stored = [...scheduledRows.values()][0];
check("raw RFC822 message stored", stored.rawMessage.length > 0, String(stored.rawMessage?.length));
check("account recorded", stored.accountName === "personal", stored.accountName);

console.log("\n[7] schedule_send validation: bad/past sendAt rejected, per item");
out = await scheduleThroughGate(client, {
  messages: [
    { to: "a@b.com", subject: "s1", body: "b1", sendAt: "garbage" },
    { to: "c@d.com", subject: "s2", body: "b2", sendAt: "2000-01-01T00:00:00Z" },
    { to: "good@x.com", subject: "s3", body: "b3", sendAt: "2099-06-01T00:00:00Z" },
  ],
});
check("unparsable sendAt rejected", /Cannot parse date/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
check("past sendAt rejected", /already in the past/.test(out.results[1].error ?? ""), JSON.stringify(out.results[1]));
check("good item still scheduled despite siblings failing", typeof out.results[2].id === "number", JSON.stringify(out.results[2]));

console.log("\n[8] list_scheduled_sends — sees queued, not canceled, scoped to account");
out = parse(await client.callTool({ name: "gmail_list_scheduled_sends", arguments: {} }));
check("lists the scheduled items", out.results.some((x) => x.subject === "Отчёт"), JSON.stringify(out.results));
check("soonest-relevant fields present", out.results.every((x) => "id" in x && "sendAt" in x));

console.log("\n[9] cancel_scheduled_send — GATED (2026-08-06): plan first, then execute");
const idToCancel = [...scheduledRows.values()].find((r) => r.subjectPreview === "Отчёт").id;

// 9a. A bare call must NOT cancel anything — it plans, and the preview has to
//     name what would be lost (recipient/subject), not just an id.
const planResp = await client.callTool({ name: "gmail_cancel_scheduled_send", arguments: { ids: [idToCancel] } });
const planText = planResp.content[0].text;
check("bare call returns a plan, not a result", planText.includes("### 📤 План"), planText.slice(0, 80));
check("preview names the recipient", planText.includes("boss@x.com"), planText.slice(0, 300));
check("preview names the subject", planText.includes("Отчёт"), planText.slice(0, 300));
check("preview warns the cancellation is one-way", /Обратной операции нет/.test(planText), planText.slice(0, 300));
check(
  "NOTHING was cancelled by the plan call",
  scheduledRows.get(idToCancel).canceled === false,
  JSON.stringify(scheduledRows.get(idToCancel)),
);
out = parse(await client.callTool({ name: "gmail_list_scheduled_sends", arguments: {} }));
check("still listed as pending after the plan call", out.results.some((x) => x.id === idToCancel), JSON.stringify(out.results));

// 9b. Execute with the manifest + a verbatim human reply.
out = await planThenExecute(client, "gmail_cancel_scheduled_send", { ids: [idToCancel] }, "да, отменяй");
check("canceled after confirmation", scheduledRows.get(idToCancel).canceled === true, JSON.stringify(out));
check("summary reports 1/1 canceled", /Отменено 1\/1/.test(out.summary), JSON.stringify(out.summary));
check("post-verify re-read the live queue", /отменена, подтверждено по живой очереди/.test(out.verification ?? ""), JSON.stringify(out.verification));
out = parse(await client.callTool({ name: "gmail_list_scheduled_sends", arguments: {} }));
check("canceled item no longer listed", !out.results.some((x) => x.id === idToCancel), JSON.stringify(out.results));

// 9c. An id that is not pending must break the PLAN — the person confirming
//     should never see a preview containing a message that cannot be cancelled.
const badPlan = await client.callTool({ name: "gmail_cancel_scheduled_send", arguments: { ids: [idToCancel, 999999] } });
const badText = badPlan.content[0].text;
check("plan refuses when an id is not pending", /не найдена среди ожидающих/.test(badText), badText.slice(0, 200));
check("refusal is an error result, not a plan", !badText.includes("### 📤 План"), badText.slice(0, 80));

// 9d. REAL binding (gate.md §3.3 п.2): the queue is re-read at execute time.
//     A message that left (or was cancelled elsewhere) between plan and
//     confirmation must not be silently swapped for whatever is there now — a
//     degenerate `rehash: sha256(addressing)` would happily accept it.
console.log("\n[9d] cancel_scheduled_send — binding catches a queue that moved after the plan");
out = await scheduleThroughGate(client, {
  messages: [{ to: "drift@x.com", subject: "Уедет", body: "b", sendAt: "2099-07-01T08:00:00Z" }],
});
const driftId = out.results[0].id;
const driftPlan = await client.callTool({ name: "gmail_cancel_scheduled_send", arguments: { ids: [driftId] } });
const driftManifest = extractManifestId(driftPlan.content[0].text);
// …the world moves: that message goes out (leaves the pending queue) before
// the human's "yes" is relayed.
scheduledRows.get(driftId).canceled = true;
const driftOut = (await client.callTool({
  name: "gmail_cancel_scheduled_send",
  arguments: { manifest_id: driftManifest, user_reply: "да, отменяй" },
})).content[0].text;
check("stale plan is refused after the queue changed", /Состояние изменилось после планирования/.test(driftOut), driftOut.slice(0, 200));
check("no success header on a refused stale plan", !/Отменено 1\/1/.test(driftOut), driftOut.slice(0, 120));

// 9e. Post-verify must RE-READ the queue, never trust the UPDATE's own answer.
//     A store that reports success while the row stays pending is exactly the
//     silent-failure shape incident 1 had; the response must show ❌, not ✅.
console.log("\n[9e] cancel_scheduled_send — post-verify believes the live queue, not the write call");
const lyingStore = {
  ...makeStore(),
  listScheduledSends: async (_a, status = "pending") =>
    status === "pending"
      ? [{ id: 42, toPreview: "x@y.com", subjectPreview: "Не отменится", sendAt: new Date("2099-01-01T00:00:00Z"), status: "pending" }]
      : [], // 'canceled' stays empty — the cancellation never actually landed
  cancelScheduledSend: async () => true, // …but the write call claims success
};
const lyingClient = await buildHarness({
  store: lyingStore,
  userToken: null,
  consentStore: makeConsentStore(),
  consentCfg: CONSENT_CFG,
});
const lyingOut = await planThenExecute(lyingClient, "gmail_cancel_scheduled_send", { ids: [42] }, "да, отменяй");
check("mismatch is caught by post-verify", /НЕ значится отменённой/.test(lyingOut.verification ?? ""), JSON.stringify(lyingOut.verification));
check("the header is NOT a clean success", /❌/.test(lyingOut.summary ?? ""), JSON.stringify(lyingOut.summary));

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
