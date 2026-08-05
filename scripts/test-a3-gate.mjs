#!/usr/bin/env node
/**
 * A3 — consent gate wired into the 4 send tools (gmail_send, gmail_reply,
 * gmail_forward, gmail_schedule_send).
 *
 * System-level test: drives the REAL registered MCP tools end to end (through
 * an InMemoryTransport Client/Server pair), not requireConsent() directly —
 * scripts/test-consent.mjs already covers the gate's pure logic in isolation.
 * This file proves the WIRING: plan phase never mutates (checked via call
 * counters on the fake Gmail/Drive clients), execute needs both manifest_id
 * and user_reply, negation invalidates, a manifest is one-shot, a self-reply
 * warns instead of refusing, and an oversized batch is capped before any
 * manifest exists.
 *
 * No network, no Postgres — fake in-memory ConsentStore/PgStore + a
 * controllable clock (cfg.now) so the anti-doublet gap can be crossed without
 * a real sleep.
 *
 * Usage: node scripts/test-a3-gate.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};
const parse = (r) => JSON.parse(r.content[0].text);
const text = (r) => r.content[0].text;

function extractManifestId(previewText) {
  const m = previewText.match(/план `([^`]+)`/);
  if (!m) throw new Error("no manifest id found in plan preview: " + previewText);
  return m[1];
}

// ── fake in-memory ConsentStore (mirrors store.ts's real predicates — see
//    scripts/test-a1-manifests.mjs for the SQL-fidelity version) ────────────
//
// Takes the SAME virtual clock as the tool's consentCfg.now — the test uses a
// fixed-past epoch (not real Date.now()), so expiry/consumedAt bookkeeping
// MUST compare against that same virtual clock, not wall time.

function makeConsentStore(clock) {
  const manifests = new Map();
  const audits = new Map();
  return {
    manifests,
    audits,
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
      if (!(r.expiresAt > clock.t)) return null;
      r.status = "DONE";
      r.consumedAt = clock.t;
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

function makeClock(start = 1_700_000_000_000) {
  const c = { t: start };
  return { clock: c, now: () => c.t };
}

function makeCfg(now, overrides = {}) {
  return { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now, ...overrides };
}

function makeCounters() {
  return { send: 0, draftsCreate: 0, draftsSend: 0, addScheduledSend: 0 };
}

/** Fake Gmail/Drive clients. `getImpl` answers messages.get for reply/forward
 * original reads AND post-verify's re-read after send. */
function buildClients(counters, { selfEmail = "me@x.com", getImpl } = {}) {
  const defaultGet = async () => ({
    data: { labelIds: ["SENT"], payload: { headers: [{ name: "From", value: "eric@x.com" }, { name: "Subject", value: "Hi" }] } },
  });
  return {
    names: ["work"],
    defaultName: "work",
    multi: false,
    resolve: () => ({
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: selfEmail } }),
          messages: {
            send: async () => {
              counters.send++;
              return { data: { id: "SID" + counters.send, threadId: "T1" } };
            },
            get: getImpl ?? defaultGet,
            attachments: { get: async () => ({ data: { data: "", size: 0 } }) },
          },
          drafts: {
            create: async () => {
              counters.draftsCreate++;
              return { data: { id: "DRAFT" + counters.draftsCreate } };
            },
            send: async () => {
              counters.draftsSend++;
              return { data: { id: "SID" + counters.draftsSend } };
            },
          },
        },
      },
    }),
    canonicalName: (n) => (n && n.trim() ? n.trim() : "work"),
    emailFor: () => selfEmail,
    baseGmailQuery: () => "",
  };
}

function buildPgStore(counters) {
  return {
    addSnooze: async () => {},
    addScheduledSend: async () => {
      counters.addScheduledSend++;
      return counters.addScheduledSend;
    },
    listScheduledSends: async () => [],
    countScheduledSends: async () => 0,
    cancelScheduledSend: async () => false,
  };
}

async function harness({ clock, consentCfg, store, clientsOpts = {} } = {}) {
  const counters = makeCounters();
  const clients = buildClients(counters, clientsOpts);
  const consentStore = makeConsentStore(clock);
  // Omitted entirely (undefined) => a working fake PgStore (schedule_send needs
  // one too); pass `store: null` explicitly to test the "not configured" path.
  const pgStore = store === undefined ? buildPgStore(counters) : store;
  const server = new McpServer({ name: "a3-gate", version: "0" });
  registerGmailTools(server, clients, { store: pgStore, userToken: null, consentStore, consentCfg });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);
  return { cli, counters, consentStore };
}

// ═══ [1] план не мутирует (ни отправка, ни черновик) для всех 4 инструментов ═══

console.log("\n[1] plan phase mutates NOTHING — checked via call counters");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });

  const sendPlan = await cli.callTool({ name: "gmail_send", arguments: { messages: [{ to: "a@x.com", subject: "S", body: "B" }] } });
  check("gmail_send plan → ### 📤 План", text(sendPlan).includes("### 📤 План"), text(sendPlan).slice(0, 60));
  check("gmail_send plan: messages.send NOT called", counters.send === 0, String(counters.send));

  const replyPlan = await cli.callTool({ name: "gmail_reply", arguments: { replies: [{ messageId: "M1", body: "B" }] } });
  check("gmail_reply plan → ### 📤 План", text(replyPlan).includes("### 📤 План"), text(replyPlan).slice(0, 60));
  check("gmail_reply plan: drafts.create NOT called (incident-2 precursor)", counters.draftsCreate === 0, String(counters.draftsCreate));
  check("gmail_reply plan: drafts.send NOT called", counters.draftsSend === 0, String(counters.draftsSend));

  const fwdPlan = await cli.callTool({ name: "gmail_forward", arguments: { items: [{ messageId: "M1", to: "b@x.com" }] } });
  check("gmail_forward plan → ### 📤 План", text(fwdPlan).includes("### 📤 План"), text(fwdPlan).slice(0, 60));
  check("gmail_forward plan: messages.send NOT called", counters.send === 0, String(counters.send));

  const schedPlan = await cli.callTool({
    name: "gmail_schedule_send",
    arguments: { messages: [{ to: "c@x.com", subject: "S", body: "B", sendAt: "2099-01-01T08:00:00-07:00" }] },
  });
  check("gmail_schedule_send plan → ### 📤 План", text(schedPlan).includes("### 📤 План"), text(schedPlan).slice(0, 60));
  check("gmail_schedule_send plan: addScheduledSend NOT called", counters.addScheduledSend === 0, String(counters.addScheduledSend));
}

// ═══ [2] execute без user_reply → отказ («нужны оба») ═══════════════════════

console.log("\n[2] execute with manifest_id but NO user_reply → refused, nothing sent");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_send", arguments: { messages: [{ to: "a@x.com", subject: "S", body: "B" }] } });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId } });
  check("refused: нужны оба параметра", text(exec).includes("Нужны оба"), text(exec).slice(0, 80));
  check("nothing sent", counters.send === 0, String(counters.send));
}

// ═══ [3] отрицание → инвалидация манифеста ═══════════════════════════════════

console.log("\n[3] user_reply = negation → manifest invalidated, refused, nothing sent");
{
  const { clock, now } = makeClock();
  const { cli, counters, consentStore } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_send", arguments: { messages: [{ to: "a@x.com", subject: "S", body: "B" }] } });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId, user_reply: "нет, отмена" } });
  check("refused, отменено", /Отменено/.test(text(exec)), text(exec).slice(0, 80));
  check("nothing sent", counters.send === 0, String(counters.send));
  check("manifest is INVALIDATED", consentStore.manifests.get(manifestId).status === "INVALIDATED");
  // A later "yes" against the same (now-dead) manifest still refuses.
  clock.t += 1_000;
  const exec2 = await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId, user_reply: "да, отправляй" } });
  check("invalidated manifest cannot later be confirmed", !/✉️|✅/.test(text(exec2).slice(0, 5)), text(exec2).slice(0, 80));
  check("still nothing sent", counters.send === 0, String(counters.send));
}

// ═══ [4] повтор manifest_id (одноразовость) → отказ ══════════════════════════

console.log("\n[4] repeated manifest_id after a successful execute → refused, no second send");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_send", arguments: { messages: [{ to: "a@x.com", subject: "S", body: "B" }] } });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const first = parse(await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId, user_reply: "да, отправляй" } }));
  check("first execute sent", counters.send === 1, String(counters.send));
  check("first execute header ✉️/✅", /^✉️|^✅/.test(first.summary), first.summary);
  clock.t += 1_000;
  const second = await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId, user_reply: "да, отправляй" } });
  check("second execute refused (one-shot)", !/^✉️|^✅/.test(text(second)), text(second).slice(0, 80));
  check("no second send happened", counters.send === 1, String(counters.send));
}

// ═══ [5] reply самому себе → превью с предупреждением (не отказ) ════════════

console.log("\n[5] gmail_reply to a message sent BY this account → preview warns, does not refuse");
{
  const { clock, now } = makeClock();
  const selfGet = async () => ({
    data: { payload: { headers: [{ name: "From", value: "Me <me@x.com>" }, { name: "Subject", value: "Note to self" }] } },
  });
  const { cli, counters } = await harness({
    clock,
    consentCfg: makeCfg(now),
    clientsOpts: { selfEmail: "me@x.com", getImpl: selfGet },
  });
  const plan = await cli.callTool({ name: "gmail_reply", arguments: { replies: [{ messageId: "M1", body: "B" }] } });
  check("plan built (not refused)", text(plan).includes("### 📤 План"), text(plan).slice(0, 80));
  check("preview warns about self-reply", /⚠️.*(вам же|отправлено ВАМИ)/i.test(text(plan)), text(plan));
  check("still nothing sent — warning, not a mutation", counters.draftsCreate === 0 && counters.draftsSend === 0);
}

// ═══ [6] батч > SEND_BATCH_MAX → 🛑, манифест не создаётся ═══════════════════

console.log("\n[6] batch over SEND_BATCH_MAX → 🛑, no manifest created");
{
  const { clock, now } = makeClock();
  const { cli, consentStore } = await harness({ clock, consentCfg: makeCfg(now, { sendBatchMax: 10 }) });
  const messages = Array.from({ length: 11 }, (_, i) => ({ to: `u${i}@x.com`, subject: `S${i}`, body: "B" }));
  const plan = await cli.callTool({ name: "gmail_send", arguments: { messages } });
  check("refused: 🛑", text(plan).includes("🛑"), text(plan).slice(0, 80));
  check("mentions the cap / split it up", /Разбей|больше предела/.test(text(plan)), text(plan));
  check("no manifest was created", consentStore.manifests.size === 0, String(consentStore.manifests.size));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
