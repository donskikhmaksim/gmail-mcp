#!/usr/bin/env node
/**
 * B3 — post-verify of sends (references/identity-postverify.md §5).
 *
 * A 200 OK from messages.send is not proof. After each send the server makes a
 * SEPARATE metadata read and checks it independently. Covers:
 *  - labelIds ["SENT","INBOX"] → ❌ (self-send, incident 2), header not "sent";
 *  - ["SENT"] → ✅;
 *  - messages.get throws/times out → ⚠️ "not verified", the send still stands;
 *  - a 3-message batch with the 2nd failing → ⚠️ aggregate;
 *  - the §5.3 report is glued on by the server and reprint-verbatim tailed.
 *
 * Both the direct helper (postVerifySend) and the wired-up gmail_send tool are
 * exercised. No network.
 *
 * Usage: node scripts/test-b3-postverify.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools, postVerifySend, renderPostVerifyReport } from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};
const parse = (r) => r.structuredContent ?? JSON.parse(r.content[0].text);

function gWith(getImpl) {
  return { gmail: { users: { messages: { get: getImpl } } } };
}
const headers = (to, subject) => ({ data: { labelIds: [], payload: { headers: [{ name: "To", value: to }, { name: "Subject", value: subject }] } } });
const withLabels = (to, subject, labelIds) => ({ data: { labelIds, payload: { headers: [{ name: "To", value: to }, { name: "Subject", value: subject }] } } });

// gmail_send is now consent-gated (package A3) — a bare call with `messages`
// only builds a plan and sends nothing. These tests care about post-verify
// plumbing, not the gate itself (that's scripts/test-a3-gate.mjs), so the fake
// store here uses minConsentGapMs=0 to skip the anti-doublet wait and just
// drive plan→confirm mechanically.
function makeFakeConsentStore() {
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
const FAKE_CONSENT_CFG = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 0, sendBatchMax: 10 };

/** Extracts the manifest id consent.ts's renderPlanned() embeds as `` `<id>` ``. */
function extractManifestId(previewText) {
  const m = previewText.match(/план `([^`]+)`/);
  if (!m) throw new Error("no manifest id found in plan preview: " + previewText);
  return m[1];
}

/** Drives the two-phase gate to completion: plan, then confirm with an
 * affirmative user_reply. Returns the parsed (JSON) execute-phase result. */
async function sendThroughGate(cli, toolName, planArgs) {
  const planResp = await cli.callTool({ name: toolName, arguments: planArgs });
  const previewText = planResp.content[0].text;
  const manifestId = extractManifestId(previewText);
  const execResp = await cli.callTool({
    name: toolName,
    arguments: { account: planArgs.account, manifest_id: manifestId, user_reply: "да, отправляй" },
  });
  return parse(execResp);
}

// --- 1. self-send → ❌ ------------------------------------------------------

console.log("\n[1] postVerifySend — SENT+INBOX is a self-send → ❌");
{
  const g = gWith(async () => withLabels("Me <me@x.com>", "Hi", ["SENT", "INBOX", "UNREAD"]));
  const pv = await postVerifySend(g, "MID1", "eric@naicapital.com", "me@x.com");
  check("outcome mismatch", pv.outcome === "mismatch", pv.outcome);
  check("line is ❌", pv.line.startsWith("- ❌"), pv.line);
  check("line mentions self-send", /ВАМ ЖЕ|самому себе/i.test(pv.line), pv.line);
}

// --- 2. normal send → ✅ ----------------------------------------------------

console.log("\n[2] postVerifySend — SENT only → ✅");
{
  const g = gWith(async () => withLabels("eric@naicapital.com", "Quote", ["SENT"]));
  const pv = await postVerifySend(g, "MID2", "eric@naicapital.com", "me@x.com");
  check("outcome ok", pv.outcome === "ok", pv.outcome);
  check("line is ✅", pv.line.startsWith("- ✅"), pv.line);
}

// --- 3. read fails/times out → ⚠️ ------------------------------------------

console.log("\n[3] postVerifySend — read throws → ⚠️ 'not verified', never throws");
{
  const g = gWith(async () => { throw new Error("network down"); });
  const pv = await postVerifySend(g, "MID3", "eric@naicapital.com", "me@x.com");
  check("outcome warn", pv.outcome === "warn", pv.outcome);
  check("line is ⚠️", pv.line.startsWith("- ⚠️"), pv.line);
}
console.log("\n[3b] postVerifySend — read hangs past timeout → ⚠️");
{
  const g = gWith(() => new Promise(() => {})); // never resolves
  const pv = await postVerifySend(g, "MID3b", "eric@x.com", "me@x.com", 50);
  check("timeout yields warn", pv.outcome === "warn", pv.outcome);
}

// --- 4. report rendering ----------------------------------------------------

console.log("\n[4] renderPostVerifyReport — §5.3 shape, БЕЗ инструкций агенту в теле");
{
  const rep = renderPostVerifyReport([
    { outcome: "ok", messageId: "a", line: "- ✅ **«A»** — в «Отправленных», To: x@y.com", detail: "" },
    { outcome: "mismatch", messageId: "b", line: "- ❌ **«B»** — ушло ВАМ ЖЕ", detail: "" },
  ]);
  check("has proof heading", rep.includes("🧾 Независимая проверка"), rep);
  check("counts summarised", /✅ 1 подтверждено, ⚠️ 0 не проверено, ❌ 1 расхождение/.test(rep), rep);
  // Было наоборот («instruction present») до 2026-08-06: сервер вшивал в тело
  // отчёта «[агенту: перепечатай … ДОСЛОВНО]». Требование не исчезло — оно
  // переехало в `_meta` ответа; в ДАННЫХ обращений к модели быть не должно.
  // Полноценная проверка «по существу, а не по строке» — test-no-agent-directives.mjs.
  check("НЕТ хвоста-инструкции агенту", !/перепечатай|\[агенту:/i.test(rep), rep);
}

// --- 5. wired gmail_send: self-send keeps header off ✅ ---------------------

console.log("\n[5] gmail_send — self-send flips the whole header to ❌ (fail-closed)");
const sendCalls = [];
function fakeClients(getImpl) {
  return {
    names: ["personal"],
    defaultName: "personal",
    multi: false,
    resolve: () => ({
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: "me@x.com" } }),
          messages: {
            send: async (a) => { sendCalls.push(a); return { data: { id: "SID" + sendCalls.length } }; },
            get: getImpl,
          },
        },
      },
    }),
    canonicalName: (n) => (n && n.trim() ? n.trim() : "personal"),
    emailFor: () => "me@x.com",
    baseGmailQuery: () => "",
  };
}
async function harness(getImpl) {
  const server = new McpServer({ name: "b3", version: "0" });
  registerGmailTools(server, fakeClients(getImpl), {
    store: null,
    userToken: null,
    consentStore: makeFakeConsentStore(),
    consentCfg: FAKE_CONSENT_CFG,
  });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);
  return cli;
}
{
  sendCalls.length = 0;
  const cli = await harness(async () => withLabels("Me <me@x.com>", "Hi", ["SENT", "INBOX"]));
  const planResp = await cli.callTool({ name: "gmail_send", arguments: { messages: [{ to: "me@x.com", subject: "Hi", body: "b" }] } });
  check("plan phase does not send", sendCalls.length === 0, String(sendCalls.length));
  const manifestId = extractManifestId(planResp.content[0].text);
  const out = parse(
    await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId, user_reply: "да, отправляй" } }),
  );
  check("send actually happened once", sendCalls.length === 1, String(sendCalls.length));
  check("header is NOT ✉️/✅ on self-send", out.summary.startsWith("❌"), out.summary);
  check("verification block attached", /🧾 Независимая проверка/.test(out.verification ?? ""), out.verification);
}

// --- 6. wired gmail_send: clean send → ✉️ header + ✅ proof -----------------

console.log("\n[6] gmail_send — clean send → normal header + ✅ proof");
{
  sendCalls.length = 0;
  const cli = await harness(async () => withLabels("eric@x.com", "Quote", ["SENT"]));
  const out = await sendThroughGate(cli, "gmail_send", { messages: [{ to: "eric@x.com", subject: "Quote", body: "b" }] });
  check("header is ✉️ Отправлено 1/1", out.summary.startsWith("✉️") && out.summary.includes("1/1"), out.summary);
  check("proof shows ✅ 1 подтверждено", /✅ 1 подтверждено/.test(out.verification ?? ""), out.verification);
}

// --- 7. batch partial failure → ⚠️ aggregate -------------------------------

console.log("\n[7] gmail_send — batch of 3, middle send fails → ⚠️ aggregate");
{
  sendCalls.length = 0;
  let n = 0;
  const clients = {
    names: ["personal"], defaultName: "personal", multi: false,
    resolve: () => ({
      gmail: { users: {
        getProfile: async () => ({ data: { emailAddress: "me@x.com" } }),
        messages: {
          send: async (a) => { n++; if (n === 2) throw new Error("quota"); sendCalls.push(a); return { data: { id: "SID" + n } }; },
          // Sent copy is in Sent only; To omitted here so the check confirms
          // delivery without a recipient-mismatch warning (the raw isn't parsed).
          get: async () => ({ data: { labelIds: ["SENT"], payload: { headers: [{ name: "Subject", value: "S" }] } } }),
        },
      } },
    }),
    canonicalName: (x) => (x && x.trim() ? x.trim() : "personal"),
    emailFor: () => "me@x.com",
    baseGmailQuery: () => "",
  };
  const server = new McpServer({ name: "b3b", version: "0" });
  registerGmailTools(server, clients, {
    store: null,
    userToken: null,
    consentStore: makeFakeConsentStore(),
    consentCfg: FAKE_CONSENT_CFG,
  });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);
  const out = await sendThroughGate(cli, "gmail_send", {
    messages: [
      { to: "a@x.com", subject: "1", body: "b" },
      { to: "b@x.com", subject: "2", body: "b" },
      { to: "c@x.com", subject: "3", body: "b" },
    ],
  });
  check("header is ⚠️ (partial)", out.summary.startsWith("⚠️"), out.summary);
  check("2 of 3 sent", out.summary.includes("2/3"), out.summary);
  check("failure count shown", /1 с ошибкой/.test(out.summary), out.summary);
  check("proof verifies the 2 that went", /✅ 2 подтверждено/.test(out.verification ?? ""), out.verification);
  check("the failed item kept its error", out.results.some((r) => /quota/.test(r.error ?? "")), JSON.stringify(out.results));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
