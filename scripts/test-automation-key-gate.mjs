#!/usr/bin/env node
/**
 * automation_key-ветка requireConsent (docs/TZ_automation_key_consent_gate.md).
 *
 * Две части:
 *  A) ЯДРО requireConsent в изоляции (как scripts/test-consent.mjs) — прямой
 *     импорт `../src/consent.ts`, фейковый ConsentStore, управляемые часы.
 *     Покрывает пункты 2–6 тестового плана ТЗ.
 *  B) ИНТЕГРАЦИЯ на уровне живого инструмента (как scripts/test-a3-gate.mjs)
 *     — реальный registerGmailTools + InMemoryTransport, gmail_send с
 *     `automation_key` в аргументах. Покрывает пункт 7 тестового плана.
 *
 * Пункт 1 (regression: checkAutomationKey не задан → побайтово как раньше)
 * покрыт тем, что scripts/test-consent.mjs остался НЕИЗМЕННЫМ и зелёным — он
 * никогда не передаёт `automationKey`/`checkAutomationKey`, так что ни разу
 * не заходит в новую ветку.
 *
 * Usage: node scripts/test-automation-key-gate.mjs (после `npm run build` —
 * часть B грузит `../dist/tools/gmail.js`, как test-a3-gate.mjs).
 */
import { requireConsent, sha256 } from "../src/consent.ts";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

// ═══════════════════════ A) ЯДРО — прямой импорт consent.ts ═══════════════

const clock = { t: 1_700_000_000_000 };
const now = () => clock.t;

function makeStore() {
  const manifests = new Map();
  const audits = [];
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
      if (clock.t >= r.expiresAt) return null;
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
      audits.push({ ...entry });
    },
    async updateConsentAuditOutcome(auditId, outcome) {
      const a = audits.find((x) => x.id === auditId);
      if (a) Object.assign(a, outcome);
    },
  };
}

const cfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now };

const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Quote", body: "..." }] };
const OBJHASH = sha256(PAYLOAD);
const plan = () => ({ payload: PAYLOAD, objectHash: OBJHASH, preview: "### 📤 План отправки\n\n- **Кому:** eric@x.com", batchSize: 1 });
const rehash = (payload) => sha256(payload);

const okKeyCheck = async (key) => (key === "valid-key" ? { ok: true, channel: "window" } : { ok: false });
const badKeyCheck = async () => ({ ok: false });

// ── [2] валидный ключ — исполнение с первого вызова, без manifest_id/user_reply ──
console.log("\n[2] валидный automation_key (мок DI ok:true) → confirmed с первого вызова");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const dec = await requireConsent({
    tool: "gmail_send",
    accountLabel: "work",
    plan,
    rehash,
    store,
    cfg,
    automationKey: "valid-key",
    checkAutomationKey: okKeyCheck,
  });
  check("kind=confirmed", dec.kind === "confirmed", JSON.stringify(dec).slice(0, 100));
  check("manifestId пустой (манифест не создавался)", dec.kind === "confirmed" && dec.manifestId === "");
  check("payload из плана", dec.kind === "confirmed" && JSON.stringify(dec.payload) === JSON.stringify(PAYLOAD));
  check("НИ ОДИН манифест не создан в store", store.manifests.size === 0, String(store.manifests.size));
  check("аудит: ровно одна запись confirmed", store.audits.length === 1 && store.audits[0].outcome === "confirmed");
}

// ── [3] невалидный ключ — тихий fallthrough на обычный план, НЕ ошибка ──────
console.log("\n[3] невалидный/просроченный automation_key → тихий fallthrough на обычный план");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const dec = await requireConsent({
    tool: "gmail_send",
    accountLabel: "work",
    plan,
    rehash,
    store,
    cfg,
    automationKey: "garbage-key",
    checkAutomationKey: badKeyCheck,
  });
  check("kind=planned (обычный путь, НЕ ошибка)", dec.kind === "planned", JSON.stringify(dec).slice(0, 100));
  check("манифест создан обычным путём", store.manifests.size === 1);
  check(
    "превью НЕ упоминает automation_key (не подсказывает модели)",
    !/automation_key/i.test(dec.kind === "planned" ? dec.preview : ""),
  );
}

// ── [4] rehash разошёлся на automation-пути → отказ, не тихое исполнение ────
console.log("\n[4] binding (rehash) разошёлся на automation-пути → refused, не confirmed");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const driftedRehash = () => sha256({ changed: true });
  const dec = await requireConsent({
    tool: "gmail_send",
    accountLabel: "work",
    plan,
    rehash: driftedRehash,
    store,
    cfg,
    automationKey: "valid-key",
    checkAutomationKey: okKeyCheck,
  });
  check("kind=refused", dec.kind === "refused", JSON.stringify(dec).slice(0, 100));
  check("сообщение про «изменилось»", dec.kind === "refused" && dec.result.includes("изменилось"));
  check("ничего не consumed (манифеста и не было)", store.manifests.size === 0);
  check("аудит: refused, actor=automation", store.audits.at(-1).outcome === "refused" && store.audits.at(-1).actor === "automation");
}

// ── [5] превышение batch cap на automation-пути → тот же отказ, что и обычно ─
console.log("\n[5] батч > SEND_BATCH_MAX на automation-пути → тот же отказ, что на обычном пути");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const bigPlan = () => ({ payload: PAYLOAD, objectHash: OBJHASH, preview: "p", batchSize: 11 });
  const dec = await requireConsent({
    tool: "gmail_send",
    accountLabel: "work",
    plan: bigPlan,
    rehash,
    store,
    cfg,
    automationKey: "valid-key",
    checkAutomationKey: okKeyCheck,
  });
  check("kind=refused", dec.kind === "refused");
  check("тот же текст, что у обычного batch-cap отказа", dec.result.includes("Разбей") || dec.result.includes("больше предела"), dec.result?.slice(0, 80));
  check("манифест НЕ создан", store.manifests.size === 0);
}

// ── [6] аудит несёт actor:"automation" + канал ───────────────────────────────
console.log("\n[6] аудит-запись automation-исполнения несёт actor:'automation' и checks.automationKey=channel");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const dec = await requireConsent({
    tool: "gmail_send",
    accountLabel: "work",
    plan,
    rehash,
    store,
    cfg,
    automationKey: "valid-key",
    checkAutomationKey: okKeyCheck,
  });
  check("kind=confirmed", dec.kind === "confirmed");
  const audit = store.audits.at(-1);
  check("actor === 'automation'", audit.actor === "automation", audit.actor);
  check("checks.automationKey === 'window' (метка канала из DI)", audit.checks.automationKey === "window", JSON.stringify(audit.checks));
  check("outcome === 'confirmed'", audit.outcome === "confirmed");
}

// ═══════════════════ B) ИНТЕГРАЦИЯ — живой инструмент gmail_send ═══════════
// (пункт 7 тестового плана: не только ядро гейта в изоляции)

console.log("\n[7] живой gmail_send реально принимает automation_key и прокидывает его в requireConsent");
{
  const counters = { send: 0 };
  const clients = {
    names: ["work"],
    defaultName: "work",
    multi: false,
    resolve: () => ({
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: "me@x.com" } }),
          messages: {
            send: async () => {
              counters.send++;
              return { data: { id: "SID" + counters.send, threadId: "T1" } };
            },
            get: async () => ({
              data: { labelIds: ["SENT"], payload: { headers: [{ name: "From", value: "eric@x.com" }, { name: "Subject", value: "Hi" }] } },
            }),
            attachments: { get: async () => ({ data: { data: "", size: 0 } }) },
          },
          drafts: { create: async () => ({ data: { id: "D1" } }), send: async () => ({ data: { id: "D1" } }) },
        },
      },
    }),
    canonicalName: (n) => (n && n.trim() ? n.trim() : "work"),
    emailFor: () => "me@x.com",
    baseGmailQuery: () => "",
  };

  const toolClock = { t: 1_700_000_000_000 };
  const toolNow = () => toolClock.t;
  const consentStore = makeStore();
  const consentCfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now: toolNow };

  const server = new McpServer({ name: "automation-key-gate-test", version: "0" });
  registerGmailTools(server, clients, {
    store: null,
    userToken: null,
    consentStore,
    consentCfg,
    auditStore: null,
    checkAutomationKey: async (key) => (key === "real-automation-key" ? { ok: true, channel: "static" } : { ok: false }),
  });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);

  // 7a. Валидный ключ, БЕЗ manifest_id/user_reply — сразу отправляет.
  const sent = await cli.callTool({
    name: "gmail_send",
    arguments: { messages: [{ to: "a@x.com", subject: "S", body: "B" }], automation_key: "real-automation-key" },
  });
  const sentText = sent.content[0].text;
  check("gmail_send с валидным automation_key отправил СРАЗУ (нет 'План')", !sentText.includes("### 📤 План"), sentText.slice(0, 100));
  check("messages.send реально вызван", counters.send === 1, String(counters.send));

  // 7b. Невалидный ключ — падает на обычный план, ничего не отправлено.
  const planned = await cli.callTool({
    name: "gmail_send",
    arguments: { messages: [{ to: "b@x.com", subject: "S2", body: "B2" }], automation_key: "wrong-key" },
  });
  const plannedText = planned.content[0].text;
  check("невалидный automation_key → обычный план (### 📤 План)", plannedText.includes("### 📤 План"), plannedText.slice(0, 100));
  check("второе письмо НЕ отправлено", counters.send === 1, String(counters.send));

  // 7c. Без automation_key вообще (обычный человеческий путь) — тоже план, не ошибка.
  const humanPlan = await cli.callTool({
    name: "gmail_send",
    arguments: { messages: [{ to: "c@x.com", subject: "S3", body: "B3" }] },
  });
  check("без automation_key — обычный план как раньше", humanPlan.content[0].text.includes("### 📤 План"));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
