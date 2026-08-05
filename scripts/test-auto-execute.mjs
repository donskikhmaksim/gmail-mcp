#!/usr/bin/env node
/**
 * Offline unit-тест авто-исполнения по кнопке в Telegram (`consent.ts`'s
 * `tryAutoExecute`) — Максим, 2026-08-05: «нажал кнопку — сразу исполнилось
 * на бэке, не ждать повторного вызова моделью». Фейковый ConsentStore,
 * управляемые часы — ни БД, ни сети.
 *
 * Запуск: node scripts/test-auto-execute.mjs
 */
import { tryAutoExecute, sha256, TG_AUTO_REPLY_MARKER } from "../src/consent.ts";

const clock = { t: 1_700_000_000_000 };
const now = () => clock.t;

function makeStore() {
  const manifests = new Map();
  const audits = [];
  return {
    manifests,
    audits,
    async getManifest(id, server) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      return { ...r };
    },
    async consumeManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      if (r.status !== "AWAITING_CONSENT") return null;
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
    async updateConsentAuditOutcome() {},
    async createManifest(input) {
      manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null });
    },
  };
}

const cfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now };

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Q", body: "..." }] };
const OBJHASH = sha256(PAYLOAD);
const rehashOk = (addressing) => sha256(addressing);
const rehashDrift = () => "different-hash-simulating-drift";

console.log("[1] happy path — манифест AWAITING_CONSENT, binding совпадает → исполняется");
{
  const store = makeStore();
  await store.createManifest({
    id: "m1", server: "gmail", tool: "gmail_send", accountLabel: "work",
    payload: PAYLOAD, objectHash: OBJHASH, createdAt: clock.t, expiresAt: clock.t + 3_600_000,
  });
  const result = await tryAutoExecute({ manifestId: "m1", tool: "gmail_send", accountLabel: "work" }, rehashOk, store, cfg);
  check("вернул результат (не null)", result !== null);
  check("payload — из манифеста", JSON.stringify(result?.payload) === JSON.stringify(PAYLOAD));
  check("auditId присвоен", typeof result?.auditId === "string" && result.auditId.length > 0);
  check("манифест помечен DONE (одноразовость)", store.manifests.get("m1").status === "DONE");
  check("аудит-запись создана с actor=tg_auto", store.audits[0]?.actor === "tg_auto");
  check("аудит-запись содержит честную метку вместо текста человека", store.audits[0]?.userReply === TG_AUTO_REPLY_MARKER);
  check("outcome=confirmed", store.audits[0]?.outcome === "confirmed");
}

console.log("\n[2] манифест не найден → null, ничего не падает");
{
  const store = makeStore();
  const result = await tryAutoExecute({ manifestId: "nope", tool: "gmail_send", accountLabel: "work" }, rehashOk, store, cfg);
  check("вернул null", result === null);
}

console.log("\n[3] tool/accountLabel не совпадают с манифестом → null (защита от подмены)");
{
  const store = makeStore();
  await store.createManifest({
    id: "m3", server: "gmail", tool: "gmail_send", accountLabel: "work",
    payload: PAYLOAD, objectHash: OBJHASH, createdAt: clock.t, expiresAt: clock.t + 3_600_000,
  });
  const wrongTool = await tryAutoExecute({ manifestId: "m3", tool: "gmail_reply", accountLabel: "work" }, rehashOk, store, cfg);
  check("другой tool → null", wrongTool === null);
  const wrongAccount = await tryAutoExecute({ manifestId: "m3", tool: "gmail_send", accountLabel: "personal" }, rehashOk, store, cfg);
  check("другой accountLabel → null", wrongAccount === null);
  check("манифест НЕ тронут (остался AWAITING_CONSENT)", store.manifests.get("m3").status === "AWAITING_CONSENT");
}

console.log("\n[4] уже исполнен (гонка/повторный тик поллера) → null, повторно не исполняется");
{
  const store = makeStore();
  await store.createManifest({
    id: "m4", server: "gmail", tool: "gmail_send", accountLabel: "work",
    payload: PAYLOAD, objectHash: OBJHASH, createdAt: clock.t, expiresAt: clock.t + 3_600_000,
  });
  const first = await tryAutoExecute({ manifestId: "m4", tool: "gmail_send", accountLabel: "work" }, rehashOk, store, cfg);
  check("первый вызов исполнился", first !== null);
  const second = await tryAutoExecute({ manifestId: "m4", tool: "gmail_send", accountLabel: "work" }, rehashOk, store, cfg);
  check("второй вызов (та же гонка) → null, письмо не улетит дважды", second === null);
  check("в аудите ровно одна запись", store.audits.length === 1);
}

console.log("\n[5] дрейф состояния (binding mismatch) → null, манифест НЕ инвалидируется молча");
{
  const store = makeStore();
  await store.createManifest({
    id: "m5", server: "gmail", tool: "gmail_send", accountLabel: "work",
    payload: PAYLOAD, objectHash: OBJHASH, createdAt: clock.t, expiresAt: clock.t + 3_600_000,
  });
  const result = await tryAutoExecute({ manifestId: "m5", tool: "gmail_send", accountLabel: "work" }, rehashDrift, store, cfg);
  check("дрейф → null", result === null);
  check(
    "манифест остался AWAITING_CONSENT (не инвалидирован тихо — обычный путь через модель ещё сможет явно доложить о дрейфе)",
    store.manifests.get("m5").status === "AWAITING_CONSENT",
  );
  check("аудит не тронут (гейт не логирует несостоявшуюся попытку авто-пути)", store.audits.length === 0);
}

console.log("\n[6] TTL истёк → null (тот же guard, что у обычного consumeManifest)");
{
  const store = makeStore();
  await store.createManifest({
    id: "m6", server: "gmail", tool: "gmail_send", accountLabel: "work",
    payload: PAYLOAD, objectHash: OBJHASH, createdAt: clock.t - 4_000_000, expiresAt: clock.t - 1_000,
  });
  const result = await tryAutoExecute({ manifestId: "m6", tool: "gmail_send", accountLabel: "work" }, rehashOk, store, cfg);
  check("истёкший TTL → null", result === null);
}

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
