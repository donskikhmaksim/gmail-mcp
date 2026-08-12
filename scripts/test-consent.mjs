#!/usr/bin/env node
/**
 * Offline unit-тест ядра consent-гейта (`src/consent.ts`). Чистая логика:
 * фейковый in-memory ConsentStore, инъекция часов — ни БД, ни сети.
 *
 * Запуск (Node ≥ 22.18 грузит .ts напрямую, tsx/build не нужны):
 *   node scripts/test-consent.mjs
 *
 * Покрывает все 6 проверок gate.md §3.3 по отдельности + фазу плана.
 */
import {
  requireConsent,
  classifyReply,
  canonicalJson,
  sha256,
} from "../src/consent.ts";

// ── фейковое хранилище + управляемые часы ───────────────────────────────────

const clock = { t: 1_700_000_000_000 }; // фиксированный старт (epoch ms)
const now = () => clock.t;

function makeStore() {
  const manifests = new Map();
  const audits = [];
  return {
    manifests,
    audits,
    async createManifest(input) {
      manifests.set(input.id, {
        ...input,
        status: "AWAITING_CONSENT",
        consumedAt: null,
        userReply: null,
      });
    },
    async getManifest(id, server) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      return { ...r };
    },
    async consumeManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      if (r.status !== "AWAITING_CONSENT") return null;
      if (clock.t >= r.expiresAt) return null; // TTL — как `expires_at > NOW()` в БД
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

const cfg = {
  server: "gmail",
  consentTtlMs: 3_600_000, // 1 ч
  minConsentGapMs: 5_000, // почта — 5 с (Q3)
  sendBatchMax: 10,
  now,
};

// payload и билдеры плана
const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Quote", body: "..." }] };
const OBJHASH = sha256(PAYLOAD);
const plan = () => ({
  payload: PAYLOAD,
  objectHash: OBJHASH,
  preview: "### 📤 План отправки\n\n- **Кому:** eric@x.com",
  batchSize: 1,
});
// СИМУЛЯЦИЯ «мир не изменился»: в тесте нет реального объекта для перечитывания,
// поэтому rehash отдаёт тот же хеш → binding проходит. В боевом A3 rehash ОБЯЗАН
// перечитать живое состояние по id и захешировать ЕГО (не аргумент) — см.
// контракт ConsentAddressing/rehash в consent.ts. Тест 9 моделирует ИЗМЕНЕНИЕ мира.
const rehash = (payload) => sha256(payload);

// ── харнесс проверок ────────────────────────────────────────────────────────

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

// helper: построить план и вернуть {store, manifestId}
async function buildPlan(overrides = {}) {
  const store = makeStore();
  const dec = await requireConsent({
    tool: "gmail_send",
    accountLabel: "work",
    plan,
    rehash,
    store,
    cfg,
    ...overrides,
  });
  return { store, dec };
}

// ── 0. хелперы canonicalJson / sha256 ───────────────────────────────────────
console.log("\n[0] canonicalJson / sha256 детерминизм");
check(
  "порядок ключей не влияет на canonicalJson",
  canonicalJson({ b: 1, a: { d: 4, c: 3 } }) === canonicalJson({ a: { c: 3, d: 4 }, b: 1 }),
);
check("sha256 стабилен для эквивалентных объектов", sha256({ x: 1, y: 2 }) === sha256({ y: 2, x: 1 }));
check("sha256 различает разные payload", sha256({ x: 1 }) !== sha256({ x: 2 }));

// ── 1. фаза плана ───────────────────────────────────────────────────────────
console.log("\n[1] фаза плана: planned, манифест создан, ничего не consumed");
{
  const { store, dec } = await buildPlan();
  check("kind=planned", dec.kind === "planned", JSON.stringify(dec).slice(0, 80));
  check("манифест создан", store.manifests.size === 1);
  check("статус AWAITING_CONSENT", [...store.manifests.values()][0].status === "AWAITING_CONSENT");
  check("превью несёт id плана", dec.kind === "planned" && dec.preview.includes(dec.manifestId));
  // До 2026-08-06 здесь проверялось наличие хвоста «[агенту: покажи это
  // пользователю дословно и дождись его ответа]» ВНУТРИ превью. Это была
  // инструкция модели, вшитая в данные; требование переехало в `description`
  // инструмента + `_meta` ответа. Теперь проверяем обратное.
  check("в превью НЕТ обращений к агенту", !/\[агенту:|дождись его ответа/i.test(dec.preview), dec.preview);
  check("превью помечает истечение в PT", dec.preview.includes("PT"));
  check("в фазе плана аудит-мутация не пишется", store.audits.length === 0);
}

// ── 2. только один из пары → refused «нужны оба» ────────────────────────────
console.log("\n[2] половина пары (только manifest_id или только user_reply) → 🛑");
{
  const store = makeStore();
  const d1 = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: "x", plan, rehash, store, cfg });
  check("только id → refused", d1.kind === "refused" && d1.result.includes("Нужны оба"), d1.result?.slice(0, 60));
  const d2 = await requireConsent({ tool: "gmail_send", accountLabel: "work", userReply: "да", plan, rehash, store, cfg });
  check("только reply → refused", d2.kind === "refused" && d2.result.includes("Нужны оба"));
  check("манифест НЕ создан", store.manifests.size === 0);
  check("🛑 в заголовке отказа", d1.result.includes("🛑"));
}

// ── 3. батч > капа → 🛑 без манифеста ───────────────────────────────────────
console.log("\n[3] батч больше SEND_BATCH_MAX → 🛑, манифест не создан");
{
  const store = makeStore();
  const bigPlan = () => ({ payload: PAYLOAD, objectHash: OBJHASH, preview: "p", batchSize: 11 });
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan: bigPlan, rehash, store, cfg });
  check("kind=refused", dec.kind === "refused");
  check("сообщение про разбивку", dec.result.includes("Разбей") || dec.result.includes("больше предела"), dec.result?.slice(0, 80));
  check("манифест НЕ создан", store.manifests.size === 0);
}

// ── 4. happy path: план → (пауза > gap) → «да» → confirmed ──────────────────
console.log("\n[4] полный путь: план → подтверждение «да» → confirmed, payload из манифеста");
{
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000; // прошло 6 с — анти-дуплет пройден
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да, отправляй", plan, rehash, store, cfg });
  check("kind=confirmed", dec.kind === "confirmed", JSON.stringify(dec).slice(0, 80));
  check("payload взят ИЗ манифеста", dec.kind === "confirmed" && canonicalJson(dec.payload) === canonicalJson(PAYLOAD));
  check("возвращён auditId", dec.kind === "confirmed" && typeof dec.auditId === "string");
  check("манифест теперь DONE", store.manifests.get(id).status === "DONE");
  check("аудит-строка confirmed записана", store.audits.some((a) => a.outcome === "confirmed"));
  check("user_reply в аудите дословно", store.audits.at(-1).userReply === "да, отправляй");
  check("аудит несёт результаты 6 проверок", store.audits.at(-1).checks.oneShot === "ok" && store.audits.at(-1).checks.binding === "ok");
}

// ── 5. анти-дуплет: план+execute в одном ходе → 🛑, манифест ЖИВ ─────────────
console.log("\n[5] план+execute в одном ходе (gap<5с) → 🛑, манифест остаётся живым");
{
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  // никакой паузы: то же значение часов
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg });
  check("kind=refused", dec.kind === "refused");
  check("сообщение про «слишком быстро»", dec.result.includes("Слишком быстро"), dec.result?.slice(0, 60));
  check("манифест НЕ consumed, всё ещё AWAITING", store.manifests.get(id).status === "AWAITING_CONSENT");
}

// ── 6. служебные строки → 🛑, манифест жив ──────────────────────────────────
console.log("\n[6] служебные user_reply (SEND 1 / JSON / uuid / id / имя инструмента) → 🛑");
for (const svc of ['SEND 1', '{"ok":true}', '550e8400-e29b-41d4-a716-446655440000', "MANIFEST_ID_SELF", "TOOL_SELF"]) {
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000;
  const reply = svc === "MANIFEST_ID_SELF" ? id : svc === "TOOL_SELF" ? "gmail_send" : svc;
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: reply, plan, rehash, store, cfg });
  check(`«${svc}» → refused (не ответ человека)`, dec.kind === "refused" && dec.result.includes("не ответ человека"), dec.result?.slice(0, 50));
  check(`«${svc}» — манифест жив`, store.manifests.get(id).status === "AWAITING_CONSENT");
}

// ── 7. отрицание → инвалидация; «нет, не отправляй» НЕ читается как «да» ─────
console.log("\n[7] отрицание инвалидирует манифест; «нет, не отправляй» ≠ утверждение");
{
  check("classifyReply(«нет, не отправляй») = negation", classifyReply("нет, не отправляй", { manifestId: "x", tool: "gmail_send" }) === "negation");
  check("classifyReply(«да, отправляй») = affirmation", classifyReply("да, отправляй", { manifestId: "x", tool: "gmail_send" }) === "affirmation");
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000;
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "нет, не отправляй", plan, rehash, store, cfg });
  check("kind=refused (отменено)", dec.kind === "refused" && dec.result.includes("Отменено"));
  check("манифест INVALIDATED", store.manifests.get(id).status === "INVALIDATED");
  check("аудит помечен invalidated", store.audits.at(-1).outcome === "invalidated");
  // повторное исполнение инвалидированного → отказ
  clock.t += 1_000;
  const dec2 = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg });
  check("инвалидированный не исполняется", dec2.kind === "refused");
}

// ── 8. неопределённый ответ → 🛑, манифест жив ──────────────────────────────
console.log("\n[8] ни да ни нет → 🛑, манифест жив");
{
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000;
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "наверное как-нибудь потом", plan, rehash, store, cfg });
  check("kind=refused (не понял)", dec.kind === "refused" && dec.result.includes("Не понял"), dec.result?.slice(0, 50));
  check("манифест жив", store.manifests.get(id).status === "AWAITING_CONSENT");
}

// ── 9. binding: состояние изменилось → 🛑, манифест не consumed ──────────────
console.log("\n[9] binding: rehash не совпал → 🛑, манифест не исполнен");
{
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000;
  const changedRehash = () => sha256({ changed: true }); // «получатель уехал»
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash: changedRehash, store, cfg });
  check("kind=refused (состояние изменилось)", dec.kind === "refused" && dec.result.includes("изменилось"));
  check("манифест НЕ consumed", store.manifests.get(id).status === "AWAITING_CONSENT");
}

// ── 10. одноразовость: второй execute → 🛑 ──────────────────────────────────
console.log("\n[10] одноразовость: повтор manifest_id после успеха → 🛑");
{
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000;
  const first = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg });
  check("первый — confirmed", first.kind === "confirmed");
  clock.t += 1_000;
  const second = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg });
  check("повтор — refused", second.kind === "refused");
}

// ── 11. TTL: исполнение после истечения → 🛑 ────────────────────────────────
console.log("\n[11] TTL: исполнение после expiresAt → 🛑");
{
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += cfg.consentTtlMs + 1_000; // за пределом TTL
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg });
  check("kind=refused (истёк)", dec.kind === "refused");
  check("манифест не DONE", store.manifests.get(id).status === "AWAITING_CONSENT");
}

// ── 12. сверка tool/account манифеста ───────────────────────────────────────
console.log("\n[12] чужой tool/account к манифесту → 🛑");
{
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000;
  const dWrongTool = await requireConsent({ tool: "gmail_forward", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg });
  check("другой tool → refused", dWrongTool.kind === "refused" && dWrongTool.result.includes("не найден"));
  const dWrongAcct = await requireConsent({ tool: "gmail_send", accountLabel: "personal", manifestId: id, userReply: "да", plan, rehash, store, cfg });
  check("другой account → refused", dWrongAcct.kind === "refused");
  check("манифест не тронут", store.manifests.get(id).status === "AWAITING_CONSENT");
}

// ── 13. classifyReply — батарея ─────────────────────────────────────────────
console.log("\n[13] classifyReply — словари RU+EN");
{
  const ctx = { manifestId: "mid", tool: "gmail_send" };
  const aff = ["да", "ок", "окей", "давай", "подтверждаю", "отправляй", "го", "+", "yes", "confirm", "send it", "go ahead"];
  const neg = ["нет", "стоп", "отмена", "погоди", "не надо", "no", "cancel", "stop", "don't", "do not"];
  const unk = ["наверное", "хм", "что там по срокам"];
  for (const s of aff) check(`aff: «${s}»`, classifyReply(s, ctx) === "affirmation", classifyReply(s, ctx));
  for (const s of neg) check(`neg: «${s}»`, classifyReply(s, ctx) === "negation", classifyReply(s, ctx));
  for (const s of unk) check(`unk: «${s}»`, classifyReply(s, ctx) === "unknown", classifyReply(s, ctx));
  check("пустая строка → unknown", classifyReply("   ", ctx) === "unknown");
}

// ── 14. регрессии приёмки: negation-конструкция vs ложная инвалидация ───────
console.log("\n[14] дыры приёмки №1/№2: «not sure» ≠ да; «отправляй, не тяни» ≠ отрицание");
{
  const ctx = { manifestId: "mid", tool: "gmail_send" };

  // №1 — дыра безопасности: «not X» больше НЕ читается как affirmation.
  for (const s of ["not sure", "not ok", "not really"]) {
    check(`«${s}» НЕ affirmation`, classifyReply(s, ctx) !== "affirmation", classifyReply(s, ctx));
  }
  // «not sure»/«not ok» — конструкция «частица+affirmation» → отрицание.
  check("«not sure» = negation", classifyReply("not sure", ctx) === "negation");
  check("«not ok» = negation", classifyReply("not ok", ctx) === "negation");
  // «not really» — частица без утвердительной головы → unknown (не да и не инвалидация).
  check("«not really» = unknown", classifyReply("not really", ctx) === "unknown");

  // «не <affirmation>» → отрицание.
  check("«не отправляй» = negation", classifyReply("не отправляй", ctx) === "negation");
  check("«не надо» = negation", classifyReply("не надо", ctx) === "negation");

  // №2 — ложная инвалидация: «не» перед НЕ-головой = согласие, а не отрицание.
  check("«отправляй, не тяни» = affirmation", classifyReply("отправляй, не тяни", ctx) === "affirmation");
  // «чего ждёшь, не томи» — согласие без явного aff-слова → хотя бы НЕ отрицание.
  check("«чего ждёшь, не томи» ≠ negation", classifyReply("чего ждёшь, не томи", ctx) !== "negation");
  // одиночная частица «не» сама по себе — НЕ отрицание.
  check("одиночное «не» = unknown", classifyReply("не", ctx) === "unknown");
}

// ── 15. интеграция: «not sure» не мутирует; «не тяни» не роняет манифест ─────
console.log("\n[15] интеграция: «not sure» → НЕ confirmed; «отправляй, не тяни» → confirmed, манифест жив до этого");
{
  // №1 боевой сценарий: раньше «not sure» → confirmed (мутация исполнялась). Теперь — refused.
  clock.t = 1_700_000_000_000;
  const { store, dec: planned } = await buildPlan();
  const id = planned.manifestId;
  clock.t += 6_000;
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "not sure", plan, rehash, store, cfg });
  check("«not sure» → НЕ confirmed", dec.kind !== "confirmed", dec.kind);
  check("«not sure» → refused", dec.kind === "refused");
  check("«not sure» манифест НЕ DONE", store.manifests.get(id).status !== "DONE");

  // №2 боевой сценарий: согласие с частицей «не» → confirmed, НЕ инвалидация.
  clock.t = 1_700_000_000_000;
  const p2 = await buildPlan();
  const id2 = p2.dec.manifestId;
  clock.t += 6_000;
  const dec2 = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id2, userReply: "отправляй, не тяни", plan, rehash, store: p2.store, cfg });
  check("«отправляй, не тяни» → confirmed", dec2.kind === "confirmed", dec2.kind);
  check("«отправляй, не тяни» манифест DONE, не INVALIDATED", p2.store.manifests.get(id2).status === "DONE");

  // одиночное «не» в реплике не инвалидирует манифест (unknown → refuse, план жив).
  clock.t = 1_700_000_000_000;
  const p3 = await buildPlan();
  const id3 = p3.dec.manifestId;
  clock.t += 6_000;
  const dec3 = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id3, userReply: "ну не знаю", plan, rehash, store: p3.store, cfg });
  check("«ну не знаю» → refused (не понял)", dec3.kind === "refused");
  check("«ну не знаю» манифест ЖИВ (AWAITING)", p3.store.manifests.get(id3).status === "AWAITING_CONSENT");
}

// ── 16. Часть 1 (docs/TZ_consent_web_hub.md): гибридное синхронное ожидание ──
console.log("\n[16] sync-wait: syncWaitMs=0 → поведение побайтово как раньше");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: { ...cfg, syncWaitMs: 0 } });
  check("kind=planned, ни одной задержки/доп.чтения", dec.kind === "planned");
  check("манифест создан ровно один раз", store.manifests.size === 1);
}

console.log("\n[16] sync-wait: syncWaitMs не задан (undefined) → тоже выключено");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg });
  check("kind=planned", dec.kind === "planned");
}

console.log("\n[16.2] sync-wait: подтверждено «человеком» в середине окна → готовый положительный ответ с первого вызова, БЕЗ повторного исполнения");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const syncCfg = { ...cfg, syncWaitMs: 5_000, syncPollMs: 1_000 };
  let polls = 0;
  const realGetManifest = store.getManifest.bind(store);
  store.getManifest = async (id, server) => {
    polls++;
    // На 2-й итерации опроса симулируем внешнее подтверждение И исполнение
    // (веб-хаб decide-confirm вызвал tryAutoExecute — реальная мутация уже
    // произошла ТАМ, здесь симулируется атомарным consumeManifest).
    if (polls === 2) {
      await store.consumeManifest(id, server, "[веб-хаб: подтверждено]");
    }
    return realGetManifest(id, server);
  };
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });
  // ИСПРАВЛЕНО (был баг двойного исполнения): наблюдение чужого DONE не
  // может вернуть kind=confirmed — тул тогда исполнил бы мутацию ВТОРОЙ раз
  // поверх уже исполненной веб-хабом. Безопасный контракт — та же форма,
  // что у обычного отказа, с позитивным текстом внутри (см. consent.ts,
  // комментарий "ИСПРАВЛЕНО" рядом с обработкой row.status === "DONE").
  check("kind=refused (безопасная форма — тул не исполнит payload повторно)", dec.kind === "refused", JSON.stringify(dec).slice(0, 100));
  check("текст сообщает про подтверждено и исполнено", dec.result.includes("одтвержд") && dec.result.includes("исполнен"), dec.result.slice(0, 100));
  check("манифест реально DONE (исполнил веб-хаб, не requireConsent)", [...store.manifests.values()][0].status === "DONE");
  check("опрошено больше одного раза (не сразу таймаут)", polls >= 2, polls);
}

console.log("\n[16.3] sync-wait: отклонено в окне → refused, мутации нет");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const syncCfg = { ...cfg, syncWaitMs: 5_000, syncPollMs: 1_000 };
  let polls = 0;
  const realGetManifest = store.getManifest.bind(store);
  store.getManifest = async (id, server) => {
    polls++;
    if (polls === 2) await store.invalidateManifest(id, server, "нет, не то письмо");
    return realGetManifest(id, server);
  };
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });
  check("kind=refused", dec.kind === "refused", JSON.stringify(dec).slice(0, 100));
  check("манифест INVALIDATED, не DONE", [...store.manifests.values()][0].status === "INVALIDATED");
}

console.log("\n[16.4] sync-wait: никто ничего не сделал за окно → обычное planned; второй вызов id+reply по-прежнему работает");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const syncCfg = { ...cfg, syncWaitMs: 2_500, syncPollMs: 1_000 };
  // Мок-часы не текут сами по себе (`now` читает `clock.t`, реальный
  // `sleep()` внутри опроса на них не влияет) — двигаем `clock.t` на
  // `syncPollMs` при каждом опросе, как если бы время шло синхронно со сном,
  // чтобы дедлайн окна реально наступил и цикл не завис.
  const realGetManifest = store.getManifest.bind(store);
  store.getManifest = async (id, server) => {
    clock.t += syncCfg.syncPollMs;
    return realGetManifest(id, server);
  };
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });
  check("kind=planned (таймаут окна)", dec.kind === "planned", JSON.stringify(dec).slice(0, 100));
  check("манифест всё ещё AWAITING_CONSENT", [...store.manifests.values()][0].status === "AWAITING_CONSENT");
  // Регресс: обычный второй вызов с manifest_id+user_reply исполняет как раньше.
  store.getManifest = realGetManifest;
  const id = dec.manifestId;
  clock.t += cfg.minConsentGapMs + 1_000;
  const dec2 = await requireConsent({ tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg: syncCfg });
  check("второй вызов confirmed (регресс не сломан)", dec2.kind === "confirmed", dec2.kind);
}

console.log("\n[16.5] sync-wait + binding: currentHash≠objectHash на sync-пути → отказ, не тихое исполнение");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const syncCfg = { ...cfg, syncWaitMs: 5_000, syncPollMs: 1_000 };
  let polls = 0;
  const realGetManifest = store.getManifest.bind(store);
  store.getManifest = async (id, server) => {
    polls++;
    if (polls === 2) await store.consumeManifest(id, server, "[веб-хаб: подтверждено]");
    return realGetManifest(id, server);
  };
  const changedRehash = () => sha256({ changed: true });
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash: changedRehash, store, cfg: syncCfg });
  check("kind=refused (состояние изменилось)", dec.kind === "refused" && dec.result.includes("изменилось"), JSON.stringify(dec).slice(0, 100));
}

console.log("\n[16.6] automation_key + sync одновременно: валидный ключ исполняет СРАЗУ, ни одной итерации опроса");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const syncCfg = { ...cfg, syncWaitMs: 25_000, syncPollMs: 1_000 };
  let getManifestCalls = 0;
  const realGetManifest = store.getManifest.bind(store);
  store.getManifest = async (...args) => {
    getManifestCalls++;
    return realGetManifest(...args);
  };
  const checkAutomationKey = async () => ({ ok: true, channel: "window" });
  const dec = await requireConsent({
    tool: "gmail_send",
    accountLabel: "work",
    plan,
    rehash,
    store,
    cfg: syncCfg,
    automationKey: "valid-key",
    checkAutomationKey,
  });
  check("kind=confirmed немедленно (automation_key)", dec.kind === "confirmed", dec.kind);
  check("manifestId пуст (automation_key-путь не создаёт манифест)", dec.kind === "confirmed" && dec.manifestId === "");
  check("getManifest НИ РАЗУ не вызван (до опроса дело не дошло)", getManifestCalls === 0, getManifestCalls);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
