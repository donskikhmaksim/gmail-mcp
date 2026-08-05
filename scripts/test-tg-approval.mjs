#!/usr/bin/env node
/**
 * Offline unit-тест опционального Telegram-approval слоя
 * (`src/tg_approval.ts` + его врезка в `src/consent.ts`). Никакого реального
 * Telegram и никакой БД — Telegram Bot API замокан через undici's MockAgent
 * (тот же HTTP-клиент, что использует сам модуль в проде — см. doc-comment
 * `tg_approval.ts`), store — in-memory Map с тем же атомарным контрактом,
 * что `store.ts`.
 *
 * Запуск: node scripts/test-tg-approval.mjs
 */
import { MockAgent, setGlobalDispatcher } from "undici";
import { requireConsent, sha256 } from "../src/consent.ts";
import { createTgApprovalGate, handleWebhook, registerWebhook, runApprovalSweep, secretTokenMatches } from "../src/tg_approval.ts";

// ── управляемые часы (как в test-consent.mjs) ───────────────────────────────
const clock = { t: 1_700_000_000_000 };
const now = () => clock.t;

const BOT_TOKEN = "TESTTOKEN";
let tgCalls = []; // { method, body } — для проверки "сколько раз/что вызвано"

/**
 * Свежий MockAgent на каждый вызов (а не общий на весь файл) — иначе
 * персистентные перехватчики из ОДНОГО раздела теста заслоняли бы перехватчики
 * следующего раздела на том же пути (sendMessage у обоих), потому что
 * `undici` матчит перехватчики в порядке регистрации, и `persist()` не даёт
 * более раннему исчезнуть. `setGlobalDispatcher` — задокументированный
 * undici-способ подменить транспорт для его же `fetch` (тот же клиент, что
 * `tg_approval.ts` использует в проде), без похода в реальную сеть
 * (`disableNetConnect()` бросает, если что-то не замокано).
 */
function resetTelegramMocks() {
  tgCalls = [];
  const agent = new MockAgent();
  agent.disableNetConnect();
  setGlobalDispatcher(agent);
  const pool = agent.get("https://api.telegram.org");
  return {
    mock(method, respond) {
      pool
        .intercept({ path: `/bot${BOT_TOKEN}/${method}`, method: "POST" })
        .reply((opts) => {
          const body = JSON.parse(opts.body);
          tgCalls.push({ method, body });
          return respond(body);
        })
        .persist();
    },
  };
}

// ── in-memory ConsentStore (как test-consent.mjs) ───────────────────────────
function makeConsentStore() {
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
    async updateConsentAuditOutcome(auditId, outcome) {
      const a = audits.find((x) => x.id === auditId);
      if (a) Object.assign(a, outcome);
    },
  };
}

// ── in-memory TgApprovalStore — тот же атомарный контракт, что store.ts ────
function makeTgStore() {
  const approvals = new Map();
  return {
    approvals,
    async createTgApproval(input) {
      approvals.set(input.manifestId, { ...input, status: "PENDING", decidedAt: null });
    },
    async getTgApproval(manifestId, server) {
      const r = approvals.get(manifestId);
      if (!r || r.server !== server) return null;
      return { ...r };
    },
    async consumeTgDecision(manifestId, server, status) {
      const r = approvals.get(manifestId);
      if (!r || r.server !== server || r.status !== "PENDING") return null; // атомарный one-shot
      if (clock.t >= r.expiresAt) return null; // TTL-guard — зеркалит store.ts's `expires_at > $now`
      r.status = status;
      r.decidedAt = clock.t;
      return { ...r };
    },
    // Server-agnostic сиблинг — реальный путь `handleWebhook` после фикса
    // "один бот на 6 серверов" (store.ts's `consumeTgDecisionAnyServer`):
    // НЕ фильтрует по server, потому что manifest_id — PRIMARY KEY (глобально
    // уникален), а вебхук физически не знает заранее, какому серверу
    // принадлежит нажатая кнопка.
    async consumeTgDecisionAnyServer(manifestId, status) {
      const r = approvals.get(manifestId);
      if (!r || r.status !== "PENDING") return null; // атомарный one-shot, БЕЗ фильтра по server
      if (clock.t >= r.expiresAt) return null; // TTL-guard — зеркалит store.ts's `expires_at > $now`
      r.status = status;
      r.decidedAt = clock.t;
      return { ...r };
    },
    async claimExpiredPendingApprovals(nowMs, limit = 50) {
      const out = [];
      for (const [id, r] of approvals) {
        if (r.status === "PENDING" && r.expiresAt <= nowMs) {
          r.status = "EXPIRED";
          out.push({ manifestId: id, chatId: r.chatId, messageId: r.messageId });
          if (out.length >= limit) break;
        }
      }
      return out;
    },
    async claimStaleDecidedApprovals(nowMs, limit = 50) {
      const out = [];
      for (const [id, r] of approvals) {
        if ((r.status === "APPROVED" || r.status === "REJECTED") && r.expiresAt <= nowMs) {
          out.push({ manifestId: id, chatId: r.chatId, messageId: r.messageId });
          if (out.length >= limit) break;
        }
      }
      for (const row of out) approvals.delete(row.manifestId);
      return out;
    },
  };
}

const consentCfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now };

const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Quote", body: "..." }] };
const OBJHASH = sha256(PAYLOAD);
const plan = () => ({
  payload: PAYLOAD,
  objectHash: OBJHASH,
  preview: "### 📤 План отправки\n\n- **Кому:** eric@x.com",
  batchSize: 1,
});
const rehash = (payload) => sha256(payload);

function tgCfg(overrides = {}) {
  return {
    enabled: true,
    botToken: BOT_TOKEN,
    ownerChatId: "555",
    webhookSecret: "wh-secret-xyz",
    publicBaseUrl: "https://example.test",
    server: "gmail",
    toolsAllowlist: null,
    ttlMs: 3_600_000,
    webhookOwner: false, // TG_WEBHOOK_OWNER default — most tests don't touch registerWebhook at all
    ...overrides,
  };
}

// ── харнесс ──────────────────────────────────────────────────────────────
let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

// ═══ [1] фича OFF (или tg вовсе не передан) — гейт побайтово как раньше ═══
console.log("\n[1] TG_APPROVAL выключен → requireConsent ведёт себя как без tg вовсе");
{
  const gate = createTgApprovalGate(tgCfg({ enabled: false }), makeTgStore(), now);
  check("enabledFor() всегда false, когда enabled=false", !gate.enabledFor("gmail_send"));

  const storeA = makeConsentStore();
  const decA = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store: storeA, cfg: consentCfg });

  const storeB = makeConsentStore();
  const decB = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store: storeB, cfg: consentCfg, tg: gate });

  check("kind совпадает (planned) без tg и с выключенным tg", decA.kind === "planned" && decB.kind === "planned");
  // Сравниваем ИГНОРИРУЯ manifest_id (он всегда разный — свежий randomUUID на
  // каждый план) — сама структура/текст превью обязана совпасть один в один.
  const stripId = (s) => s.replace(/`[0-9a-f-]{36}`/, "`<id>`");
  check(
    "превью идентично — выключенный tg не добавляет ТГ-строку",
    stripId(decA.preview) === stripId(decB.preview),
    `A=${decA.preview}\nB=${decB.preview}`,
  );
  check("никакого обращения к Telegram не было", tgCalls.length === 0);

  clock.t += 6_000; // анти-дуплет (2): план и execute обязаны разойтись по времени
  // Полный цикл execute тоже не должен отличаться.
  const decAExec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: decA.manifestId, userReply: "да",
    plan, rehash, store: storeA, cfg: consentCfg,
  });
  const decBExec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: decB.manifestId, userReply: "да",
    plan, rehash, store: storeB, cfg: consentCfg, tg: gate,
  });
  check("execute: оба confirmed", decAExec.kind === "confirmed" && decBExec.kind === "confirmed");
  check("execute: без обращения к Telegram (enabledFor=false)", tgCalls.length === 0);
}

// ═══ [2] fail-closed: отправка в Telegram упала на фазе плана ═══
console.log("\n[2] fail-closed: sendMessage упал → манифест НЕ остаётся живым, refused");
{
  const { mock } = resetTelegramMocks();
  mock("sendMessage", () => ({ statusCode: 200, data: { ok: false, description: "Bad Request: chat not found" }, headers: { "content-type": "application/json" } }));

  const tgStore = makeTgStore();
  const gate = createTgApprovalGate(tgCfg(), tgStore, now);
  const consentStore = makeConsentStore();

  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store: consentStore, cfg: consentCfg, tg: gate });

  check("kind=refused", dec.kind === "refused", JSON.stringify(dec).slice(0, 120));
  check("текст объясняет, что ТГ недоступен, действие не выполнено", /Telegram/i.test(dec.result) && /не выполнено/i.test(dec.result));
  const row = [...consentStore.manifests.values()][0];
  check("манифест создан, но сразу INVALIDATED (не остался живым для голого user_reply)", row && row.status === "INVALIDATED", JSON.stringify(row));
  check("tg_approvals ничего не создал (send упал раньше store.createTgApproval)", tgStore.approvals.size === 0);
  check("sendMessage реально вызывался", tgCalls.some((c) => c.method === "sendMessage"));
}

// ═══ [3] happy path плана: sendMessage ок → PENDING-строка, ТГ-подсказка в превью ═══
console.log("\n[3] план: sendMessage ок → planned, tg_approvals PENDING, превью просит и кнопку, и «да»");
let planCtx; // переиспользуем в [4]/[5]/[6]/[7]
{
  const { mock } = resetTelegramMocks();
  mock("sendMessage", () => ({ statusCode: 200, data: { ok: true, result: { message_id: 4242 } }, headers: { "content-type": "application/json" } }));

  const tgStore = makeTgStore();
  const gate = createTgApprovalGate(tgCfg(), tgStore, now);
  const consentStore = makeConsentStore();

  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store: consentStore, cfg: consentCfg, tg: gate });

  check("kind=planned", dec.kind === "planned");
  check("превью упоминает Telegram И «да» здесь", /Telegram/.test(dec.preview) && /да/.test(dec.preview));
  const row = tgStore.approvals.get(dec.manifestId);
  check("tg_approvals содержит PENDING-строку с этим manifestId", !!row && row.status === "PENDING");
  check("message_id из ответа Telegram сохранён", row.messageId === 4242);
  planCtx = { dec, consentStore, tgStore, gate };
}

// ═══ [4] execute + PENDING (кнопку не нажали) → refused «жду кнопку», манифест жив ═══
console.log("\n[4] execute при PENDING в Telegram → refused «жду подтверждения», манифест ЖИВ");
{
  const { dec, consentStore, gate } = planCtx;
  clock.t += 6_000; // анти-дуплет (2) — иначе даже правильный отказ был бы "слишком быстро", не "жду кнопку"
  const exec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: dec.manifestId, userReply: "да",
    plan, rehash, store: consentStore, cfg: consentCfg, tg: gate,
  });
  check("kind=refused", exec.kind === "refused", JSON.stringify(exec).slice(0, 120));
  check("текст просит нажать кнопку в Telegram", /Telegram/.test(exec.result) || /кноп/i.test(exec.result));
  const row = consentStore.manifests.get(dec.manifestId);
  check("манифест всё ещё AWAITING_CONSENT (не consumed)", row.status === "AWAITING_CONSENT");
}

// ═══ [5] APPROVED (через тот же путь, что и webhook — consumeTgDecisionAnyServer) → execute проходит ═══
console.log("\n[5] APPROVED в Telegram + «да» в чате → confirmed");
{
  const { dec, consentStore, tgStore, gate } = planCtx;
  const consumed = await tgStore.consumeTgDecisionAnyServer(dec.manifestId, "APPROVED");
  check("consumeTgDecisionAnyServer(APPROVED) сработал", !!consumed && consumed.status === "APPROVED");

  const exec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: dec.manifestId, userReply: "да",
    plan, rehash, store: consentStore, cfg: consentCfg, tg: gate,
  });
  check("kind=confirmed", exec.kind === "confirmed", JSON.stringify(exec).slice(0, 120));
  check("payload взят из манифеста", JSON.stringify(exec.payload) === JSON.stringify(PAYLOAD));
  const row = consentStore.manifests.get(dec.manifestId);
  check("манифест теперь DONE", row.status === "DONE");
}

// ═══ [6] REJECTED в Telegram → invalidate, refused, ничего не отправлено ═══
console.log("\n[6] REJECTED в Telegram → манифест INVALIDATED, refused «отклонено»");
{
  const { mock } = resetTelegramMocks();
  mock("sendMessage", () => ({ statusCode: 200, data: { ok: true, result: { message_id: 7 } }, headers: { "content-type": "application/json" } }));
  const tgStore = makeTgStore();
  const gate = createTgApprovalGate(tgCfg(), tgStore, now);
  const consentStore = makeConsentStore();

  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store: consentStore, cfg: consentCfg, tg: gate });
  await tgStore.consumeTgDecisionAnyServer(dec.manifestId, "REJECTED");
  clock.t += 6_000; // анти-дуплет (2)

  const exec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: dec.manifestId, userReply: "да",
    plan, rehash, store: consentStore, cfg: consentCfg, tg: gate,
  });
  check("kind=refused", exec.kind === "refused");
  check("текст упоминает отклонение в Telegram", /Отклонено в Telegram|отклон/i.test(exec.result));
  const row = consentStore.manifests.get(dec.manifestId);
  check("манифест INVALIDATED", row.status === "INVALIDATED");
}

// ═══ [7] TTL истёк (кнопку не нажали вовремя) → refuse «истёк» ═══
console.log("\n[7] TTL approval-запроса истёк → checkApproval='none' → refused «истёк»");
{
  const { mock } = resetTelegramMocks();
  mock("sendMessage", () => ({ statusCode: 200, data: { ok: true, result: { message_id: 9 } }, headers: { "content-type": "application/json" } }));
  const tgStore = makeTgStore();
  const shortCfg = tgCfg({ ttlMs: 1_000 });
  const gate = createTgApprovalGate(shortCfg, tgStore, now);
  const consentStore = makeConsentStore();

  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store: consentStore, cfg: consentCfg, tg: gate });
  check("approval ещё pending сразу после плана", (await gate.checkApproval(dec.manifestId)) === "pending");

  clock.t += consentCfg.minConsentGapMs + 2_000; // прошли анти-дуплет-зазор И approval TTL (1с)

  const exec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: dec.manifestId, userReply: "да",
    plan, rehash, store: consentStore, cfg: consentCfg, tg: gate,
  });
  check("kind=refused", exec.kind === "refused");
  check("текст упоминает истечение", /истёк/i.test(exec.result));
  clock.t = 1_700_000_000_000; // откатываем общие часы для следующих секций
}

// ═══ [7b] TTL-guard в consumeTgDecisionAnyServer: кнопка нажата ПОСЛЕ истечения ═══
// approval-TTL, но пока consent-манифест ещё жив (окно из приёмки: approval-
// TTL короче consent-TTL) → webhook-путь не должен записать решение вообще.
console.log("\n[7b] кнопка нажата после истечения approval-TTL (манифест ещё жив) → решение НЕ записывается");
{
  const { mock } = resetTelegramMocks();
  mock("sendMessage", () => ({ statusCode: 200, data: { ok: true, result: { message_id: 11 } }, headers: { "content-type": "application/json" } }));
  mock("answerCallbackQuery", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));
  mock("editMessageReplyMarkup", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));

  // approval-TTL (1с) короче consent-TTL (1ч) — ровно окно из приёмки.
  const shortCfg = tgCfg({ ttlMs: 1_000 });
  const tgStore = makeTgStore();
  const gate = createTgApprovalGate(shortCfg, tgStore, now);
  const consentStore = makeConsentStore();

  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store: consentStore, cfg: consentCfg, tg: gate });
  const rowBefore = tgStore.approvals.get(dec.manifestId);
  check("approval-строка создана, PENDING", !!rowBefore && rowBefore.status === "PENDING");

  // прошли и анти-дуплет-зазор (иначе execute отказал бы раньше по check (2),
  // не дойдя до tg-ветки), и approval-TTL (1с) — но НЕ consent-манифест (1ч).
  clock.t += consentCfg.minConsentGapMs + 2_000;

  const update = {
    callback_query: {
      id: "cbq-7b",
      from: { id: Number(shortCfg.ownerChatId) },
      data: `a:${dec.manifestId}`,
      message: { message_id: 11, chat: { id: shortCfg.ownerChatId } },
    },
  };
  await handleWebhook(shortCfg, tgStore, update);

  const rowAfter = tgStore.approvals.get(dec.manifestId);
  check(
    "webhook НЕ перевёл строку в APPROVED — осталась PENDING (TTL-guard в consumeTgDecisionAnyServer)",
    rowAfter.status === "PENDING",
    JSON.stringify(rowAfter),
  );
  check("decidedAt не проставлен", rowAfter.decidedAt === null);
  check(
    "editMessageReplyMarkup НЕ вызван — consumed=null, кнопки снимать нечего",
    tgCalls.filter((c) => c.method === "editMessageReplyMarkup").length === 0,
  );
  check(
    "answerCallbackQuery всё же вызван (спиннер гасится «уже обработано»)",
    tgCalls.filter((c) => c.method === "answerCallbackQuery").length === 1,
  );

  // execute остаётся refuse — манифест не должен исполниться по протухшей кнопке.
  const exec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: dec.manifestId, userReply: "да",
    plan, rehash, store: consentStore, cfg: consentCfg, tg: gate,
  });
  check("execute: kind=refused (протухшая кнопка не исполняет план)", exec.kind === "refused", JSON.stringify(exec).slice(0, 160));
  const manifestRow = consentStore.manifests.get(dec.manifestId);
  check("consent-манифест НЕ стал DONE", manifestRow.status !== "DONE", JSON.stringify(manifestRow));

  clock.t = 1_700_000_000_000; // откатываем общие часы для следующих секций
}

// ═══ [8] webhook: неверный secret_token → отказ ═══
console.log("\n[8] webhook secret_token: неверный → secretTokenMatches=false");
{
  check("верный секрет матчится", secretTokenMatches("wh-secret-xyz", "wh-secret-xyz"));
  check("неверный секрет НЕ матчится", !secretTokenMatches("wrong", "wh-secret-xyz"));
  check("пустой предоставленный секрет НЕ матчится", !secretTokenMatches("", "wh-secret-xyz"));
  check("пустой ожидаемый секрет (фича не настроена) НЕ матчится ни с чем", !secretTokenMatches("anything", ""));
}

// ═══ [9] webhook: чужой from.id → игнор, store не тронут ═══
console.log("\n[9] webhook: callback от НЕ владельца → игнорируется, approval не меняется");
{
  const { mock } = resetTelegramMocks();
  mock("answerCallbackQuery", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));
  mock("editMessageReplyMarkup", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));

  const cfg = tgCfg();
  const tgStore = makeTgStore();
  await tgStore.createTgApproval({ manifestId: "m-owner-check", server: "gmail", chatId: cfg.ownerChatId, messageId: 1, createdAt: now(), expiresAt: now() + 3_600_000 });

  const update = {
    callback_query: {
      id: "cbq-1",
      from: { id: 999999 }, // НЕ ownerChatId (555)
      data: "a:m-owner-check",
      message: { message_id: 1, chat: { id: cfg.ownerChatId } },
    },
  };
  await handleWebhook(cfg, tgStore, update);

  const row = tgStore.approvals.get("m-owner-check");
  check("approval остался PENDING — чужой from.id не смог его решить", row.status === "PENDING");
  check("Telegram НЕ вызывался (ни answer, ни editMarkup) для чужого from.id", tgCalls.length === 0);
}

// ═══ [10] webhook: replay того же callback → второй раз не проходит ═══
console.log("\n[10] webhook: повторный (replay) callback того же решения — второй раз no-op");
{
  const { mock } = resetTelegramMocks();
  mock("answerCallbackQuery", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));
  mock("editMessageReplyMarkup", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));

  const cfg = tgCfg();
  const tgStore = makeTgStore();
  await tgStore.createTgApproval({ manifestId: "m-replay", server: "gmail", chatId: cfg.ownerChatId, messageId: 2, createdAt: now(), expiresAt: now() + 3_600_000 });

  const update = {
    callback_query: {
      id: "cbq-2",
      from: { id: Number(cfg.ownerChatId) },
      data: "a:m-replay",
      message: { message_id: 2, chat: { id: cfg.ownerChatId } },
    },
  };

  await handleWebhook(cfg, tgStore, update); // первый раз — реальное решение
  check("после первого вызова — APPROVED", tgStore.approvals.get("m-replay").status === "APPROVED");
  check("editMessageReplyMarkup вызван один раз (кнопки сняты)", tgCalls.filter((c) => c.method === "editMessageReplyMarkup").length === 1);

  const answersAfterFirst = tgCalls.filter((c) => c.method === "answerCallbackQuery").length;

  await handleWebhook(cfg, tgStore, update); // replay того же update
  check("статус НЕ изменился повторным вызовом (остался APPROVED)", tgStore.approvals.get("m-replay").status === "APPROVED");
  check("editMessageReplyMarkup НЕ вызван повторно (consumed=null на втором разе)", tgCalls.filter((c) => c.method === "editMessageReplyMarkup").length === 1);
  check("answerCallbackQuery всё же вызван второй раз (гасим часики), но решение не поменял", tgCalls.filter((c) => c.method === "answerCallbackQuery").length === answersAfterFirst + 1);

  // Попытка "перевернуть" решение replay'ем противоположной кнопки — тоже no-op.
  const flipUpdate = { ...update, callback_query: { ...update.callback_query, id: "cbq-3", data: "r:m-replay" } };
  await handleWebhook(cfg, tgStore, flipUpdate);
  check("REJECT-реплей после APPROVED не может перевернуть решение", tgStore.approvals.get("m-replay").status === "APPROVED");
}

// ═══ [11] webhook: игнорирует всё, что не callback_query ═══
console.log("\n[11] webhook: обновление без callback_query — игнорируется без ошибки");
{
  const { mock } = resetTelegramMocks();
  const cfg = tgCfg();
  const tgStore = makeTgStore();
  await handleWebhook(cfg, tgStore, { update_id: 1, message: { text: "hi" } });
  check("никакого обращения к Telegram", tgCalls.length === 0);
}

// ═══ [12] один бот на 6 серверов: вебхук консюмит манифест ЧУЖОГО сервера ═══
// Регрессионный тест на сам фикс: cfg этого процесса — "gmail" (webhook
// физически задеплоен на gmail-mcp), а approval-строка в БД принадлежит
// "calendar" (создана ДРУГИМ сервером через тот же общий бот-токен). Со
// старым фильтром `AND server = cfg.server` в `consumeTgDecision` это был бы
// 0-rows silent miss — approval "calendar" навсегда застревал бы в PENDING.
// После фикса (`consumeTgDecisionAnyServer`, БЕЗ фильтра по server) вебхук
// обязан консюмить его корректно именно потому, что manifest_id — глобально
// уникальный PRIMARY KEY, а не потому, что сервера совпали.
console.log("\n[12] вебхук на gmail консюмит approval манифеста, принадлежащего server=calendar");
{
  const { mock } = resetTelegramMocks();
  mock("answerCallbackQuery", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));
  mock("editMessageReplyMarkup", () => ({ statusCode: 200, data: { ok: true }, headers: { "content-type": "application/json" } }));

  // cfg.server = "gmail" (этот процесс), но approval-строка принадлежит "calendar".
  const cfg = tgCfg({ server: "gmail" });
  const tgStore = makeTgStore();
  await tgStore.createTgApproval({
    manifestId: "m-cross-server",
    server: "calendar", // ЧУЖОЙ сервер, не cfg.server
    chatId: cfg.ownerChatId,
    messageId: 55,
    createdAt: now(),
    expiresAt: now() + 3_600_000,
  });

  // Контрольная проверка регрессии: старый server-scoped `consumeTgDecision`
  // с cfg.server="gmail" против строки server="calendar" — 0 rows, silent miss.
  const oldPathMiss = await tgStore.consumeTgDecision("m-cross-server", cfg.server, "APPROVED");
  check(
    "контроль: старый server-scoped путь ДЕЙСТВИТЕЛЬНО падал бы тут (0 rows) — подтверждает, что баг был реальным",
    oldPathMiss === null,
  );
  check("approval всё ещё PENDING после неудачной старой попытки", tgStore.approvals.get("m-cross-server").status === "PENDING");

  const update = {
    callback_query: {
      id: "cbq-cross-server",
      from: { id: Number(cfg.ownerChatId) },
      data: `a:m-cross-server`,
      message: { message_id: 55, chat: { id: cfg.ownerChatId } },
    },
  };
  await handleWebhook(cfg, tgStore, update);

  const row = tgStore.approvals.get("m-cross-server");
  check(
    "новый server-agnostic путь: вебхук на gmail консюмит APPROVED для манифеста server=calendar",
    row.status === "APPROVED",
    JSON.stringify(row),
  );
  check("decidedAt проставлен", row.decidedAt === clock.t);
  check("editMessageReplyMarkup вызван — кнопки сняты", tgCalls.some((c) => c.method === "editMessageReplyMarkup"));
  check(
    "answerCallbackQuery отвечает «Подтверждено», а не «Уже обработано»",
    tgCalls.some((c) => c.method === "answerCallbackQuery" && c.body.text === "Подтверждено"),
  );

  // REJECTED-ветка тем же способом, другой манифест чужого сервера ("docs").
  await tgStore.createTgApproval({
    manifestId: "m-cross-server-2",
    server: "docs",
    chatId: cfg.ownerChatId,
    messageId: 56,
    createdAt: now(),
    expiresAt: now() + 3_600_000,
  });
  await handleWebhook(cfg, tgStore, {
    callback_query: {
      id: "cbq-cross-server-2",
      from: { id: Number(cfg.ownerChatId) },
      data: `r:m-cross-server-2`,
      message: { message_id: 56, chat: { id: cfg.ownerChatId } },
    },
  });
  check(
    "REJECTED тоже консюмится через чужой сервер (docs)",
    tgStore.approvals.get("m-cross-server-2").status === "REJECTED",
  );
}

// ═══ [13] registerWebhook: guard TG_WEBHOOK_OWNER ═══
// Один бот-токен на 6 серверов означает, что setWebhook ДОЛЖЕН вызвать
// РОВНО один из них. Без TG_WEBHOOK_OWNER=true (дефолт) registerWebhook
// обязан быть no-op — иначе второй сервер, получивший этот же код при
// переносе (gmail-mcp -> sheets/calendar/docs/drive/ticktick-mcp), молча
// перезапишет чужой вебхук просто потому, что у него тоже включён
// TG_APPROVAL_ENABLED.
console.log("\n[13] registerWebhook: TG_WEBHOOK_OWNER не установлен/false → setWebhook НЕ вызывается");
{
  const { mock } = resetTelegramMocks();
  // Если бы registerWebhook всё-таки дошёл до сети, setWebhook ответил бы ok —
  // тест обязан провалиться на отсутствии самого вызова, а не на его результате.
  mock("setWebhook", () => ({ statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } }));

  // (a) enabled=true, webhookOwner не задан (false по умолчанию через tgCfg()).
  await registerWebhook(tgCfg({ enabled: true }));
  check("webhookOwner отсутствует/false → setWebhook НЕ вызван", tgCalls.filter((c) => c.method === "setWebhook").length === 0);

  // (b) enabled=true, webhookOwner ЯВНО false.
  await registerWebhook(tgCfg({ enabled: true, webhookOwner: false }));
  check("webhookOwner=false явно → setWebhook по-прежнему НЕ вызван", tgCalls.filter((c) => c.method === "setWebhook").length === 0);

  // (c) контрольная проверка: с webhookOwner=true (и enabled=true) вызов ДОЛЖЕН пройти —
  // подтверждает, что guard не сломал сам happy-path, а именно гейтит его.
  await registerWebhook(tgCfg({ enabled: true, webhookOwner: true }));
  check("webhookOwner=true → setWebhook ВЫЗВАН ровно один раз", tgCalls.filter((c) => c.method === "setWebhook").length === 1);
}

// [14] runApprovalSweep: снимает кнопку у просроченных PENDING, удаляет
// сообщение у решённых старше TTL — Максим, 2026-08-05.
console.log("\n[14] runApprovalSweep — чистка чата бота");
{
  const { mock } = resetTelegramMocks();
  mock("editMessageReplyMarkup", () => ({ statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } }));
  mock("deleteMessage", () => ({ statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } }));

  const store = makeTgStore();
  // PENDING, TTL уже прошёл — кандидат класса 1.
  store.approvals.set("expired-1", { manifestId: "expired-1", server: "gmail", chatId: "555", messageId: 111, status: "PENDING", createdAt: clock.t - 4000, expiresAt: clock.t - 1000, decidedAt: null });
  // PENDING, ещё не истёк — трогать нельзя.
  store.approvals.set("still-pending", { manifestId: "still-pending", server: "gmail", chatId: "555", messageId: 222, status: "PENDING", createdAt: clock.t, expiresAt: clock.t + 10000, decidedAt: null });
  // APPROVED, TTL-окно истекло — кандидат класса 2 (сообщение удалить).
  store.approvals.set("decided-1", { manifestId: "decided-1", server: "sheets", chatId: "555", messageId: 333, status: "APPROVED", createdAt: clock.t - 5000, expiresAt: clock.t - 500, decidedAt: clock.t - 2000 });
  // REJECTED, TTL-окно ещё не истекло — трогать рано.
  store.approvals.set("decided-fresh", { manifestId: "decided-fresh", server: "ticktick", chatId: "555", messageId: 444, status: "REJECTED", createdAt: clock.t, expiresAt: clock.t + 10000, decidedAt: clock.t });

  await runApprovalSweep(tgCfg({ enabled: true, webhookOwner: true }), store, now);

  check("просроченный PENDING переведён в EXPIRED", store.approvals.get("expired-1").status === "EXPIRED");
  check("editMessageReplyMarkup вызван для просроченного (снята кнопка)",
    tgCalls.some((c) => c.method === "editMessageReplyMarkup" && c.body.message_id === 111));
  check("ещё живой PENDING не тронут", store.approvals.get("still-pending").status === "PENDING");
  check("ещё живой PENDING — editMessageReplyMarkup НЕ вызван для него",
    !tgCalls.some((c) => c.method === "editMessageReplyMarkup" && c.body.message_id === 222));

  check("решённый (APPROVED) старше TTL — строка удалена из store", !store.approvals.has("decided-1"));
  check("deleteMessage вызван для решённого старше TTL",
    tgCalls.some((c) => c.method === "deleteMessage" && c.body.message_id === 333));
  check("свежерешённый (REJECTED, TTL не истёк) НЕ тронут", store.approvals.has("decided-fresh"));
  check("свежерешённый — deleteMessage НЕ вызван для него",
    !tgCalls.some((c) => c.method === "deleteMessage" && c.body.message_id === 444));

  // Гейт webhookOwner — та же дисциплина, что у registerWebhook: сервер, не
  // владеющий вебхуком, не должен трогать ЧУЖИЕ строки других серверов.
  const { mock: mock2 } = resetTelegramMocks();
  mock2("editMessageReplyMarkup", () => ({ statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } }));
  const store2 = makeTgStore();
  store2.approvals.set("expired-2", { manifestId: "expired-2", server: "gmail", chatId: "555", messageId: 555, status: "PENDING", createdAt: clock.t - 4000, expiresAt: clock.t - 1000, decidedAt: null });
  await runApprovalSweep(tgCfg({ enabled: true, webhookOwner: false }), store2, now);
  check("webhookOwner=false → sweep вообще не трогает store (не-владелец молчит)",
    store2.approvals.get("expired-2").status === "PENDING" && tgCalls.length === 0);
}

// ── итог ─────────────────────────────────────────────────────────────────
console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
