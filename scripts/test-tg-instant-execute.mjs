#!/usr/bin/env node
/**
 * Offline unit-тест НЕМЕДЛЕННОГО исполнения по нажатию кнопки
 * (`tg_approval.ts`'s `handleWebhook(..., onApproved)` + связка с
 * `consent.ts`'s `tryAutoExecute`) — Максим, 2026-08-06: «отчёт пришёл спустя
 * секунд 10, надо ускорять; исполнять прямо в обработчике нажатия, опрос
 * оставить страховкой».
 *
 * Замеренный на проде повод (consent_audit + tg_approvals, 2026-08-06):
 * кнопка нажата 13:22:28 → аудит исполнения 13:22:34 → фактическая отправка
 * 13:22:44. Между решением и стартом работы стояло ожидание следующего тика
 * поллера (10 с) — эта правка убирает именно его.
 *
 * Ничего сетевого и никакой БД: Telegram Bot API замокан undici's MockAgent
 * (как в test-tg-approval.mjs), хранилища — in-memory с ТЕМ ЖЕ атомарным
 * контрактом, что у Postgres-версий (проверка и запись в одном шаге —
 * моделируют `UPDATE … WHERE status = 'PENDING' … RETURNING`).
 *
 * Запуск: node scripts/test-tg-instant-execute.mjs
 */
import { readFile } from "node:fs/promises";
import { MockAgent, setGlobalDispatcher } from "undici";
import { handleWebhook } from "../src/tg_approval.ts";
import { tryAutoExecute, sha256, TG_AUTO_REPLY_MARKER } from "../src/consent.ts";

const clock = { t: 1_700_000_000_000 };
const now = () => clock.t;
const BOT_TOKEN = "TESTTOKEN";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let tgCalls = [];
function resetTelegramMocks() {
  tgCalls = [];
  const agent = new MockAgent();
  agent.disableNetConnect();
  setGlobalDispatcher(agent);
  const pool = agent.get("https://api.telegram.org");
  for (const method of ["editMessageReplyMarkup", "answerCallbackQuery", "editMessageText"]) {
    pool
      .intercept({ path: `/bot${BOT_TOKEN}/${method}`, method: "POST" })
      .reply((opts) => {
        tgCalls.push({ method, body: JSON.parse(opts.body) });
        return { statusCode: 200, data: { ok: true, result: {} } };
      })
      .persist();
  }
}

// ── TgApprovalStore: атомарный one-shot, как в store.ts ─────────────────────
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
      if (!r || r.server !== server || r.status !== "PENDING") return null;
      if (clock.t >= r.expiresAt) return null;
      r.status = status;
      r.decidedAt = clock.t;
      return { ...r };
    },
    // Ровно то, что делает Postgres одним UPDATE: сравнение статуса и запись
    // решения без единой точки прерывания между ними. Именно на этом стоит
    // одноразовость при двух одновременных нажатиях (раздел [4] ниже).
    async consumeTgDecisionAnyServer(manifestId, status) {
      const r = approvals.get(manifestId);
      if (!r || r.status !== "PENDING") return null;
      if (clock.t >= r.expiresAt) return null;
      r.status = status;
      r.decidedAt = clock.t;
      return { ...r };
    },
    async claimExpiredPendingApprovals() {
      return [];
    },
    async claimStaleDecidedApprovals() {
      return [];
    },
  };
}

// ── ConsentStore. `consumeManifest` неделим (проверка статуса и запись без
// точки прерывания между ними) — ровно как `UPDATE … WHERE status =
// 'AWAITING_CONSENT' … RETURNING` в store.ts. Это и есть та гарантия, которую
// проверяет раздел [5].
function makeConsentStore() {
  const manifests = new Map();
  const audits = [];
  const stats = { consumeAttempts: 0 };
  return {
    manifests,
    audits,
    stats,
    async createManifest(input) {
      manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null });
    },
    async getManifest(id, server) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      return { ...r };
    },
    async consumeManifest(id, server, userReply) {
      stats.consumeAttempts++;
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
    webhookOwner: true,
    ...overrides,
  };
}

const consentCfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now };
const PAYLOAD = { account: "admin", messages: [{ to: "eric@x.com", subject: "Quote", body: "..." }] };
const OBJHASH = sha256(PAYLOAD);
const rehashOk = (addressing) => sha256(addressing);

function tap(manifestId, decision = "a", fromId = "555") {
  return {
    update_id: Math.floor(Math.random() * 1e6),
    callback_query: {
      id: "cbq-" + manifestId + "-" + decision,
      from: { id: fromId },
      data: `${decision}:${manifestId}`,
      message: { message_id: 586, chat: { id: "555" } },
    },
  };
}

async function seed(tgStore, consentStore, id = "m1", server = "gmail") {
  await consentStore.createManifest({
    id, server, tool: "gmail_send", accountLabel: "admin",
    payload: PAYLOAD, objectHash: OBJHASH, createdAt: clock.t, expiresAt: clock.t + 3_600_000,
  });
  await tgStore.createTgApproval({
    manifestId: id, server, chatId: "555", messageId: 586,
    createdAt: clock.t, expiresAt: clock.t + 3_600_000,
  });
}

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

// ═══ [1] APPROVED → хук вызван ровно один раз и получает строку решения ═══
console.log("\n[1] нажата «✅ Подтвердить» → хук немедленного исполнения вызван ровно один раз");
{
  resetTelegramMocks();
  const tgStore = makeTgStore();
  const consentStore = makeConsentStore();
  await seed(tgStore, consentStore);
  const seen = [];
  await handleWebhook(tgCfg(), tgStore, tap("m1"), (row) => seen.push(row));
  await sleep(10);
  check("хук вызван ровно один раз", seen.length === 1, `вызовов: ${seen.length}`);
  check("хук получил manifestId нажатой кнопки", seen[0]?.manifestId === "m1");
  check("хук получил server строки (нужен вызывающему, чтобы отсечь чужой сервер)", seen[0]?.server === "gmail");
  check("хук получил messageId (куда вписывать отчёт)", seen[0]?.messageId === 586);
  check("строка переведена в APPROVED", tgStore.approvals.get("m1").status === "APPROVED");
}

// ═══ [2] REJECTED → хук НЕ вызывается ═══
console.log("\n[2] нажата «🛑 Отклонить» → немедленное исполнение НЕ запускается");
{
  resetTelegramMocks();
  const tgStore = makeTgStore();
  const consentStore = makeConsentStore();
  await seed(tgStore, consentStore, "m2");
  const seen = [];
  await handleWebhook(tgCfg(), tgStore, tap("m2", "r"), (row) => seen.push(row));
  await sleep(10);
  check("хук НЕ вызван", seen.length === 0, `вызовов: ${seen.length}`);
  check("строка переведена в REJECTED", tgStore.approvals.get("m2").status === "REJECTED");
}

// ═══ [3] чужой from.id → ни решения, ни исполнения ═══
console.log("\n[3] кнопку нажал НЕ владелец → ни решения, ни немедленного исполнения");
{
  resetTelegramMocks();
  const tgStore = makeTgStore();
  const consentStore = makeConsentStore();
  await seed(tgStore, consentStore, "m3");
  const seen = [];
  await handleWebhook(tgCfg(), tgStore, tap("m3", "a", "999"), (row) => seen.push(row));
  await sleep(10);
  check("хук НЕ вызван", seen.length === 0, `вызовов: ${seen.length}`);
  check("строка осталась PENDING", tgStore.approvals.get("m3").status === "PENDING");
}

// ═══ [4] ДВА ОДНОВРЕМЕННЫХ НАЖАТИЯ → ровно ОДНО исполнение ═══
console.log("\n[4] два одновременных нажатия одной кнопки → ровно ОДИН запуск исполнения");
{
  resetTelegramMocks();
  const tgStore = makeTgStore();
  const consentStore = makeConsentStore();
  await seed(tgStore, consentStore, "m4");
  const seen = [];
  const cfg = tgCfg();
  // Оба апдейта уходят в обработку одновременно — как две доставки Telegram
  // (двойной тап / ретрай вебхука), не дожидаясь друг друга.
  await Promise.all([
    handleWebhook(cfg, tgStore, tap("m4"), (row) => seen.push(row)),
    handleWebhook(cfg, tgStore, tap("m4"), (row) => seen.push(row)),
  ]);
  await sleep(10);
  check("хук исполнения вызван РОВНО ОДИН раз (захват решения неделим)", seen.length === 1, `вызовов: ${seen.length}`);
  check("оба нажатия получили ответ (спиннер снят у обоих)",
    tgCalls.filter((c) => c.method === "answerCallbackQuery").length === 2);
  check("второму нажатию сказано «Уже обработано»",
    tgCalls.filter((c) => c.method === "answerCallbackQuery" && c.body.text === "Уже обработано").length === 1);
}

// ═══ [5] ДВА ОДНОВРЕМЕННЫХ ПУТИ ИСПОЛНЕНИЯ (кнопка + поллер-страховка) ═══
console.log("\n[5] немедленный путь и поллер-страховка стартовали одновременно → ровно ОДНА отправка");
{
  const consentStore = makeConsentStore();
  await consentStore.createManifest({
    id: "m5", server: "gmail", tool: "gmail_send", accountLabel: "admin",
    payload: PAYLOAD, objectHash: OBJHASH, createdAt: clock.t, expiresAt: clock.t + 3_600_000,
  });
  // Пауза ВНУТРИ rehash — он в проде реально ходит за живым состоянием в
  // Gmail, и это единственное место, где два исполнителя гарантированно
  // переплетаются: оба уже прочитали манифест живым и оба идут потреблять его.
  // Без паузы первый успевал бы пройти всю цепочку до того, как второй вообще
  // начнёт, и раздел проверял бы очередь, а не одноразовость.
  const rehashSlow = async (addressing) => {
    await sleep(20);
    return rehashOk(addressing);
  };
  let executed = 0;
  const runOnce = async () => {
    const result = await tryAutoExecute(
      { manifestId: "m5", tool: "gmail_send", accountLabel: "admin" },
      rehashSlow, consentStore, consentCfg,
    );
    if (!result) return null;
    executed++; // «фактическая отправка письма» — считаем сколько раз дошли сюда
    return result;
  };
  const [a, b] = await Promise.all([runOnce(), runOnce()]);
  // Страховка от вырождения самого теста: если бы второй путь отвалился ещё до
  // захвата (например первый успел закрыть манифест, пока второй не начал),
  // раздел проверял бы очередь, а не одноразовость, и молча зеленел бы даже
  // со сломанным захватом.
  check("оба пути реально дошли до захвата (гонка настоящая)",
    consentStore.stats.consumeAttempts === 2, `попыток захвата: ${consentStore.stats.consumeAttempts}`);
  check("исполнение произошло РОВНО ОДИН раз", executed === 1, `исполнений: ${executed}`);
  check("ровно один путь получил результат, второй — null", (a === null) !== (b === null));
  check("манифест потреблён (DONE)", consentStore.manifests.get("m5").status === "DONE");
  check("аудит-запись ровно одна", consentStore.audits.length === 1, `записей: ${consentStore.audits.length}`);
  check("аудит честно помечен actor=tg_auto", consentStore.audits[0]?.actor === "tg_auto");
  check("в аудите метка кнопки, а не выдуманное «да»", consentStore.audits[0]?.userReply === TG_AUTO_REPLY_MARKER);
}

// ═══ [6] хук НЕ блокирует обработчик нажатия ═══
console.log("\n[6] долгое исполнение не задерживает ответ Telegram (работа уходит в фон)");
{
  resetTelegramMocks();
  const tgStore = makeTgStore();
  const consentStore = makeConsentStore();
  await seed(tgStore, consentStore, "m6");
  let hookFinished = false;
  const started = Date.now();
  await handleWebhook(tgCfg(), tgStore, tap("m6"), async () => {
    await sleep(300); // «отправка письма» — заведомо дольше обработчика
    hookFinished = true;
  });
  const elapsed = Date.now() - started;
  check("handleWebhook вернулся, не дожидаясь исполнения", hookFinished === false);
  check("и вернулся быстро (< 200 мс)", elapsed < 200, `прошло ${elapsed} мс`);
  check("кнопки сняты, не дожидаясь исполнения",
    tgCalls.some((c) => c.method === "editMessageReplyMarkup"));
  await sleep(400);
  check("фоновое исполнение всё-таки завершилось", hookFinished === true);
}

// ═══ [7] упавший хук не ломает обработчик нажатия ═══
console.log("\n[7] исполнение упало → решение всё равно записано, кнопка отвечена");
{
  resetTelegramMocks();
  const tgStore = makeTgStore();
  const consentStore = makeConsentStore();
  await seed(tgStore, consentStore, "m7");
  await handleWebhook(tgCfg(), tgStore, tap("m7"), () => {
    throw new Error("исполнение сломалось");
  });
  await sleep(10);
  check("решение записано (APPROVED)", tgStore.approvals.get("m7").status === "APPROVED");
  check("answerCallbackQuery всё равно вызван", tgCalls.some((c) => c.method === "answerCallbackQuery"));
}

// ═══ [8] обратная совместимость: без хука всё как раньше ═══
console.log("\n[8] хук не передан (старый вызов из портированных копий) → поведение прежнее");
{
  resetTelegramMocks();
  const tgStore = makeTgStore();
  const consentStore = makeConsentStore();
  await seed(tgStore, consentStore, "m8");
  // Ловим и «тихие» поломки: вызов необязательного хука без проверки на его
  // наличие даёт TypeError, который try/catch внутри проглотит — снаружи это
  // выглядело бы как рабочий путь, отличаясь только строкой в логе.
  const realError = console.error;
  const errors = [];
  console.error = (...args) => errors.push(args.map(String).join(" "));
  await handleWebhook(tgCfg(), tgStore, tap("m8"));
  await sleep(10);
  console.error = realError;
  check("ни одной ошибки в лог не ушло", errors.length === 0, `в логе: ${errors[0] ?? ""}`);
  check("решение записано без хука", tgStore.approvals.get("m8").status === "APPROVED");
  check("кнопки сняты", tgCalls.some((c) => c.method === "editMessageReplyMarkup"));
  check("ответ на нажатие отправлен", tgCalls.some((c) => c.method === "answerCallbackQuery"));
}

// ═══ [9] проводка в http.ts — чтобы «ускорение» не осталось неподключённым ═══
// Разделы [1]–[8] зовут `handleWebhook` напрямую и потому НЕ заметили бы, если
// бы маршрут `/tg/webhook` перестал передавать хук (тогда всё молча вернулось
// бы к ожиданию поллера — ровно тот баг, который чинится). Тот же приём, что
// в test-gate-coverage.mjs: читаем исходник и проверяем факт проводки.
console.log("\n[9] маршрут вебхука реально подключает немедленное исполнение (проверка по исходнику)");
{
  const httpSrc = await readFile(new URL("../src/http.ts", import.meta.url), "utf8");
  const storeSrc = await readFile(new URL("../src/store.ts", import.meta.url), "utf8");
  check("handleWebhook вызывается с хуком-колбэком", /handleWebhook\([^)]*?,\s*\(row\)\s*=>/s.test(httpSrc));
  check("хук запускает немедленное исполнение", /executeApprovedNow\(config,\s*row\.manifestId\)/.test(httpSrc));
  check("чужой сервер отсекается в вызывающем",
    /row\.server\s*!==\s*consentServerConfig\.server/.test(httpSrc));
  check("немедленное исполнение НЕ ожидается обработчиком (нет await перед ним)",
    /void\s+executeApprovedNow\(/.test(httpSrc));
  check("поллер-страховка остался на месте", /setInterval\([\s\S]{0,120}runAutoExecutePoller\(/.test(httpSrc));
  check("точечный SELECT кандидата server-scoped (вторая линия защиты)",
    /getApprovedUnexecuted[\s\S]{0,900}m\.server\s*=\s*\$2/.test(storeSrc));
  check("точечный SELECT требует APPROVED и живой манифест",
    /getApprovedUnexecuted[\s\S]{0,900}m\.status\s*=\s*'AWAITING_CONSENT'[\s\S]{0,300}a\.status\s*=\s*'APPROVED'/.test(storeSrc));
}

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
