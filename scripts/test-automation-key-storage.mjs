#!/usr/bin/env node
/**
 * Offline-тест возможностей 2 и 3 задачи «менеджер ключей»:
 *  [A] AUTOMATION_KEY_MASTER_SECRET — парсинг/валидация в config.ts
 *      (loadAutomationKeyConfig): отсутствует → null (фича выключена молча);
 *      валидные 32 байта (base64/base64url) → строка как есть; невалидная
 *      длина/мусор → null + предупреждение в лог, НЕ падение процесса.
 *  [B] Шифрованное хранение (`generateAndDeliverKey`) + перевыпуск
 *      (`reissueNoteForWindow`) — round-trip: без мастер-секрета
 *      `tokenEncrypted` остаётся `null` (регресс, тестовый план п.3); с
 *      мастер-секретом — `tokenEncrypted` заполнен, `reissueNoteForWindow`
 *      расшифровывает его обратно и создаёт РАБОЧУЮ вторую заметку с ТЕМ ЖЕ
 *      инструктивным текстом/токеном, что и первая (тестовый план п.2/п.4).
 *  [C] Смена scope (`store.updateScope`) — `checkAutomationKeyFor` до/после
 *      реально видит новый scope, а не старый (тестовый план п.1).
 *
 * Никакого реального Telegram/self-destroyed-notes/Postgres — тот же приём
 * (undici MockAgent + in-memory store), что и `test-automation-key.mjs`.
 *
 * Запуск: node scripts/test-automation-key-storage.mjs
 */
import crypto from "node:crypto";
import { MockAgent, setGlobalDispatcher } from "undici";
import { loadAutomationKeyConfig } from "../src/config.ts";
import {
  generateAndDeliverKey,
  reissueNoteForWindow,
  checkAutomationKeyFor,
} from "../src/automation_key.ts";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const SELF_DESTROYED_NOTES_BASE_URL = "https://self-destroyed-notes-production.up.railway.app";
const BOT_TOKEN = "TESTTOKEN";
const OWNER_CHAT_ID = "555";
const nowFixed = () => 1_700_000_000_000;

// Обратная операция encryptForNote() — та же, что в test-automation-key.mjs.
function decryptNotePayload(payload, keyB64Url) {
  const urlKey = Buffer.from(keyB64Url, "base64url");
  const salt = Buffer.from(payload.salt, "base64");
  const key = crypto.pbkdf2Sync(urlKey, salt, payload.iter, 32, "sha256");
  const iv = Buffer.from(payload.iv, "base64");
  const dataAndTag = Buffer.from(payload.data, "base64");
  const tag = dataAndTag.subarray(dataAndTag.length - 16);
  const encrypted = dataAndTag.subarray(0, dataAndTag.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}
function noteKeyFromLink(noteLink) {
  return noteLink.split("/").pop();
}

// ═══ [A] AUTOMATION_KEY_MASTER_SECRET — парсинг в config.ts ═══
console.log("\n[A] loadAutomationKeyConfig().masterSecret — парсинг переменной окружения");
{
  const savedEnv = process.env.AUTOMATION_KEY_MASTER_SECRET;

  delete process.env.AUTOMATION_KEY_MASTER_SECRET;
  check("[план 3] переменная отсутствует → masterSecret = null (фича выключена молча)", loadAutomationKeyConfig().masterSecret === null);

  process.env.AUTOMATION_KEY_MASTER_SECRET = "   ";
  check("переменная из одних пробелов → null (как отсутствующая)", loadAutomationKeyConfig().masterSecret === null);

  const validB64 = crypto.randomBytes(32).toString("base64");
  process.env.AUTOMATION_KEY_MASTER_SECRET = validB64;
  check("валидные 32 байта (обычный base64, вывод `openssl rand -base64 32`) → принято как есть", loadAutomationKeyConfig().masterSecret === validB64);

  const validB64Url = crypto.randomBytes(32).toString("base64url");
  process.env.AUTOMATION_KEY_MASTER_SECRET = validB64Url;
  check("валидные 32 байта (base64url) → тоже принято", loadAutomationKeyConfig().masterSecret === validB64Url);

  process.env.AUTOMATION_KEY_MASTER_SECRET = crypto.randomBytes(16).toString("base64");
  check("16 байт (неверная длина) → null, НЕ бросает исключение", loadAutomationKeyConfig().masterSecret === null);

  process.env.AUTOMATION_KEY_MASTER_SECRET = "not-even-base64-!!!###";
  check("мусорная строка → null, НЕ бросает исключение", loadAutomationKeyConfig().masterSecret === null);

  if (savedEnv === undefined) delete process.env.AUTOMATION_KEY_MASTER_SECRET;
  else process.env.AUTOMATION_KEY_MASTER_SECRET = savedEnv;
}

// ── общая инфраструктура для [B]/[C] — тот же приём, что test-automation-key.mjs ──
let tgCalls = [];
let noteApiCalls = [];

function resetMocks(notesResponder) {
  tgCalls = [];
  noteApiCalls = [];
  const agent = new MockAgent();
  agent.disableNetConnect();
  setGlobalDispatcher(agent);
  const pool = agent.get("https://api.telegram.org");
  const notesPool = agent.get(SELF_DESTROYED_NOTES_BASE_URL);
  let noteIdCounter = 0;
  const defaultResponder = () => ({ statusCode: 200, data: { id: `note-${++noteIdCounter}` }, headers: { "content-type": "application/json" } });
  notesPool
    .intercept({ path: "/api/notes", method: "POST" })
    .reply((opts) => {
      const body = JSON.parse(opts.body);
      noteApiCalls.push(body);
      return (notesResponder ?? defaultResponder)(body);
    })
    .persist();
  for (const method of ["sendMessage", "deleteMessage"]) {
    pool
      .intercept({ path: `/bot${BOT_TOKEN}/${method}`, method: "POST" })
      .reply((opts) => {
        const body = JSON.parse(opts.body);
        tgCalls.push({ method, body });
        return { statusCode: 200, data: { ok: true, result: { message_id: 1000 + tgCalls.length } }, headers: { "content-type": "application/json" } };
      })
      .persist();
  }
}

function makeStore() {
  const windows = new Map();
  return {
    windows,
    async createWindow(input) {
      windows.set(input.windowId, { ...input, label: input.label ?? null, revokedAt: null, tokenEncrypted: input.tokenEncrypted ?? null });
    },
    async listActiveWindows(nowMs) {
      return [...windows.values()].filter((w) => w.revokedAt === null && (w.expiresAt === null || w.expiresAt > nowMs));
    },
    async listAllWindows(limit) {
      const all = [...windows.values()].sort((a, b) => b.createdAt - a.createdAt);
      return { windows: all.slice(0, limit), total: all.length };
    },
    async getWindow(windowId) {
      return windows.get(windowId) ?? null;
    },
    async revokeWindow(windowId, nowMs) {
      const w = windows.get(windowId);
      if (!w || w.revokedAt !== null) return false;
      w.revokedAt = nowMs;
      return true;
    },
    async updateScope(windowId, scope) {
      const w = windows.get(windowId);
      if (!w) return false;
      w.scope = scope;
      return true;
    },
  };
}

function tgCfg() {
  return {
    enabled: true,
    botToken: BOT_TOKEN,
    ownerChatId: OWNER_CHAT_ID,
    webhookSecret: "wh-secret-xyz",
    publicBaseUrl: "https://example.test",
    server: "gmail",
    toolsAllowlist: null,
    ttlMs: 3_600_000,
    webhookOwner: true,
    ownBot: false,
  };
}

const MASTER_SECRET = crypto.randomBytes(32).toString("base64url");

// ═══ [B-1] Без мастер-секрета — tokenEncrypted остаётся null (регресс, план п.3) ═══
console.log("\n[B-1] akCfg.masterSecret = null (регресс) → tokenEncrypted НЕ пишется, окно/доставка работают как раньше");
{
  resetMocks();
  const store = makeStore();
  const result = await generateAndDeliverKey(tgCfg(), { ttlMs: 3_600_000, masterSecret: null }, store, OWNER_CHAT_ID, 1, 3_600_000, null, nowFixed);
  check("окно создано", store.windows.size === 1, store.windows.size);
  const w = [...store.windows.values()][0];
  check("[план 3] tokenEncrypted === null без мастер-секрета", w.tokenEncrypted === null, w.tokenEncrypted);
  check("ключ всё равно доставлен (noteLink не null) — регресса в доставке нет", result && result.noteLink !== null, result);

  const reissue = await reissueNoteForWindow({ ttlMs: 3_600_000, masterSecret: null }, store, w.windowId, nowFixed);
  check("[план 4] перевыпуск без masterSecret → отказ master_secret_not_configured (не 500/исключение)", reissue.ok === false && reissue.reason === "master_secret_not_configured", reissue);
}

// ═══ [B-2] С мастер-секретом — tokenEncrypted пишется, round-trip через reissueNoteForWindow ═══
console.log("\n[B-2] akCfg.masterSecret задан → tokenEncrypted заполнен; reissueNoteForWindow расшифровывает и перевыпускает ту же заметку");
{
  resetMocks();
  const store = makeStore();
  const akCfg = { ttlMs: 3_600_000, masterSecret: MASTER_SECRET };
  const result = await generateAndDeliverKey(tgCfg(), akCfg, store, OWNER_CHAT_ID, 3 /* gmail+calendar */, 3_600_000, "рабочий ноутбук", nowFixed);
  const w = [...store.windows.values()][0];
  check("окно создано", !!w);
  check("[план 2] tokenEncrypted заполнен (не null)", typeof w.tokenEncrypted === "string" && w.tokenEncrypted.length > 0, w.tokenEncrypted);
  const parsed = JSON.parse(w.tokenEncrypted);
  check("[план 2] tokenEncrypted — та же форма {v,iv,data,salt,iter,pw}, что и заметка", parsed.v === 1 && typeof parsed.iv === "string" && typeof parsed.data === "string" && typeof parsed.salt === "string" && typeof parsed.iter === "number", parsed);

  // Исходная заметка (та, что ушла в чат при генерации) — для сравнения текста ниже.
  const firstNoteApiCall = noteApiCalls[0];
  const firstSentMsg = tgCalls.find((c) => c.method === "sendMessage");
  const firstLinkMatch = (firstSentMsg?.body.text ?? "").match(new RegExp(`${SELF_DESTROYED_NOTES_BASE_URL.replace(/[.]/g, "\\.")}/#/n/[^/\\s]+/[^\\s]+`));
  const firstLink = firstLinkMatch?.[0];
  const firstNoteBody = firstLink ? decryptNotePayload(firstNoteApiCall.payload, noteKeyFromLink(firstLink)) : "";
  const firstRawToken = firstNoteBody.match(/Ключ: (\S+)/)?.[1];
  check("[контроль] исходная заметка содержит rawToken, чей sha256 == tokenHash", !!firstRawToken && crypto.createHash("sha256").update(firstRawToken).digest("hex") === w.tokenHash, { firstRawToken, tokenHash: w.tokenHash });

  // Перевыпуск — та же расшифровка через akCfg.masterSecret, НОВАЯ заметка.
  const before = noteApiCalls.length;
  const reissue = await reissueNoteForWindow(akCfg, store, w.windowId, nowFixed);
  check("[план 4] перевыпуск успешен", reissue.ok === true, reissue);
  check("[план 4] ровно один НОВЫЙ POST /api/notes на перевыпуск", noteApiCalls.length === before + 1, noteApiCalls.length - before);
  check("перевыпуск НЕ отправил ничего в чат (только вернул ссылку — страница мини-аппа сама её показывает)", tgCalls.filter((c) => c.method === "sendMessage").length === 1, tgCalls.filter((c) => c.method === "sendMessage").length);

  const reissuedLinkMatch = reissue.noteLink.match(new RegExp(`${SELF_DESTROYED_NOTES_BASE_URL.replace(/[.]/g, "\\.")}/#/n/([^/\\s]+)/([^\\s]+)`));
  check("[план 4] noteLink — рабочая ссылка на self-destroyed-notes", !!reissuedLinkMatch, reissue.noteLink);
  const reissuedNoteApiCall = noteApiCalls[noteApiCalls.length - 1];
  const reissuedNoteBody = decryptNotePayload(reissuedNoteApiCall.payload, noteKeyFromLink(reissue.noteLink));
  const reissuedRawToken = reissuedNoteBody.match(/Ключ: (\S+)/)?.[1];
  check(
    "[план 4] расшифровка перевыпущенной заметки (тем же способом, что test-note-crypto.mjs) даёт ТОТ ЖЕ rawToken, что исходная",
    reissuedRawToken === firstRawToken,
    { reissuedRawToken, firstRawToken },
  );
  check("[план 4] перевыпущенная заметка несёт тот же инструктивный текст (упоминает automation_key/срок/сервисы)", /automation_key/.test(reissuedNoteBody) && /gmail/.test(reissuedNoteBody) && /calendar/.test(reissuedNoteBody), reissuedNoteBody);
  // Название окна (label) в текст самой заметки НЕ входит — buildNoteInstructions
  // никогда не принимала label (см. её сигнатуру), ни при первой выдаче, ни
  // при перевыпуске; название видно только в сообщении бота/в менеджере.
}

// ═══ [B-3] Отказы reissueNoteForWindow — понятные причины, не 500/исключение ═══
console.log("\n[B-3] reissueNoteForWindow — отказы (не найдено/отозвано/истекло/нет токена/сбой сервиса/неверный ключ), тестовый план п.4");
{
  resetMocks();
  const store = makeStore();
  const akCfg = { ttlMs: 3_600_000, masterSecret: MASTER_SECRET };
  const now0 = nowFixed();

  const notFound = await reissueNoteForWindow(akCfg, store, "no-such-window", nowFixed);
  check("окно не найдено → window_not_found", notFound.ok === false && notFound.reason === "window_not_found", notFound);

  await store.createWindow({ windowId: "revoked1", tokenHash: "h1", scope: "gmail", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID, tokenEncrypted: "{}" });
  await store.revokeWindow("revoked1", now0);
  const revokedResult = await reissueNoteForWindow(akCfg, store, "revoked1", nowFixed);
  check("окно отозвано → window_revoked", revokedResult.ok === false && revokedResult.reason === "window_revoked", revokedResult);

  await store.createWindow({ windowId: "expired1", tokenHash: "h2", scope: "gmail", createdAt: now0 - 200_000, expiresAt: now0 - 1_000, createdByChat: OWNER_CHAT_ID, tokenEncrypted: "{}" });
  const expiredResult = await reissueNoteForWindow(akCfg, store, "expired1", nowFixed);
  check("окно истекло → window_expired", expiredResult.ok === false && expiredResult.reason === "window_expired", expiredResult);

  await store.createWindow({ windowId: "no-token1", tokenHash: "h3", scope: "gmail", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID, tokenEncrypted: null });
  const noTokenResult = await reissueNoteForWindow(akCfg, store, "no-token1", nowFixed);
  check("[план 4] окно БЕЗ token_encrypted (выпущено до включения фичи) → no_stored_token, НЕ 500", noTokenResult.ok === false && noTokenResult.reason === "no_stored_token", noTokenResult);

  // Битый payload (не расшифровывается этим ключом) → decrypt_failed, не исключение наружу.
  const otherKey = crypto.randomBytes(32).toString("base64url");
  const bogusPayload = JSON.stringify({ v: 1, iv: Buffer.alloc(12).toString("base64"), data: Buffer.alloc(32).toString("base64"), salt: Buffer.alloc(16).toString("base64"), iter: 100_000, pw: false });
  void otherKey;
  await store.createWindow({ windowId: "bad-payload1", tokenHash: "h4", scope: "gmail", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID, tokenEncrypted: bogusPayload });
  const badPayloadResult = await reissueNoteForWindow(akCfg, store, "bad-payload1", nowFixed);
  check("[план 4] битый/несовпадающий payload → decrypt_failed, НЕ исключение наружу", badPayloadResult.ok === false && badPayloadResult.reason === "decrypt_failed", badPayloadResult);

  // self-destroyed-notes недоступен во время перевыпуска.
  resetMocks(() => ({ statusCode: 500, data: { error: "internal" }, headers: { "content-type": "application/json" } }));
  const store2 = makeStore();
  const gen = await generateAndDeliverKey(tgCfg(), { ttlMs: 3_600_000, masterSecret: MASTER_SECRET }, store2, OWNER_CHAT_ID, 1, 3_600_000, null, nowFixed);
  void gen;
  const w2 = [...store2.windows.values()][0];
  const failResult = await reissueNoteForWindow({ ttlMs: 3_600_000, masterSecret: MASTER_SECRET }, store2, w2.windowId, nowFixed);
  check("[план 4] self-destroyed-notes недоступен при перевыпуске → note_service_unavailable", failResult.ok === false && failResult.reason === "note_service_unavailable", failResult);
}

// ═══ [C] Смена scope — checkAutomationKeyFor реально видит НОВЫЙ scope (план п.1) ═══
console.log("\n[C] store.updateScope меняет scope на месте; checkAutomationKeyFor до/после видит именно его");
{
  const store = makeStore();
  const now0 = nowFixed();
  const rawToken = "raw-token-for-scope-test";
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  await store.createWindow({ windowId: "scope-test", tokenHash, scope: "gmail", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID, tokenEncrypted: null });

  const beforeGmail = await checkAutomationKeyFor("gmail", store, rawToken, "gmail_send", nowFixed);
  const beforeCalendar = await checkAutomationKeyFor("calendar", store, rawToken, "calendar_event_create", nowFixed);
  check("[план 1] ДО смены scope: покрывает gmail", beforeGmail.ok === true, beforeGmail);
  check("[план 1] ДО смены scope: НЕ покрывает calendar", beforeCalendar.ok === false, beforeCalendar);

  const updated = await store.updateScope("scope-test", "calendar");
  check("updateScope вернул true (строка найдена)", updated === true);

  const afterGmail = await checkAutomationKeyFor("gmail", store, rawToken, "gmail_send", nowFixed);
  const afterCalendar = await checkAutomationKeyFor("calendar", store, rawToken, "calendar_event_create", nowFixed);
  check("[план 1] ПОСЛЕ смены scope: gmail больше НЕ покрыт (старый scope не работает)", afterGmail.ok === false, afterGmail);
  check("[план 1] ПОСЛЕ смены scope: calendar теперь покрыт (новый scope работает)", afterCalendar.ok === true, afterCalendar);

  const missing = await store.updateScope("no-such-window", "gmail");
  check("updateScope на несуществующем windowId → false", missing === false);
}

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
