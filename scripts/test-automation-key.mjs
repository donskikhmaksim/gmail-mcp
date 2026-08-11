#!/usr/bin/env node
/**
 * Offline unit-тест единого `automation_key` hub (`src/automation_key.ts`,
 * `docs/TZ_automation_key_hub.md`). Никакого реального Telegram — Bot API
 * замокан через undici's MockAgent (тот же клиент, что использует сам
 * модуль в проде — см. `tg_approval.ts`'s `tgCall`), store — in-memory Map с
 * тем же контрактом, что store.ts (`AutomationWindowStore`).
 *
 * Реальная Postgres-миграция (идемпотентность ADD COLUMN/бэкафилл) — в
 * отдельном разделе [8] ниже, ТОЛЬКО когда задан AUTOMATION_KEY_TEST_DB_URL
 * (см. README-запуск ниже); без него раздел молча пропускается, весь
 * остальной файл — чистый offline-тест по стилю test-tg-approval.mjs.
 *
 * Запуск: node scripts/test-automation-key.mjs
 *   (для раздела [8]: AUTOMATION_KEY_TEST_DB_URL=postgres://... node scripts/test-automation-key.mjs)
 */
import { MockAgent, setGlobalDispatcher } from "undici";
import {
  handleAutomationKeyMessage,
  handleAutomationKeyCallback,
  maskToScope,
  AUTOMATION_SERVICES,
} from "../src/automation_key.ts";

const BOT_TOKEN = "TESTTOKEN";
const OWNER_CHAT_ID = "555";
let tgCalls = [];

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

function mockDefaults(h) {
  h.mock("sendMessage", () => ({
    statusCode: 200,
    data: { ok: true, result: { message_id: 1000 + tgCalls.length } },
    headers: { "content-type": "application/json" },
  }));
  h.mock("editMessageReplyMarkup", () => ({
    statusCode: 200,
    data: { ok: true, result: true },
    headers: { "content-type": "application/json" },
  }));
  h.mock("editMessageText", () => ({
    statusCode: 200,
    data: { ok: true, result: true },
    headers: { "content-type": "application/json" },
  }));
  h.mock("answerCallbackQuery", () => ({
    statusCode: 200,
    data: { ok: true, result: true },
    headers: { "content-type": "application/json" },
  }));
  h.mock("deleteMessage", () => ({
    statusCode: 200,
    data: { ok: true, result: true },
    headers: { "content-type": "application/json" },
  }));
}

// ── in-memory AutomationWindowStore — тот же контракт, что store.ts ────────
function makeStore() {
  const windows = new Map();
  return {
    windows,
    async createWindow(input) {
      windows.set(input.windowId, { ...input, revokedAt: null });
    },
    async listActiveWindows(nowMs) {
      return [...windows.values()].filter((w) => w.revokedAt === null && w.expiresAt > nowMs);
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

function akCfg(overrides = {}) {
  return { ttlMs: 24 * 60 * 60 * 1000, ...overrides };
}

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const nowFixed = () => 1_700_000_000_000;

/** Проходит полный флоу: /automation_key → toggle одного сервиса → «Получить
 * ключ». Возвращает { store, windows: [...] } для проверок. */
async function generateWithMask(services) {
  const h = resetTelegramMocks();
  mockDefaults(h);
  const store = makeStore();
  const cfg = tgCfg();

  // Строим маску тем же путём, что реальные нажатия: стартуем с 0, тоггл
  // каждого нужного сервиса по очереди — как в UI.
  let mask = 0;
  for (const svc of services) {
    const idx = AUTOMATION_SERVICES.indexOf(svc);
    const bit = 1 << idx;
    const newMask = mask ^ bit;
    const handled = await handleAutomationKeyCallback(
      cfg,
      akCfg(),
      store,
      { id: `cbq-toggle-${svc}`, fromId: Number(OWNER_CHAT_ID), data: `ak:toggle:${svc}:${mask}`, chatId: Number(OWNER_CHAT_ID), messageId: 42 },
      nowFixed,
    );
    check(`toggle(${svc}) обработан модулем`, handled === true);
    mask = newMask;
  }

  const genHandled = await handleAutomationKeyCallback(
    cfg,
    akCfg(),
    store,
    { id: "cbq-gen", fromId: Number(OWNER_CHAT_ID), data: `ak:gen:${mask}`, chatId: Number(OWNER_CHAT_ID), messageId: 42 },
    nowFixed,
  );
  check("ak:gen обработан модулем", genHandled === true);

  return { store, mask, tgCalls };
}

// ═══ [1] Генерация с ОДНИМ отмеченным сервисом → scope = это имя ═══
console.log("\n[1] генерация с одним отмеченным сервисом (ticktick) → scope='ticktick'");
{
  const { store } = await generateWithMask(["ticktick"]);
  const windows = [...store.windows.values()];
  check("ровно одно окно создано", windows.length === 1, windows.length);
  check("scope === 'ticktick'", windows[0]?.scope === "ticktick", windows[0]?.scope);
  check("scope НЕ 'all' (только этот один сервис)", windows[0]?.scope !== "all");
  check("tokenHash — это sha256 hex (64 hex-символа), не сырой токен", /^[0-9a-f]{64}$/.test(windows[0]?.tokenHash ?? ""), windows[0]?.tokenHash);
  const sentToken = tgCalls.find((c) => c.method === "sendMessage" && /🔑/.test(c.body.text));
  check("отдельное сообщение с сырым токеном отправлено", !!sentToken);
  check("текст сообщения упоминает ticktick", /ticktick/.test(sentToken?.body.text ?? ""));
}

// ═══ [2] Генерация с «Все сразу» → scope = "all" ═══
console.log('\n[2] генерация с «Все сразу» → scope="all"');
{
  const h = resetTelegramMocks();
  mockDefaults(h);
  const store = makeStore();
  const cfg = tgCfg();

  const allHandled = await handleAutomationKeyCallback(
    cfg, akCfg(), store,
    { id: "cbq-all", fromId: Number(OWNER_CHAT_ID), data: "ak:all:0", chatId: Number(OWNER_CHAT_ID), messageId: 7 },
    nowFixed,
  );
  check("ak:all обработан", allHandled === true);
  // После "Все сразу" маска = все 6 бит выставлены.
  const ALL_MASK = (1 << AUTOMATION_SERVICES.length) - 1;
  check("maskToScope(ALL_MASK) === 'all'", maskToScope(ALL_MASK) === "all");

  const genHandled = await handleAutomationKeyCallback(
    cfg, akCfg(), store,
    { id: "cbq-gen-all", fromId: Number(OWNER_CHAT_ID), data: `ak:gen:${ALL_MASK}`, chatId: Number(OWNER_CHAT_ID), messageId: 7 },
    nowFixed,
  );
  check("ak:gen обработан", genHandled === true);
  const windows = [...store.windows.values()];
  check("ровно одно окно создано", windows.length === 1, windows.length);
  check("scope === 'all'", windows[0]?.scope === "all", windows[0]?.scope);
}

// ═══ [3] Пустой выбор + «Получить ключ» → ничего не создано, есть ответ об ошибке ═══
console.log('\n[3] пустой выбор (mask=0) + «Получить ключ» → БД пуста, есть текст ошибки');
{
  const h = resetTelegramMocks();
  mockDefaults(h);
  const store = makeStore();
  const cfg = tgCfg();

  const handled = await handleAutomationKeyCallback(
    cfg, akCfg(), store,
    { id: "cbq-gen-empty", fromId: Number(OWNER_CHAT_ID), data: "ak:gen:0", chatId: Number(OWNER_CHAT_ID), messageId: 9 },
    nowFixed,
  );
  check("ak:gen(mask=0) всё равно обработан модулем (true)", handled === true);
  check("НИЧЕГО не создано в store", store.windows.size === 0, store.windows.size);
  const errAnswer = tgCalls.find((c) => c.method === "answerCallbackQuery" && c.body.callback_query_id === "cbq-gen-empty");
  check("answerCallbackQuery вызван", !!errAnswer);
  check("текст ошибки присутствует", !!errAnswer?.body.text && errAnswer.body.text.length > 0, errAnswer?.body.text);
  check("show_alert=true (заметная ошибка, не тихий тост)", errAnswer?.body.show_alert === true);
  check("НИ ОДНОГО sendMessage с 🔑 не отправлено", !tgCalls.some((c) => c.method === "sendMessage"));
}

// ═══ [4] /automation_key list показывает только активные окна ═══
console.log("\n[4] /automation_key list — только активные (не отозванные/не истёкшие)");
{
  const h = resetTelegramMocks();
  mockDefaults(h);
  const store = makeStore();
  const cfg = tgCfg();
  const now0 = nowFixed();

  await store.createWindow({ windowId: "active1", tokenHash: "h1", scope: "gmail", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID });
  await store.createWindow({ windowId: "active2", tokenHash: "h2", scope: "all", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID });
  await store.createWindow({ windowId: "expired1", tokenHash: "h3", scope: "drive", createdAt: now0 - 200_000, expiresAt: now0 - 1_000, createdByChat: OWNER_CHAT_ID });
  await store.createWindow({ windowId: "revoked1", tokenHash: "h4", scope: "sheets", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID });
  await store.revokeWindow("revoked1", now0);

  const handled = await handleAutomationKeyMessage(
    cfg, store,
    { chatId: Number(OWNER_CHAT_ID), fromId: Number(OWNER_CHAT_ID), text: "/automation_key list" },
    nowFixed,
  );
  check("/automation_key list обработана модулем", handled === true);
  const listMsg = tgCalls.find((c) => c.method === "sendMessage");
  check("sendMessage со списком отправлен", !!listMsg);
  const text = listMsg?.body.text ?? "";
  check("active1 присутствует в списке", text.includes("active1"));
  check("active2 присутствует в списке", text.includes("active2"));
  check("expired1 ОТСУТСТВУЕТ (истёк)", !text.includes("expired1"));
  check("revoked1 ОТСУТСТВУЕТ (отозван)", !text.includes("revoked1"));
  const buttons = (listMsg?.body.reply_markup?.inline_keyboard ?? []).flat();
  check("кнопка «Отозвать» есть у каждого активного окна (2 кнопки)", buttons.length === 2, buttons.length);
  check("callback_data кнопок кодирует window_id", buttons.every((b) => /^ak:revoke:/.test(b.callback_data)));
}

// ═══ [5] revoke <id> гасит конкретное окно, остальные продолжают жить ═══
console.log("\n[5] /automation_key revoke <id> — гасит одно, остальные живы");
{
  const h = resetTelegramMocks();
  mockDefaults(h);
  const store = makeStore();
  const cfg = tgCfg();
  const now0 = nowFixed();
  await store.createWindow({ windowId: "keep-me", tokenHash: "hA", scope: "gmail", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID });
  await store.createWindow({ windowId: "kill-me", tokenHash: "hB", scope: "docs", createdAt: now0, expiresAt: now0 + 100_000, createdByChat: OWNER_CHAT_ID });

  const handled = await handleAutomationKeyMessage(
    cfg, store,
    { chatId: Number(OWNER_CHAT_ID), fromId: Number(OWNER_CHAT_ID), text: "/automation_key revoke kill-me" },
    nowFixed,
  );
  check("revoke-команда обработана", handled === true);
  const active = await store.listActiveWindows(now0);
  check("осталось ровно одно активное окно", active.length === 1, active.length);
  check("это именно keep-me", active[0]?.windowId === "keep-me", active[0]?.windowId);
  const killed = await store.getWindow("kill-me");
  check("kill-me помечен revokedAt", killed?.revokedAt !== null);

  // Повторный revoke того же id — идемпотентно false, ничего не меняет.
  const secondHandled = await handleAutomationKeyMessage(
    cfg, store,
    { chatId: Number(OWNER_CHAT_ID), fromId: Number(OWNER_CHAT_ID), text: "/automation_key revoke kill-me" },
    nowFixed,
  );
  check("повторный revoke тоже обработан (не падает)", secondHandled === true);
  const activeAfter = await store.listActiveWindows(now0);
  check("активных окон по-прежнему одно (повтор не сломал keep-me)", activeAfter.length === 1, activeAfter.length);

  // Кнопка «Отозвать» из /automation_key list — тот же эффект через callback.
  const cbHandled = await handleAutomationKeyCallback(
    cfg, akCfg(), store,
    { id: "cbq-revoke-btn", fromId: Number(OWNER_CHAT_ID), data: "ak:revoke:keep-me", chatId: Number(OWNER_CHAT_ID), messageId: 55 },
    nowFixed,
  );
  check("ak:revoke callback обработан", cbHandled === true);
  const activeFinal = await store.listActiveWindows(now0);
  check("после revoke кнопкой активных окон 0", activeFinal.length === 0, activeFinal.length);
}

// ═══ [6] Owner-only — не-владелец не может ни сгенерировать, ни отозвать ═══
console.log("\n[6] owner-only — чужой chat/from не может ни генерировать, ни отзывать");
{
  const h = resetTelegramMocks();
  mockDefaults(h);
  const store = makeStore();
  const cfg = tgCfg();
  const INTRUDER_ID = 999;

  const msgHandled = await handleAutomationKeyMessage(
    cfg, store,
    { chatId: INTRUDER_ID, fromId: INTRUDER_ID, text: "/automation_key" },
    nowFixed,
  );
  check("сообщение от чужого распознано как /automation_key (true), но проигнорировано", msgHandled === true);
  check("никакого sendMessage чужому не отправлено", !tgCalls.some((c) => c.method === "sendMessage"));

  const genHandled = await handleAutomationKeyCallback(
    cfg, akCfg(), store,
    { id: "cbq-intruder-gen", fromId: INTRUDER_ID, data: "ak:gen:63", chatId: INTRUDER_ID, messageId: 1 },
    nowFixed,
  );
  check("callback от чужого обработан модулем (true), но ничего не создал", genHandled === true);
  check("НИЧЕГО не создано чужим", store.windows.size === 0, store.windows.size);

  await store.createWindow({ windowId: "owner-win", tokenHash: "hX", scope: "gmail", createdAt: nowFixed(), expiresAt: nowFixed() + 100_000, createdByChat: OWNER_CHAT_ID });
  const revokeHandled = await handleAutomationKeyCallback(
    cfg, akCfg(), store,
    { id: "cbq-intruder-revoke", fromId: INTRUDER_ID, data: "ak:revoke:owner-win", chatId: INTRUDER_ID, messageId: 1 },
    nowFixed,
  );
  check("revoke-попытка чужого обработана модулем, но не сработала", revokeHandled === true);
  const stillActive = await store.listActiveWindows(nowFixed());
  check("owner-win всё ещё активно — чужой не смог отозвать", stillActive.some((w) => w.windowId === "owner-win"));

  const textRevokeHandled = await handleAutomationKeyMessage(
    cfg, store,
    { chatId: INTRUDER_ID, fromId: INTRUDER_ID, text: "/automation_key revoke owner-win" },
    nowFixed,
  );
  check("текстовый revoke от чужого тоже не сработал", textRevokeHandled === true);
  const stillActive2 = await store.listActiveWindows(nowFixed());
  check("owner-win всё ещё активно после текстовой попытки чужого", stillActive2.some((w) => w.windowId === "owner-win"));
}

// ═══ [7] Сообщение с токеном планируется на удаление примерно через 10с ═══
console.log("\n[7] сообщение с токеном самоудаляется ~через 10с");
{
  const h = resetTelegramMocks();
  mockDefaults(h);
  const store = makeStore();
  const cfg = tgCfg();

  await handleAutomationKeyCallback(
    cfg, akCfg(), store,
    { id: "cbq-gen-del", fromId: Number(OWNER_CHAT_ID), data: "ak:gen:1", chatId: Number(OWNER_CHAT_ID), messageId: 3 },
    nowFixed,
  );
  const sentToken = tgCalls.find((c) => c.method === "sendMessage" && /🔑/.test(c.body.text));
  check("сообщение с токеном отправлено", !!sentToken);
  check("deleteMessage ЕЩЁ не вызван сразу после отправки", !tgCalls.some((c) => c.method === "deleteMessage"));

  await new Promise((resolve) => setTimeout(resolve, 10_300));
  const deleteCall = tgCalls.find((c) => c.method === "deleteMessage");
  check("deleteMessage вызван примерно через 10с", !!deleteCall, JSON.stringify(tgCalls.map((c) => c.method)));
}

// ═══ [8] Миграция схемы идемпотентна (реальная Postgres, опционально) ═══
console.log("\n[8] миграция схемы (ensureSchema) — идемпотентность + бэкафилл scope из server");
{
  const dbUrlRaw = process.env.AUTOMATION_KEY_TEST_DB_URL;
  if (!dbUrlRaw) {
    console.log("  skip  AUTOMATION_KEY_TEST_DB_URL не задан — раздел пропущен (см. README-запуск в шапке файла)");
  } else {
    // `sslmode=disable` — сигнал и для нашего локального pg.Pool ниже, И для
    // `store.ts`'s `initStore` (см. его doc-comment): большинство локальных
    // Postgres не поддерживают TLS без отдельной настройки сертификатов.
    const dbUrl = dbUrlRaw.includes("sslmode=") ? dbUrlRaw : `${dbUrlRaw}${dbUrlRaw.includes("?") ? "&" : "?"}sslmode=disable`;
    const pg = (await import("pg")).default;
    const pool = new pg.Pool({ connectionString: dbUrl, ssl: false });
    try {
      await pool.query("DROP TABLE IF EXISTS tg_automation_windows");

      // Симулируем ЛЕГАСИ-таблицу ticktick-mcp (server, БЕЗ scope) — уже в проде.
      await pool.query(`
        CREATE TABLE tg_automation_windows (
          window_id       TEXT PRIMARY KEY,
          token_hash      TEXT NOT NULL,
          server          TEXT NOT NULL,
          label           TEXT,
          created_at      BIGINT NOT NULL,
          expires_at      BIGINT NOT NULL,
          revoked_at      BIGINT,
          created_by_chat TEXT NOT NULL
        )
      `);
      await pool.query(
        `INSERT INTO tg_automation_windows (window_id, token_hash, server, created_at, expires_at, created_by_chat)
         VALUES ('legacy1', 'hashlegacy', 'ticktick', 1700000000000, 1800000000000, '555')`,
      );

      // store.ts (в отличие от automation_key.ts) НЕ самодостаточен — тянет
      // crypto.ts и т.д. через относительные `.js`-импорты, которые
      // резолвятся только в `dist/` после `npm run build` (см. комментарий
      // наверху automation_key.ts про тот же класс проблемы). `npm run test`
      // уже гоняет `npm run build` первым шагом цепочки, так что dist свежий.
      const { initStore, ensureSchema } = await import(new URL("../dist/store.js", import.meta.url));
      initStore(dbUrl, "0".repeat(64));
      await ensureSchema(); // первый прогон — должен добавить scope + забэкафилить
      await ensureSchema(); // второй прогон — идемпотентно, не должен упасть/задвоить

      const cols = await pool.query(
        `SELECT column_name FROM information_schema.columns WHERE table_name = 'tg_automation_windows'`,
      );
      const colNames = cols.rows.map((r) => r.column_name);
      check("колонка scope добавлена", colNames.includes("scope"), colNames);
      check("колонка server НЕ удалена", colNames.includes("server"), colNames);

      const legacyRow = await pool.query(`SELECT scope, server FROM tg_automation_windows WHERE window_id = 'legacy1'`);
      check("старая строка читается после миграции", legacyRow.rows.length === 1);
      check("scope забэкафиллен из server", legacyRow.rows[0]?.scope === "ticktick", legacyRow.rows[0]);

      // Второй прогон не должен был перезаписать scope на что-то другое / не
      // должен был упасть — если мы дошли досюда, ensureSchema() дважды не бросил.
      check("повторный ensureSchema() не упал (мы всё ещё тут)", true);

      // Пишем новое окно НА ТОЙ ЖЕ (легаси-формы) таблице БЕЗ `server` — ровно
      // то, что делает реальный createAutomationWindow (store.ts): он никогда
      // не заполняет `server`, потому что automation_key — мультисервисный,
      // "одного server" для него не существует. Раньше это падало бы на
      // NOT NULL constraint от легаси-схемы ticktick-mcp; ensureSchema теперь
      // снимает этот constraint (ALTER COLUMN server DROP NOT NULL) именно
      // ради этого — иначе gmail-mcp не смог бы писать НИ ОДНОГО нового окна
      // на боевой (легаси) таблице.
      await pool.query(
        `INSERT INTO tg_automation_windows (window_id, token_hash, scope, created_at, expires_at, created_by_chat)
         VALUES ('fresh-on-legacy', 'hashfresh', 'gmail,calendar', 1700000000000, 1800000000000, '555')`,
      );
      const legacyWriteRow = await pool.query(
        `SELECT scope, server FROM tg_automation_windows WHERE window_id = 'fresh-on-legacy'`,
      );
      check(
        "на легаси-таблице (после миграции) INSERT БЕЗ server теперь работает",
        legacyWriteRow.rows.length === 1 && legacyWriteRow.rows[0]?.scope === "gmail,calendar",
        legacyWriteRow.rows[0],
      );
      check("server у новой строки — NULL (никогда не заполнялся новым писателем)", legacyWriteRow.rows[0]?.server === null);

      // ── Случай Б: таблицы вообще не было (свежий gmail-mcp, ещё никто не
      // создавал tg_automation_windows) — CREATE TABLE IF NOT EXISTS должен
      // взять канонический вид ИЗ ТЗ (со scope, БЕЗ server), и запись нового
      // окна должна штатно работать без какого-либо server.
      await pool.query("DROP TABLE IF EXISTS tg_automation_windows");
      await ensureSchema();
      await ensureSchema(); // идемпотентность и на свежей таблице тоже

      const freshCols = await pool.query(
        `SELECT column_name FROM information_schema.columns WHERE table_name = 'tg_automation_windows'`,
      );
      const freshColNames = freshCols.rows.map((r) => r.column_name);
      check("на свежей таблице scope есть", freshColNames.includes("scope"), freshColNames);
      check("на свежей таблице server ОТСУТСТВУЕТ (канонический вид без легаси-столбца)", !freshColNames.includes("server"), freshColNames);

      await pool.query(
        `INSERT INTO tg_automation_windows (window_id, token_hash, scope, created_at, expires_at, created_by_chat)
         VALUES ('fresh1', 'hashfresh', 'gmail,calendar', 1700000000000, 1800000000000, '555')`,
      );
      const freshRow = await pool.query(`SELECT scope FROM tg_automation_windows WHERE window_id = 'fresh1'`);
      check("новая строка со scope пишется штатно на свежей таблице", freshRow.rows[0]?.scope === "gmail,calendar");
    } finally {
      await pool.query("DROP TABLE IF EXISTS tg_automation_windows").catch(() => {});
      await pool.end();
    }
  }
}

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
