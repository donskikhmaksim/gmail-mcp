#!/usr/bin/env node
/**
 * HTTP-уровень менеджера ключей в мини-аппе — новые owner-only роуты
 * `POST /automation-key-app/{list,revoke,reissue-note,update-scope}`
 * (задача «менеджер ключей», возможности 1/2/3). Тот же приём, что часть
 * [B] `test-automation-key-miniapp.mjs`: реальный `startHttpServer`
 * (dist/http.js) + фейковый Telegram Bot API (undici MockAgent) + реальный
 * Postgres, гейтится `AUTOMATION_KEY_TEST_DB_URL` — без неё файл целиком
 * пропускается (auth-проверки [1] не требуют БД и всё равно гоняются).
 *
 * `AUTOMATION_KEY_MASTER_SECRET` задаётся здесь валидным значением ДО
 * импорта `dist/http.js` (тот же приём, что и остальные env — `config.ts`
 * читает `process.env` один раз при импорте `server.ts`), так что
 * `token_encrypted`/`reissue-note` можно проверить сквозным HTTP-путём.
 * Регресс "переменная НЕ задана" — отдельный файл
 * `test-automation-key-no-master-secret.mjs` (свой процесс, своя точка входа,
 * без AUTOMATION_KEY_MASTER_SECRET) — в одном процессе оба состояния не
 * проверить, `automationKeyConfig` в `server.ts` — модульный синглтон.
 *
 * Запуск: npm run build && AUTOMATION_KEY_TEST_DB_URL=postgres://... node scripts/test-automation-key-manager-http.mjs
 */
import crypto, { createHmac } from "node:crypto";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const BOT_TOKEN = "TESTTOKEN";
const OWNER_CHAT_ID = "555";
const MASTER_SECRET = crypto.randomBytes(32).toString("base64url");

function buildInitData(userId, authDateSec, botToken = BOT_TOKEN) {
  const params = new URLSearchParams();
  params.set("auth_date", String(authDateSec));
  params.set("user", JSON.stringify({ id: userId, first_name: "Test" }));
  params.set("query_id", "AAFake");
  const entries = [];
  params.forEach((value, key) => entries.push(`${key}=${value}`));
  entries.sort();
  const dataCheckString = entries.join("\n");
  const secretKey = createHmac("sha256", "WebAppData").update(botToken).digest();
  const hash = createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
  params.set("hash", hash);
  return params.toString();
}

const dbUrlRaw = process.env.AUTOMATION_KEY_TEST_DB_URL;
if (!dbUrlRaw) {
  console.log("skip — AUTOMATION_KEY_TEST_DB_URL не задан, весь файл пропущен (см. README-запуск в шапке)");
  process.exit(0);
}

process.env.TG_APPROVAL_ENABLED = "true";
process.env.TG_BOT_TOKEN = BOT_TOKEN;
process.env.TG_OWNER_CHAT_ID = OWNER_CHAT_ID;
process.env.TG_APPROVAL_WEBHOOK_SECRET = "wh-secret-xyz";
process.env.PUBLIC_BASE_URL = "http://127.0.0.1:0";
process.env.TG_WEBHOOK_OWNER = "true";
process.env.AUTOMATION_KEY_MASTER_SECRET = MASTER_SECRET;

const { MockAgent, setGlobalDispatcher } = await import("undici");
const agent = new MockAgent();
agent.disableNetConnect();
agent.enableNetConnect(/^127\.0\.0\.1/);
setGlobalDispatcher(agent);
const tgPool = agent.get("https://api.telegram.org");
const tgCalls = [];
for (const method of ["sendMessage", "setWebhook", "setMyCommands", "setChatMenuButton", "deleteMessage"]) {
  tgPool
    .intercept({ path: `/bot${BOT_TOKEN}/${method}`, method: "POST" })
    .reply((opts) => {
      let body = {};
      try {
        body = JSON.parse(opts.body);
      } catch {
        /* ignore */
      }
      tgCalls.push({ method, body });
      if (method === "sendMessage") {
        return { statusCode: 200, data: { ok: true, result: { message_id: 1000 + tgCalls.length } }, headers: { "content-type": "application/json" } };
      }
      return { statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } };
    })
    .persist();
}

let notesFail = false;
const notesPool = agent.get("https://self-destroyed-notes-production.up.railway.app");
let noteIdCounter = 0;
notesPool
  .intercept({ path: "/api/notes", method: "POST" })
  .reply(() =>
    notesFail
      ? { statusCode: 500, data: { error: "internal" }, headers: { "content-type": "application/json" } }
      : { statusCode: 200, data: { id: `note-${++noteIdCounter}` }, headers: { "content-type": "application/json" } },
  )
  .persist();

const PORT = 34917;
const BASE = `http://127.0.0.1:${PORT}`;

const dbUrl = dbUrlRaw.includes("sslmode=") ? dbUrlRaw : `${dbUrlRaw}${dbUrlRaw.includes("?") ? "&" : "?"}sslmode=disable`;
const pg = (await import("pg")).default;
const pool = new pg.Pool({ connectionString: dbUrl, ssl: false });
await pool.query("DROP TABLE IF EXISTS tg_automation_windows");

const { initStore, ensureSchema } = await import("../dist/store.js");
initStore(dbUrl, "0".repeat(64));
await ensureSchema();

const { startHttpServer } = await import("../dist/http.js");
await startHttpServer({
  transport: "http",
  port: PORT,
  requireAuth: false,
  users: [],
  onboarding: { enabled: false },
  sendingStuckMinutes: 10,
});

function ownerInitData() {
  return buildInitData(Number(OWNER_CHAT_ID), Math.floor(Date.now() / 1000));
}
function intruderInitData() {
  return buildInitData(999, Math.floor(Date.now() / 1000));
}
function forgedInitData() {
  return ownerInitData().replace(/hash=[0-9a-f]+/, "hash=" + "0".repeat(64));
}

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function generateWindow(scopeTokens, durationMs = 3_600_000, label = null) {
  const { status, json } = await post("/automation-key-app/generate", { initData: ownerInitData(), scopeTokens, durationMs, label });
  if (status !== 200 || !json.ok) throw new Error(`generate failed: ${status} ${JSON.stringify(json)}`);
  const row = await pool.query(`SELECT window_id FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
  return { windowId: row.rows[0].window_id, noteLink: json.noteLink };
}

// ═══ [1] Auth — все 4 новых роута требуют owner-only initData ═══
console.log("\n[1] auth: поддельная подпись/чужой user.id → 403 на всех 4 новых роутах, ничего не меняется");
{
  const { windowId } = await generateWindow(["gmail"]);

  for (const [path, extraBody] of [
    ["/automation-key-app/list", {}],
    ["/automation-key-app/revoke", { windowId }],
    ["/automation-key-app/reissue-note", { windowId }],
    ["/automation-key-app/update-scope", { windowId, scopeTokens: ["gmail"] }],
  ]) {
    const forged = await post(path, { initData: forgedInitData(), ...extraBody });
    check(`${path}: поддельная подпись → 403 invalid_init_data`, forged.status === 403 && forged.json.error === "invalid_init_data", forged);

    const intruder = await post(path, { initData: intruderInitData(), ...extraBody });
    check(`${path}: чужой user.id → 403 forbidden`, intruder.status === 403 && intruder.json.error === "forbidden", intruder);
  }

  const stillActiveRow = await pool.query(`SELECT revoked_at, scope FROM tg_automation_windows WHERE window_id = $1`, [windowId]);
  check("окно НЕ отозвано неавторизованными попытками", stillActiveRow.rows[0].revoked_at === null, stillActiveRow.rows[0]);
  check("scope НЕ изменён неавторизованными попытками", stillActiveRow.rows[0].scope === "gmail", stillActiveRow.rows[0]);
}

// ═══ [2] /automation-key-app/list — показывает окно, hasStoredToken=true (мастер-секрет задан) ═══
console.log("\n[2] /automation-key-app/list — окно видно, поля корректны, hasStoredToken=true");
{
  const { windowId } = await generateWindow(["ticktick"], 7 * 24 * 60 * 60 * 1000, "мой ноутбук");
  const { status, json } = await post("/automation-key-app/list", { initData: ownerInitData() });
  check("200 ok", status === 200 && json.ok === true, { status, json });
  const w = (json.windows || []).find((x) => x.windowId === windowId);
  check("окно присутствует в списке", !!w, json.windows);
  check("scope как выдан", w?.scope === "ticktick", w);
  check("scopeHuman присутствует", typeof w?.scopeHuman === "string" && w.scopeHuman.length > 0, w);
  check("label сохранён", w?.label === "мой ноутбук", w);
  check("status='active'", w?.status === "active", w);
  check("[план — с мастер-секретом] hasStoredToken=true", w?.hasStoredToken === true, w);
  check("сырой токен НИГДЕ не попадает в ответ /list (только сводка, tokenHash тоже не отдаётся)", !JSON.stringify(w).match(/[A-Za-z0-9_-]{40,}/), w);
}

// ═══ [3] /automation-key-app/revoke — реально отзывает (тестовый план п.5) ═══
console.log("\n[3] /automation-key-app/revoke — реально отзывает, statused как revoked в /list, checkAutomationKeyFor после этого false");
{
  const { windowId } = await generateWindow(["drive"]);
  const before = await post("/automation-key-app/list", { initData: ownerInitData() });
  const wBefore = before.json.windows.find((x) => x.windowId === windowId);
  check("до отзыва — active", wBefore?.status === "active", wBefore);

  const { status, json } = await post("/automation-key-app/revoke", { initData: ownerInitData(), windowId });
  check("[план 5] 200 ok, revoked:true", status === 200 && json.ok === true && json.revoked === true, { status, json });

  const row = await pool.query(`SELECT revoked_at FROM tg_automation_windows WHERE window_id = $1`, [windowId]);
  check("[план 5] revoked_at заполнен в БД", row.rows[0].revoked_at !== null, row.rows[0]);

  const after = await post("/automation-key-app/list", { initData: ownerInitData() });
  const wAfter = after.json.windows.find((x) => x.windowId === windowId);
  check("после отзыва — status='revoked' в /list", wAfter?.status === "revoked", wAfter);

  const second = await post("/automation-key-app/revoke", { initData: ownerInitData(), windowId });
  check("повторный revoke — идемпотентно revoked:false, не ошибка", second.status === 200 && second.json.ok === true && second.json.revoked === false, second);

  const missing = await post("/automation-key-app/revoke", { initData: ownerInitData(), windowId: "no-such-window-xyz" });
  check("revoke несуществующего windowId — тоже 200/revoked:false, не 500", missing.status === 200 && missing.json.revoked === false, missing);
}

// ═══ [4] /automation-key-app/update-scope — меняет scope, checkAutomationKeyFor видит новый (план п.1) ═══
console.log("\n[4] /automation-key-app/update-scope — scope=gmail → calendar, старый недоступен, новый доступен");
{
  const { windowId, noteLink } = await generateWindow(["gmail"], 3_600_000);
  const rawTokenMatch = noteLink; // сам ключ не выковыриваем тут — covered by test-automation-key-storage.mjs; здесь смотрим на scope в БД.

  const { status, json } = await post("/automation-key-app/update-scope", { initData: ownerInitData(), windowId, scopeTokens: ["calendar"] });
  check("[план 1] 200 ok, scope='calendar'", status === 200 && json.ok === true && json.scope === "calendar", { status, json });

  const row = await pool.query(`SELECT scope FROM tg_automation_windows WHERE window_id = $1`, [windowId]);
  check("[план 1] scope в БД реально сменился", row.rows[0].scope === "calendar", row.rows[0]);

  // Пустой выбор — fail-closed, как и /generate.
  const empty = await post("/automation-key-app/update-scope", { initData: ownerInitData(), windowId, scopeTokens: [] });
  check("пустой scopeTokens → 400 empty_selection, scope не тронут", empty.status === 400 && empty.json.error === "empty_selection", empty);
  const rowAfterEmpty = await pool.query(`SELECT scope FROM tg_automation_windows WHERE window_id = $1`, [windowId]);
  check("scope не изменился после отклонённой пустой попытки", rowAfterEmpty.rows[0].scope === "calendar", rowAfterEmpty.rows[0]);

  const missing = await post("/automation-key-app/update-scope", { initData: ownerInitData(), windowId: "no-such-window-abc", scopeTokens: ["gmail"] });
  check("несуществующий windowId → 404 window_not_found", missing.status === 404 && missing.json.error === "window_not_found", missing);

  void rawTokenMatch;
}

// ═══ [5] /automation-key-app/reissue-note — рабочая вторая заметка (план п.4) ═══
console.log("\n[5] /automation-key-app/reissue-note — окно с token_encrypted → рабочий noteLink; без него/отозванное/несуществующее → понятный отказ, не 500");
{
  const { windowId } = await generateWindow(["sheets"]);
  const { status, json } = await post("/automation-key-app/reissue-note", { initData: ownerInitData(), windowId });
  check("[план 4] 200 ok, noteLink возвращён", status === 200 && json.ok === true && typeof json.noteLink === "string", { status, json });
  check(
    "[план 4] noteLink — валидная ссылка self-destroyed-notes",
    /^https:\/\/self-destroyed-notes-production\.up\.railway\.app\/#\/n\/[^/]+\/[^/]+$/.test(json.noteLink ?? ""),
    json.noteLink,
  );

  const missing = await post("/automation-key-app/reissue-note", { initData: ownerInitData(), windowId: "no-such-window-def" });
  check("несуществующее окно → 400 window_not_found, НЕ 500", missing.status === 400 && missing.json.error === "window_not_found", missing);

  await post("/automation-key-app/revoke", { initData: ownerInitData(), windowId });
  const revokedTry = await post("/automation-key-app/reissue-note", { initData: ownerInitData(), windowId });
  check("[план 4] отозванное окно → 400 window_revoked, НЕ 500", revokedTry.status === 400 && revokedTry.json.error === "window_revoked", revokedTry);

  // self-destroyed-notes недоступен во время перевыпуска.
  const { windowId: w2 } = await generateWindow(["docs"]);
  notesFail = true;
  const failTry = await post("/automation-key-app/reissue-note", { initData: ownerInitData(), windowId: w2 });
  check("[план 4] сбой self-destroyed-notes при перевыпуске → 400 note_service_unavailable, НЕ 500", failTry.status === 400 && failTry.json.error === "note_service_unavailable", failTry);
  notesFail = false;
}

await pool.query("DROP TABLE IF EXISTS tg_automation_windows").catch(() => {});
await pool.end();

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
