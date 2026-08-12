#!/usr/bin/env node
/**
 * Регресс (тестовый план п.3): `AUTOMATION_KEY_MASTER_SECRET` НЕ задана —
 * `token_encrypted` не пишется, генерация/список/отзыв/смена scope
 * продолжают работать штатно, ничего не падает. Отдельный процесс от
 * `test-automation-key-manager-http.mjs` (которая, наоборот, ЗАДАЁТ мастер-
 * секрет) — `automationKeyConfig` в `server.ts` читает `process.env` один раз
 * при импорте, оба состояния в одном процессе не проверить.
 *
 * Гейтится `AUTOMATION_KEY_TEST_DB_URL`, тот же приём, что и остальные live-
 * HTTP тесты этого репозитория.
 *
 * Запуск: npm run build && AUTOMATION_KEY_TEST_DB_URL=postgres://... node scripts/test-automation-key-no-master-secret.mjs
 */
import { createHmac } from "node:crypto";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const BOT_TOKEN = "TESTTOKEN";
const OWNER_CHAT_ID = "555";

function buildInitData(userId, authDateSec) {
  const params = new URLSearchParams();
  params.set("auth_date", String(authDateSec));
  params.set("user", JSON.stringify({ id: userId, first_name: "Test" }));
  const entries = [];
  params.forEach((value, key) => entries.push(`${key}=${value}`));
  entries.sort();
  const dataCheckString = entries.join("\n");
  const secretKey = createHmac("sha256", "WebAppData").update(BOT_TOKEN).digest();
  const hash = createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
  params.set("hash", hash);
  return params.toString();
}

const dbUrlRaw = process.env.AUTOMATION_KEY_TEST_DB_URL;
if (!dbUrlRaw) {
  console.log("skip — AUTOMATION_KEY_TEST_DB_URL не задан, весь файл пропущен");
  process.exit(0);
}

process.env.TG_APPROVAL_ENABLED = "true";
process.env.TG_BOT_TOKEN = BOT_TOKEN;
process.env.TG_OWNER_CHAT_ID = OWNER_CHAT_ID;
process.env.TG_APPROVAL_WEBHOOK_SECRET = "wh-secret-xyz";
process.env.PUBLIC_BASE_URL = "http://127.0.0.1:0";
process.env.TG_WEBHOOK_OWNER = "true";
// Намеренно НЕ задаём AUTOMATION_KEY_MASTER_SECRET — это весь смысл файла.
delete process.env.AUTOMATION_KEY_MASTER_SECRET;

const { MockAgent, setGlobalDispatcher } = await import("undici");
const agent = new MockAgent();
agent.disableNetConnect();
agent.enableNetConnect(/^127\.0\.0\.1/);
setGlobalDispatcher(agent);
const tgPool = agent.get("https://api.telegram.org");
for (const method of ["sendMessage", "setWebhook", "setMyCommands", "setChatMenuButton", "deleteMessage"]) {
  tgPool
    .intercept({ path: `/bot${BOT_TOKEN}/${method}`, method: "POST" })
    .reply(() => ({ statusCode: 200, data: { ok: true, result: { message_id: 1 } }, headers: { "content-type": "application/json" } }))
    .persist();
}
let noteIdCounter = 0;
agent
  .get("https://self-destroyed-notes-production.up.railway.app")
  .intercept({ path: "/api/notes", method: "POST" })
  .reply(() => ({ statusCode: 200, data: { id: `note-${++noteIdCounter}` }, headers: { "content-type": "application/json" } }))
  .persist();

const PORT = 34918;
const BASE = `http://127.0.0.1:${PORT}`;

const dbUrl = dbUrlRaw.includes("sslmode=") ? dbUrlRaw : `${dbUrlRaw}${dbUrlRaw.includes("?") ? "&" : "?"}sslmode=disable`;
const pg = (await import("pg")).default;
const pool = new pg.Pool({ connectionString: dbUrl, ssl: false });
await pool.query("DROP TABLE IF EXISTS tg_automation_windows");

const { initStore, ensureSchema } = await import("../dist/store.js");
initStore(dbUrl, "0".repeat(64));
await ensureSchema();

const { startHttpServer } = await import("../dist/http.js");
await startHttpServer({ transport: "http", port: PORT, requireAuth: false, users: [], onboarding: { enabled: false }, sendingStuckMinutes: 10 });

function ownerInitData() {
  return buildInitData(Number(OWNER_CHAT_ID), Math.floor(Date.now() / 1000));
}
async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

console.log("\n[регресс] AUTOMATION_KEY_MASTER_SECRET не задана — фича молча выключена, всё остальное работает как раньше");
{
  const gen = await post("/automation-key-app/generate", { initData: ownerInitData(), scopeTokens: ["gmail"], durationMs: 3_600_000 });
  check("генерация окна работает как раньше (200 ok, noteLink выдан)", gen.status === 200 && gen.json.ok === true && typeof gen.json.noteLink === "string", gen);

  const row = await pool.query(`SELECT window_id, token_encrypted FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
  const windowId = row.rows[0].window_id;
  check("[план 3] token_encrypted === NULL в БД без мастер-секрета", row.rows[0].token_encrypted === null, row.rows[0]);

  const list = await post("/automation-key-app/list", { initData: ownerInitData() });
  const w = list.json.windows.find((x) => x.windowId === windowId);
  check("список работает как раньше", list.status === 200 && !!w, list.json);
  check("[план 3] hasStoredToken=false без мастер-секрета", w?.hasStoredToken === false, w);

  const reissue = await post("/automation-key-app/reissue-note", { initData: ownerInitData(), windowId });
  check(
    "[план 4] перевыпуск отказывает понятной причиной (мастер-секрет не настроен), НЕ 500",
    reissue.status === 400 && reissue.json.error === "master_secret_not_configured",
    reissue,
  );

  const scopeChange = await post("/automation-key-app/update-scope", { initData: ownerInitData(), windowId, scopeTokens: ["calendar"] });
  check("смена scope работает как раньше (не зависит от мастер-секрета)", scopeChange.status === 200 && scopeChange.json.ok === true, scopeChange);

  const revoke = await post("/automation-key-app/revoke", { initData: ownerInitData(), windowId });
  check("отзыв работает как раньше", revoke.status === 200 && revoke.json.revoked === true, revoke);
}

await pool.query("DROP TABLE IF EXISTS tg_automation_windows").catch(() => {});
await pool.end();

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
