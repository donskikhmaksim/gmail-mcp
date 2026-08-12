#!/usr/bin/env node
/**
 * Offline тест Telegram Mini App для `automation_key`
 * (`src/automation_key_miniapp.ts` + `POST/GET /automation-key-app*` в
 * `src/http.ts`). Spec: `docs/TZ_automation_key_miniapp.md`, тестовый план
 * (8 пунктов).
 *
 * Часть [A] — чистый unit-тест `verifyTelegramInitData` (алгоритм
 * HMAC-подписи + свежесть `auth_date`), без сети и без HTTP-сервера.
 *
 * Часть [B] — реальный `startHttpServer` (dist/http.js, как test-dl-headers.mjs
 * делает для `/dl/:token`) с фейковым Telegram Bot API (undici MockAgent —
 * тот же приём, что test-tg-webhook-gate.mjs). Env (TG_BOT_TOKEN,
 * TG_OWNER_CHAT_ID, ...) задаётся ДО импорта dist/http.js, потому что
 * tgApprovalConfig — модульный синглтон, читающий process.env один раз при
 * импорте `server.ts` (тот же факт зафиксирован в шапке
 * test-tg-webhook-gate.mjs). Проверки 1/2/3/6/8 (подделанная подпись, чужой
 * user.id, протухший auth_date, пустой выбор, GET без авторизации) НЕ трогают
 * Postgres — `generateAndDeliverKey` возвращает `null`/кидает исключение
 * ДО первого обращения к store.createWindow, так что они работают всегда.
 * Проверки 4/5/7 (реальная запись окна + доставка ключа сообщением) требуют
 * настоящий Postgres — гейтятся `AUTOMATION_KEY_TEST_DB_URL`, тем же приёмом,
 * что раздел [8] в test-automation-key.mjs; без него секция молча
 * пропускается.
 *
 * Запуск: npm run build && node scripts/test-automation-key-miniapp.mjs
 *   (для [4]/[5]/[7]: AUTOMATION_KEY_TEST_DB_URL=postgres://... node scripts/test-automation-key-miniapp.mjs)
 */
import { createHmac } from "node:crypto";
import { verifyTelegramInitData, renderAutomationKeyMiniAppPage } from "../dist/automation_key_miniapp.js";
import { isValidDurationMs } from "../dist/automation_key.js";
import { loadExternalCatalogUrls } from "../dist/config.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const BOT_TOKEN = "TESTTOKEN";
const OWNER_CHAT_ID = "555";

/** Строит валидный `initData` по тому же алгоритму, что и сам модуль (нужно
 * для теста "нормального" пути) — независимая реализация здесь была бы
 * бессмысленна (просто копия), так что это ЭТАЛОННАЯ реализация ИЗ ТЗ,
 * которую verifyTelegramInitData обязана распознать как валидную. */
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

const nowMs = 1_700_000_000_000;
const now = () => nowMs;

// ═══ [A] verifyTelegramInitData — unit ═══
console.log("\n[A] verifyTelegramInitData — подпись/свежесть/владелец");
{
  const authDateSec = Math.floor(nowMs / 1000);
  const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);

  const okResult = verifyTelegramInitData(BOT_TOKEN, valid, now);
  check("валидный initData → ok:true", okResult.ok === true, JSON.stringify(okResult));
  check("userId извлечён правильно", okResult.ok && okResult.userId === OWNER_CHAT_ID, okResult);

  // [1] Поддельная/испорченная подпись.
  const tampered = valid.replace(/hash=[0-9a-f]+/, "hash=" + "0".repeat(64));
  const badSig = verifyTelegramInitData(BOT_TOKEN, tampered, now);
  check("[план 1] поддельный hash → ok:false", badSig.ok === false, JSON.stringify(badSig));
  check("[план 1] причина bad_signature", !badSig.ok && badSig.reason === "bad_signature", badSig);

  // Изменённое поле (user.id подделан) при старом hash — тоже должно провалиться.
  const forgedUser = valid.replace(/user=[^&]+/, "user=" + encodeURIComponent(JSON.stringify({ id: 999 })));
  const forgedResult = verifyTelegramInitData(BOT_TOKEN, forgedUser, now);
  check("подделанное поле user (hash не пересчитан) → ok:false", forgedResult.ok === false, forgedResult);

  // [3] auth_date протух (> 5 минут).
  const staleAuthDate = authDateSec - 6 * 60; // 6 минут назад
  const stale = buildInitData(Number(OWNER_CHAT_ID), staleAuthDate);
  const staleResult = verifyTelegramInitData(BOT_TOKEN, stale, now);
  check("[план 3] auth_date старше 5 минут → ok:false", staleResult.ok === false, staleResult);
  check("[план 3] причина stale", !staleResult.ok && staleResult.reason === "stale", staleResult);

  // Свежий (в пределах окна) — должен пройти.
  const freshAuthDate = authDateSec - 60; // 1 минута назад
  const fresh = buildInitData(Number(OWNER_CHAT_ID), freshAuthDate);
  const freshResult = verifyTelegramInitData(BOT_TOKEN, fresh, now);
  check("auth_date 1 минуту назад — ещё свежий → ok:true", freshResult.ok === true, freshResult);

  // Неправильный бот-токен (подпись, посчитанная другим ключом) — тоже bad_signature.
  const wrongBotToken = buildInitData(Number(OWNER_CHAT_ID), authDateSec, "OTHER_BOT_TOKEN");
  const wrongBotResult = verifyTelegramInitData(BOT_TOKEN, wrongBotToken, now);
  check("initData подписан ДРУГИМ токеном бота → ok:false", wrongBotResult.ok === false, wrongBotResult);

  // Отсутствующий/пустой initData — fail closed.
  const emptyResult = verifyTelegramInitData(BOT_TOKEN, "", now);
  check("пустой initData → ok:false (missing)", !emptyResult.ok && emptyResult.reason === "missing", emptyResult);

  // [2] Подпись валидна, но user.id принадлежит НЕ владельцу — по спецификации
  // verifyTelegramInitData сама не решает owner-only (это работа вызывающего
  // http.ts кода), но обязана честно вернуть userId интрудера, чтобы
  // вызывающий код мог его отклонить.
  const intruderInitData = buildInitData(999, authDateSec);
  const intruderResult = verifyTelegramInitData(BOT_TOKEN, intruderInitData, now);
  check("[план 2] подпись интрудера валидна (сама по себе)", intruderResult.ok === true, intruderResult);
  check("[план 2] но userId — НЕ владелец", intruderResult.ok && intruderResult.userId !== OWNER_CHAT_ID, intruderResult);
}

// ═══ [A-bis] isValidDurationMs — unit (docs/TZ_automation_key_duration_labels.md раздел 1) ═══
console.log("\n[A-bis] isValidDurationMs — прямой unit-тест (в обход JSON-сериализации, которая NaN/Infinity превращает в null)");
{
  check("положительное конечное число — валидно", isValidDurationMs(3 * 60 * 60 * 1000) === true);
  check("0 — НЕ валидно", isValidDurationMs(0) === false);
  check("отрицательное — НЕ валидно", isValidDurationMs(-1) === false);
  check("NaN — НЕ валидно", isValidDurationMs(NaN) === false);
  check("Infinity — НЕ валидно", isValidDurationMs(Infinity) === false);
  check("строка — НЕ валидно", isValidDurationMs("3600000") === false);
  check("null сам по себе НЕ проходит isValidDurationMs (вызывающий код проверяет null отдельно)", isValidDurationMs(null) === false);
}

// ═══ [B] реальный HTTP-роут ═══
process.env.TG_APPROVAL_ENABLED = "true";
process.env.TG_BOT_TOKEN = BOT_TOKEN;
process.env.TG_OWNER_CHAT_ID = OWNER_CHAT_ID;
process.env.TG_APPROVAL_WEBHOOK_SECRET = "wh-secret-xyz";
process.env.PUBLIC_BASE_URL = "http://127.0.0.1:0"; // переопределяется портом ниже, просто чтобы loadTgApprovalConfig не упал на старте
process.env.TG_WEBHOOK_OWNER = "true";

const { MockAgent, setGlobalDispatcher } = await import("undici");
const agent = new MockAgent();
agent.disableNetConnect();
agent.enableNetConnect(/^127\.0\.0\.1/);
setGlobalDispatcher(agent);
const tgPool = agent.get("https://api.telegram.org");
const tgCalls = [];
for (const method of ["sendMessage", "setWebhook", "setMyCommands", "setChatMenuButton"]) {
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
        return {
          statusCode: 200,
          data: { ok: true, result: { message_id: 1000 + tgCalls.length } },
          headers: { "content-type": "application/json" },
        };
      }
      return { statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } };
    })
    .persist();
}

// self-destroyed-notes (docs/TZ_automation_key_note_delivery_and_buttons.md
// раздел 1) — тот же приём, что и в test-automation-key.mjs: `/api/notes`
// замокан отдельным pool'ом на другом хосте, возвращает растущий `id`.
const notesPool = agent.get("https://self-destroyed-notes-production.up.railway.app");
let noteIdCounter = 0;
notesPool
  .intercept({ path: "/api/notes", method: "POST" })
  .reply(() => ({
    statusCode: 200,
    data: { id: `note-${++noteIdCounter}` },
    headers: { "content-type": "application/json" },
  }))
  .persist();

const PORT = 34913;
const BASE = `http://127.0.0.1:${PORT}`;

const { startHttpServer } = await import("../dist/http.js");
await startHttpServer({
  transport: "http",
  port: PORT,
  requireAuth: false,
  users: [],
  onboarding: { enabled: false },
  sendingStuckMinutes: 10,
});

console.log("\n[8] GET /automation-key-app — без авторизации, 200 OK");
{
  const res = await fetch(`${BASE}/automation-key-app`);
  const html = await res.text();
  check("200 OK", res.status === 200, res.status);
  check("Content-Type html", (res.headers.get("content-type") ?? "").includes("html"), res.headers.get("content-type"));
  check("страница содержит telegram-web-app.js", html.includes("telegram-web-app.js"));
  check("страница содержит все 6 чекбоксов сервисов", ["gmail", "calendar", "drive", "sheets", "docs", "ticktick"].every((s) => html.includes(`value="${s}"`)), "missing checkbox");
  check("страница содержит чекбокс «Все сразу»", html.includes('id="all"'));
  check("страница содержит кнопку «Получить ключ»", html.includes("Получить ключ"));
  check(
    "статичный рендер (renderAutomationKeyMiniAppPage) и HTTP-ответ совпадают",
    html === renderAutomationKeyMiniAppPage(loadExternalCatalogUrls()),
  );
}

async function postGenerate(body) {
  const res = await fetch(`${BASE}/automation-key-app/generate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

console.log("\n[1] POST с поддельным hash → 403, ничего не создано, tgCalls пуст");
{
  const authDateSec = Math.floor(nowMs / 1000);
  const forged = buildInitData(Number(OWNER_CHAT_ID), authDateSec).replace(/hash=[0-9a-f]+/, "hash=" + "0".repeat(64));
  const before = tgCalls.length;
  const { status, json } = await postGenerate({ initData: forged, scopeTokens: ["gmail"] });
  check("403", status === 403, status);
  check("error: invalid_init_data", json.error === "invalid_init_data", json);
  check("ни одного нового вызова Telegram API (sendMessage/setWebhook)", tgCalls.length === before, tgCalls.length - before);
}

console.log("\n[2] POST с валидным initData, но чужим user.id → 403, ничего не отправлено");
{
  const authDateSec = Math.floor(Date.now() / 1000); // реальное текущее время — проверка идёт по Date.now() внутри роута
  const intruderInitData = buildInitData(999, authDateSec);
  const before = tgCalls.length;
  const { status, json } = await postGenerate({ initData: intruderInitData, scopeTokens: ["gmail"] });
  check("403", status === 403, status);
  check("error: forbidden", json.error === "forbidden", json);
  check("ничего не отправлено интрудеру", tgCalls.length === before, tgCalls.length - before);
}

console.log("\n[3] POST с протухшим auth_date (владелец, но > 5 минут назад) → 403");
{
  const staleAuthDate = Math.floor(Date.now() / 1000) - 10 * 60; // 10 минут назад
  const stale = buildInitData(Number(OWNER_CHAT_ID), staleAuthDate);
  const before = tgCalls.length;
  const { status, json } = await postGenerate({ initData: stale, scopeTokens: ["gmail"] });
  check("403", status === 403, status);
  check("error: invalid_init_data", json.error === "invalid_init_data", json);
  check("ничего не отправлено", tgCalls.length === before, tgCalls.length - before);
}

console.log('\n[6] POST от владельца с ПУСТЫМ выбором → 400, ничего не отправлено (backend, не только фронтенд)');
{
  const authDateSec = Math.floor(Date.now() / 1000);
  const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);
  const before = tgCalls.length;
  // durationMs валиден (3ч) — проверяем именно empty_selection, не путаем с валидацией срока.
  const { status, json } = await postGenerate({ initData: valid, scopeTokens: [], durationMs: 3 * 60 * 60 * 1000 });
  check("400", status === 400, status);
  check("error: empty_selection", json.error === "empty_selection", json);
  check("ничего не отправлено", tgCalls.length === before, tgCalls.length - before);

  // Тот же случай, но поле scopeTokens вообще отсутствует в теле — тоже fail-closed.
  const before2 = tgCalls.length;
  const { status: status2 } = await postGenerate({ initData: valid, durationMs: 3 * 60 * 60 * 1000 });
  check("scopeTokens отсутствует в теле → тоже 400", status2 === 400, status2);
  check("ничего не отправлено (2)", tgCalls.length === before2, tgCalls.length - before2);
}

// ═══ Раздел 1 ТЗ-аддендума (docs/TZ_automation_key_duration_labels.md): backend-валидация durationMs ═══
console.log("\n[7] POST с некорректным durationMs (0/отрицательное/строка/отсутствует) → 400 invalid_duration, ничего не отправлено; durationMs=null валиден сам по себе");
{
  const authDateSec = Math.floor(Date.now() / 1000);
  const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);

  // NaN/Infinity намеренно не тестируются здесь: JSON.stringify сериализует
  // оба в `null` (JSON не умеет их выражать), так что по HTTP они бы всё
  // равно пришли как `null` (валидное "бессрочно"), а не как экзотический
  // невалидный `number` — isValidDurationMs() сам по себе (unit) уже
  // проверяет их отдельно через прямой вызов, не через сериализацию.
  for (const [label, rawDuration] of [
    ["0", 0],
    ["отрицательное", -1000],
    ["строка", "3h"],
  ]) {
    const before = tgCalls.length;
    const { status, json } = await postGenerate({ initData: valid, scopeTokens: ["gmail"], durationMs: rawDuration });
    check(`[план — валидация durationMs] durationMs=${label} → 400 invalid_duration`, status === 400 && json.error === "invalid_duration", { status, json });
    check(`ничего не отправлено (durationMs=${label})`, tgCalls.length === before, tgCalls.length - before);
  }

  // Поле durationMs вообще отсутствует в теле — тоже отклоняется, не тихий дефолт.
  const beforeMissing = tgCalls.length;
  const { status: statusMissing, json: jsonMissing } = await postGenerate({ initData: valid, scopeTokens: ["gmail"] });
  check("durationMs отсутствует в теле → 400 invalid_duration (backend НЕ подставляет тихий дефолт)", statusMissing === 400 && jsonMissing.error === "invalid_duration", { statusMissing, jsonMissing });
  check("ничего не отправлено (durationMs отсутствует)", tgCalls.length === beforeMissing, tgCalls.length - beforeMissing);

  // durationMs=null (бессрочно) — валиден САМ ПО СЕБЕ: с пустым scopeTokens запрос
  // доходит до empty_selection, а НЕ invalid_duration — доказывает, что null
  // прошёл валидацию длительности.
  const beforeNull = tgCalls.length;
  const { status: statusNull, json: jsonNull } = await postGenerate({ initData: valid, scopeTokens: [], durationMs: null });
  check("[план 1] durationMs=null проходит валидацию (падает на empty_selection, не invalid_duration)", statusNull === 400 && jsonNull.error === "empty_selection", { statusNull, jsonNull });
  check("ничего не отправлено (durationMs=null, пустой выбор)", tgCalls.length === beforeNull, tgCalls.length - beforeNull);
}

// ═══ [4]/[5]/[7] — реальная запись окна + доставка ключа (нужен Postgres) ═══
console.log("\n[4]/[5]/[7] валидный запрос владельца → окно создано, ключ доставлен сообщением (нужен AUTOMATION_KEY_TEST_DB_URL)");
{
  const dbUrlRaw = process.env.AUTOMATION_KEY_TEST_DB_URL;
  if (!dbUrlRaw) {
    console.log("  skip  AUTOMATION_KEY_TEST_DB_URL не задан — секция пропущена (см. README-запуск в шапке файла)");
  } else {
    const dbUrl = dbUrlRaw.includes("sslmode=") ? dbUrlRaw : `${dbUrlRaw}${dbUrlRaw.includes("?") ? "&" : "?"}sslmode=disable`;
    const pg = (await import("pg")).default;
    const pool = new pg.Pool({ connectionString: dbUrl, ssl: false });
    try {
      await pool.query("DROP TABLE IF EXISTS tg_automation_windows");
      const { initStore, ensureSchema } = await import("../dist/store.js");
      initStore(dbUrl, "0".repeat(64));
      await ensureSchema();

      // ── [4] один отмеченный сервис, конкретный срок (7 дней) → scope = это имя, expires_at = created_at + 7д ──
      {
        const authDateSec = Math.floor(Date.now() / 1000);
        const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);
        const sendMessageBefore = tgCalls.filter((c) => c.method === "sendMessage").length;
        const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
        const { status, json } = await postGenerate({ initData: valid, scopeTokens: ["ticktick"], durationMs: SEVEN_DAYS_MS });
        check("[план 4] 200 ok", status === 200 && json.ok === true, JSON.stringify({ status, json }));
        check(
          "[план 7] ровно один новый tgCall (sendMessage)",
          tgCalls.filter((c) => c.method === "sendMessage").length === sendMessageBefore + 1,
          tgCalls.filter((c) => c.method === "sendMessage").length - sendMessageBefore,
        );
        const sent = tgCalls.filter((c) => c.method === "sendMessage").at(-1);
        check("[план 7] это именно sendMessage с 🔑", sent.method === "sendMessage" && /🔑/.test(sent.body.text ?? ""), sent);
        // ТЗ раздел 1 "Мини-апп": ответ backend'а несёт ссылку на self-destruct-заметку
        // (страница показывает её напрямую), не сырой токен — ни в чате, ни в HTTP-ответе.
        check("[план 2] сырой токен НЕ попадает в тело HTTP-ответа, только ok+noteLink", Object.keys(json).sort().join(",") === "noteLink,ok", JSON.stringify(json));
        check(
          "[план 2] noteLink — ссылка на self-destroyed-notes /#/n/<id>/<key>",
          typeof json.noteLink === "string" && /^https:\/\/self-destroyed-notes-production\.up\.railway\.app\/#\/n\/[^/]+\/[^/]+$/.test(json.noteLink),
          json.noteLink,
        );
        check("[план 1] сообщение в чате несёт ту же ссылку, что и HTTP-ответ", sent.body.text.includes(json.noteLink), { text: sent.body.text, noteLink: json.noteLink });

        const row = await pool.query(`SELECT scope, created_at, expires_at FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 4] окно в БД с scope='ticktick'", row.rows[0]?.scope === "ticktick", row.rows[0]);
        check(
          "[план 2 ТЗ-аддендума] expires_at = created_at + 7 дней (в мс)",
          Number(row.rows[0]?.expires_at) === Number(row.rows[0]?.created_at) + SEVEN_DAYS_MS,
          row.rows[0],
        );
      }

      // ── [5] «Все сразу» (все 6 сервисов отмечены), durationMs=null → scope = 'all', expires_at IS NULL (тестовый план п.1) ──
      {
        const authDateSec = Math.floor(Date.now() / 1000);
        const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);
        const { status, json } = await postGenerate({
          initData: valid,
          scopeTokens: ["gmail", "calendar", "drive", "sheets", "docs", "ticktick"],
          durationMs: null,
        });
        check("[план 5] 200 ok", status === 200 && json.ok === true, JSON.stringify({ status, json }));
        const row = await pool.query(`SELECT scope, expires_at FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 5] scope === 'all'", row.rows[0]?.scope === "all", row.rows[0]);
        check("[план 1] durationMs=null → expires_at IS NULL в БД", row.rows[0]?.expires_at === null, row.rows[0]);
      }

      // ── Раздел 2 ТЗ-аддендума: label — пустая строка → NULL, заполненная → сохраняется (тестовый план п.4) ──
      {
        const authDateSec = Math.floor(Date.now() / 1000);
        const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);

        // Пустая строка (и строка из одних пробелов) → NULL.
        await postGenerate({ initData: valid, scopeTokens: ["gmail"], durationMs: 3_600_000, label: "" });
        const emptyLabelRow = await pool.query(`SELECT label FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 4] пустая строка label → NULL в БД", emptyLabelRow.rows[0]?.label === null, emptyLabelRow.rows[0]);

        await postGenerate({ initData: valid, scopeTokens: ["gmail"], durationMs: 3_600_000, label: "   " });
        const blankLabelRow = await pool.query(`SELECT label FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 4] label из одних пробелов → NULL в БД (trim)", blankLabelRow.rows[0]?.label === null, blankLabelRow.rows[0]);

        // label отсутствует в теле вовсе → тоже NULL (как раньше, поле необязательное).
        await postGenerate({ initData: valid, scopeTokens: ["gmail"], durationMs: 3_600_000 });
        const missingLabelRow = await pool.query(`SELECT label FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 4] label отсутствует в теле → NULL в БД", missingLabelRow.rows[0]?.label === null, missingLabelRow.rows[0]);

        // Заполненная строка — сохраняется как есть (после trim).
        await postGenerate({ initData: valid, scopeTokens: ["gmail"], durationMs: 3_600_000, label: "  рабочий ноутбук  " });
        const filledLabelRow = await pool.query(`SELECT label FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 4] заполненный label сохраняется (обрезанный по краям)", filledLabelRow.rows[0]?.label === "рабочий ноутбук", filledLabelRow.rows[0]);
      }

      // ── [7] deleteMessage планируется, но не сразу (тот же механизм, что кнопочная версия — уже покрыт test-automation-key.mjs #7 напрямую на generateAndDeliverKey; здесь достаточно факта, что сырой токен ушёл СООБЩЕНИЕМ, проверено выше) ──
    } finally {
      await pool.query("DROP TABLE IF EXISTS tg_automation_windows").catch(() => {});
      await pool.end();
    }
  }
}

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
