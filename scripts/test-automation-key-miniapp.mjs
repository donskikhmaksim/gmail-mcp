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
for (const method of ["sendMessage", "setWebhook"]) {
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
  check("статичный рендер (renderAutomationKeyMiniAppPage) и HTTP-ответ совпадают", html === renderAutomationKeyMiniAppPage());
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
  const { status, json } = await postGenerate({ initData: forged, services: ["gmail"] });
  check("403", status === 403, status);
  check("error: invalid_init_data", json.error === "invalid_init_data", json);
  check("ни одного нового вызова Telegram API (sendMessage/setWebhook)", tgCalls.length === before, tgCalls.length - before);
}

console.log("\n[2] POST с валидным initData, но чужим user.id → 403, ничего не отправлено");
{
  const authDateSec = Math.floor(Date.now() / 1000); // реальное текущее время — проверка идёт по Date.now() внутри роута
  const intruderInitData = buildInitData(999, authDateSec);
  const before = tgCalls.length;
  const { status, json } = await postGenerate({ initData: intruderInitData, services: ["gmail"] });
  check("403", status === 403, status);
  check("error: forbidden", json.error === "forbidden", json);
  check("ничего не отправлено интрудеру", tgCalls.length === before, tgCalls.length - before);
}

console.log("\n[3] POST с протухшим auth_date (владелец, но > 5 минут назад) → 403");
{
  const staleAuthDate = Math.floor(Date.now() / 1000) - 10 * 60; // 10 минут назад
  const stale = buildInitData(Number(OWNER_CHAT_ID), staleAuthDate);
  const before = tgCalls.length;
  const { status, json } = await postGenerate({ initData: stale, services: ["gmail"] });
  check("403", status === 403, status);
  check("error: invalid_init_data", json.error === "invalid_init_data", json);
  check("ничего не отправлено", tgCalls.length === before, tgCalls.length - before);
}

console.log('\n[6] POST от владельца с ПУСТЫМ выбором → 400, ничего не отправлено (backend, не только фронтенд)');
{
  const authDateSec = Math.floor(Date.now() / 1000);
  const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);
  const before = tgCalls.length;
  const { status, json } = await postGenerate({ initData: valid, services: [] });
  check("400", status === 400, status);
  check("error: empty_selection", json.error === "empty_selection", json);
  check("ничего не отправлено", tgCalls.length === before, tgCalls.length - before);

  // Тот же случай, но поле services вообще отсутствует в теле — тоже fail-closed.
  const before2 = tgCalls.length;
  const { status: status2 } = await postGenerate({ initData: valid });
  check("services отсутствует в теле → тоже 400", status2 === 400, status2);
  check("ничего не отправлено (2)", tgCalls.length === before2, tgCalls.length - before2);
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

      // ── [4] один отмеченный сервис → scope = это имя ──
      {
        const authDateSec = Math.floor(Date.now() / 1000);
        const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);
        const before = tgCalls.length;
        const { status, json } = await postGenerate({ initData: valid, services: ["ticktick"] });
        check("[план 4] 200 ok", status === 200 && json.ok === true, JSON.stringify({ status, json }));
        check("[план 7] ровно один новый tgCall (sendMessage)", tgCalls.length === before + 1, tgCalls.length - before);
        const sent = tgCalls[tgCalls.length - 1];
        check("[план 7] это именно sendMessage с 🔑", sent.method === "sendMessage" && /🔑/.test(sent.body.text ?? ""), sent);
        check("[план 7] сырой токен НЕ попадает в тело HTTP-ответа", JSON.stringify(json) === '{"ok":true}', JSON.stringify(json));

        const row = await pool.query(`SELECT scope FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 4] окно в БД с scope='ticktick'", row.rows[0]?.scope === "ticktick", row.rows[0]);
      }

      // ── [5] «Все сразу» (все 6 сервисов отмечены) → scope = 'all' ──
      {
        const authDateSec = Math.floor(Date.now() / 1000);
        const valid = buildInitData(Number(OWNER_CHAT_ID), authDateSec);
        const { status, json } = await postGenerate({
          initData: valid,
          services: ["gmail", "calendar", "drive", "sheets", "docs", "ticktick"],
        });
        check("[план 5] 200 ok", status === 200 && json.ok === true, JSON.stringify({ status, json }));
        const row = await pool.query(`SELECT scope FROM tg_automation_windows ORDER BY created_at DESC LIMIT 1`);
        check("[план 5] scope === 'all'", row.rows[0]?.scope === "all", row.rows[0]);
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
