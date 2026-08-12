#!/usr/bin/env node
/**
 * Веб-хаб подтверждений (docs/TZ_consent_web_hub.md, часть 2) — сквозной
 * HTTP-тест: реальный `startHttpServer` (dist/http.js) + реальный Postgres
 * (гейтится `AUTOMATION_KEY_TEST_DB_URL`, тот же приём, что и остальные
 * live-DB тесты этого репо — без неё файл целиком пропускается) + 4 фейковых
 * "соседних" HTTP-сервиса (calendar/drive/sheets/docs), один из которых
 * намеренно НЕ поднят, чтобы проверить деградацию агрегатора (тест 11).
 *
 * `CONSENT_HUB_SECRET` задаётся ДО импорта `dist/http.js` (модульный
 * синглтон, читается один раз при импорте) — состояние "секрет НЕ задан"
 * (тест 8) проверяется отдельным файлом `test-consent-hub-no-secret.mjs`
 * (свой процесс), в одном процессе оба состояния не проверить.
 *
 * Покрывает тесты 7/9/10/11/12 тестового плана ТЗ (8 — в соседнем файле).
 *
 * Запуск: npm run build && AUTOMATION_KEY_TEST_DB_URL=postgres://... node scripts/test-consent-hub.mjs
 */
import { randomUUID } from "node:crypto";
import http from "node:http";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const dbUrlRaw = process.env.AUTOMATION_KEY_TEST_DB_URL;
if (!dbUrlRaw) {
  console.log("skip — AUTOMATION_KEY_TEST_DB_URL не задан, весь файл пропущен (см. README-запуск в шапке)");
  process.exit(0);
}

const SECRET = "hub-secret-xyz-" + randomUUID();
const HOST = "127.0.0.1";
const PORT = 34932;
const CAL_PORT = 34933;
const DRIVE_PORT = 34934; // намеренно НЕ поднимается — тест 11 (деградация)
const SHEETS_PORT = 34935;
const DOCS_PORT = 34936;
const BASE = `http://${HOST}:${PORT}`;

process.env.CONSENT_HUB_SECRET = SECRET;
process.env.CONSENT_SERVER = "gmail";
process.env.CALENDAR_MCP_URL = `http://${HOST}:${CAL_PORT}`;
process.env.DRIVE_MCP_URL = `http://${HOST}:${DRIVE_PORT}`;
process.env.SHEETS_MCP_URL = `http://${HOST}:${SHEETS_PORT}`;
process.env.DOCS_MCP_URL = `http://${HOST}:${DOCS_PORT}`;

// ── Фейковые "соседние" сервисы — минимальный http.Server, без express ──────
const neighborCalls = { calendar: [], sheets: [], docs: [] };

function startNeighbor(name, port, { items }) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      neighborCalls[name].push({ method: req.method, url: req.url, secret: req.headers["x-consent-hub-secret"], body });
      if (req.method === "GET" && req.url === "/pending-consents") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ service: name, items }));
        return;
      }
      if (req.method === "POST" && req.url === "/pending-consents/decide") {
        let parsed = {};
        try {
          parsed = JSON.parse(body);
        } catch {
          /* ignore */
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, outcome: parsed.decision === "confirm" ? "confirmed" : "refused", result: `neighbor-${name}-${parsed.manifestId}` }));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "not_found" }));
    });
  });
  return new Promise((resolve) => server.listen(port, HOST, () => resolve(server)));
}

const calServer = await startNeighbor("calendar", CAL_PORT, {
  items: [{ manifestId: "cal-1", tool: "calendar_event_create", title: "Создать событие", summary: "Созвон завтра", preview: "...", createdAt: Date.now(), expiresAt: Date.now() + 3_600_000, accountLabel: "work" }],
});
const sheetsServer = await startNeighbor("sheets", SHEETS_PORT, { items: [] });
const docsServer = await startNeighbor("docs", DOCS_PORT, {
  items: [{ manifestId: "docs-1", tool: "docs_replace_text", title: "Заменить текст", summary: "Q3 отчёт", preview: "...", createdAt: Date.now(), expiresAt: Date.now() + 3_600_000, accountLabel: "work" }],
});
// drive НЕ поднимается — DRIVE_MCP_URL указывает в никуда, соединение отвалится по connection-refused.

// ── Postgres: своя тестовая БД (тот же приём, что automation-key тесты) ─────
const dbUrl = dbUrlRaw.includes("sslmode=") ? dbUrlRaw : `${dbUrlRaw}${dbUrlRaw.includes("?") ? "&" : "?"}sslmode=disable`;
const pg = (await import("pg")).default;
const pool = new pg.Pool({ connectionString: dbUrl, ssl: false });
await pool.query("DROP TABLE IF EXISTS consent_manifests, consent_audit, tg_approvals CASCADE");

const { initStore, ensureSchema, createManifest } = await import("../dist/store.js");
initStore(dbUrl, "0".repeat(64));
await ensureSchema();

const { sha256 } = await import("../dist/consent.js");
const { registerAutoExecutor } = await import("../dist/autoExecute.js");

let executeCalls = 0;
const executedPayloads = [];
registerAutoExecutor("__test_tool__", {
  rehash: async (payload) => sha256(payload),
  execute: async (payload) => {
    executeCalls++;
    executedPayloads.push(payload);
    return `done:${JSON.stringify(payload)}`;
  },
});
registerAutoExecutor("__test_tool_mismatch__", {
  rehash: async () => "some-other-hash-entirely",
  execute: async () => "should-never-run",
});

async function makeManifest(tool, payload, { ttlMs = 3_600_000, alreadyExpired = false } = {}) {
  const id = randomUUID();
  const objectHash = sha256(payload);
  const createdAt = alreadyExpired ? Date.now() - ttlMs - 1000 : Date.now();
  const expiresAt = alreadyExpired ? Date.now() - 1000 : createdAt + ttlMs;
  await createManifest({ id, server: "gmail", tool, accountLabel: "work", payload, objectHash, createdAt, expiresAt });
  return id;
}

const { startHttpServer } = await import("../dist/http.js");
await startHttpServer({
  transport: "http",
  port: PORT,
  requireAuth: false,
  users: [
    {
      name: "default",
      accounts: [{ name: "default", auth: { mode: "oauth", clientId: "x", clientSecret: "y", refreshToken: "z" } }],
      defaultAccount: "default",
    },
  ],
  onboarding: { enabled: false },
  sendingStuckMinutes: 10,
});

async function getJson(path, headers) {
  const res = await fetch(`${BASE}${path}`, { headers });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}
async function postJson(path, body, headers) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: Object.assign({ "content-type": "application/json" }, headers || {}),
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}
const H = { "X-Consent-Hub-Secret": SECRET };

// ═══ [7] auth: без секрета / с неверным секретом → 404; с верным → 200 ═══
console.log("\n[7] /pending-consents: без секрета / неверный секрет → 404; верный → 200");
{
  const noHeader = await getJson("/pending-consents");
  check("без заголовка → 404", noHeader.status === 404, noHeader.status);
  const wrong = await getJson("/pending-consents", { "X-Consent-Hub-Secret": "definitely-wrong" });
  check("неверный секрет → 404 (не 401/403)", wrong.status === 404, wrong.status);
  const right = await getJson("/pending-consents", H);
  check("верный секрет → 200", right.status === 200, right.status);
  check("service='gmail'", right.json.service === "gmail", right.json);
}

// ═══ [9] decide confirm — реально исполняет, повтор → already_decided ═══
console.log("\n[9] decide confirm: реально исполняет (тем же путём, что кнопка в TG); повтор → already_decided, второй мутации нет");
{
  const id = await makeManifest("__test_tool__", { hello: "world", n: 1 });
  const before = executeCalls;
  const r1 = await postJson("/pending-consents/decide", { manifestId: id, decision: "confirm" }, H);
  check("200 ok", r1.status === 200 && r1.json.ok === true, r1);
  check("outcome=confirmed", r1.json.outcome === "confirmed", r1.json);
  check("result — реальный отчёт исполнителя", typeof r1.json.result === "string" && r1.json.result.startsWith("done:"), r1.json);
  check("executor.execute вызван РОВНО один раз", executeCalls === before + 1, executeCalls);

  const r2 = await postJson("/pending-consents/decide", { manifestId: id, decision: "confirm" }, H);
  check("повтор → 409 already_decided", r2.status === 409 && r2.json.error === "already_decided", r2);
  check("второй мутации НЕТ (executeCalls не изменился)", executeCalls === before + 1, executeCalls);

  // binding_mismatch — отдельный, машиночитаемый код, манифест НЕ трогается.
  const idMismatch = await makeManifest("__test_tool_mismatch__", { x: 1 });
  const rMismatch = await postJson("/pending-consents/decide", { manifestId: idMismatch, decision: "confirm" }, H);
  check("binding mismatch → 409 binding_mismatch", rMismatch.status === 409 && rMismatch.json.error === "binding_mismatch", rMismatch);
  const stillAwaiting = await pool.query("SELECT status FROM consent_manifests WHERE id = $1", [idMismatch]);
  check("манифест НЕ consumed при binding_mismatch", stillAwaiting.rows[0]?.status === "AWAITING_CONSENT", stillAwaiting.rows[0]);

  // not_found / expired — машиночитаемые коды, никогда 500.
  const rNotFound = await postJson("/pending-consents/decide", { manifestId: "nope-" + randomUUID(), decision: "confirm" }, H);
  check("неизвестный manifestId → 404 not_found", rNotFound.status === 404 && rNotFound.json.error === "not_found", rNotFound);

  const idExpired = await makeManifest("__test_tool__", { late: true }, { alreadyExpired: true });
  const rExpired = await postJson("/pending-consents/decide", { manifestId: idExpired, decision: "confirm" }, H);
  check("просроченный manifestId → 410 expired", rExpired.status === 410 && rExpired.json.error === "expired", rExpired);
}

// ═══ [10] decide reject с комментарием ═══
console.log("\n[10] decide reject с комментарием: манифест отклонён, комментарий — userReply в аудите");
{
  const id = await makeManifest("__test_tool__", { subject: "reject me" });
  const r = await postJson("/pending-consents/decide", { manifestId: id, decision: "reject", comment: "плохая идея, отмени" }, H);
  check("200 ok, outcome=refused", r.status === 200 && r.json.ok === true && r.json.outcome === "refused", r);
  const row = await pool.query("SELECT status FROM consent_manifests WHERE id = $1", [id]);
  check("манифест INVALIDATED", row.rows[0]?.status === "INVALIDATED", row.rows[0]);
  const audit = await pool.query("SELECT user_reply, outcome FROM consent_audit WHERE manifest_id = $1 ORDER BY ts DESC LIMIT 1", [id]);
  check("аудит: outcome=invalidated", audit.rows[0]?.outcome === "invalidated", audit.rows[0]);
  check("аудит: user_reply = комментарий дословно", audit.rows[0]?.user_reply === "плохая идея, отмени", audit.rows[0]);
}

// ═══ [11] агрегатор: один сосед недоступен → остальные отдаются, 200 не 500 ═══
console.log("\n[11] /consent-hub-api/pending: drive недоступен → остальные пункты отдаются, ответ 200");
{
  await makeManifest("__test_tool__", { agg: "own-item" });
  const r = await getJson("/consent-hub-api/pending", H);
  check("200 (не 500)", r.status === 200, r.status);
  check("drive помечен недоступным", Array.isArray(r.json.unavailable) && r.json.unavailable.includes("drive"), r.json.unavailable);
  check("gmail (свои) пункты присутствуют", r.json.items.some((i) => i.service === "gmail"), r.json.items.map((i) => i.service));
  check("calendar пункт присутствует (сосед жив)", r.json.items.some((i) => i.service === "calendar" && i.manifestId === "cal-1"), r.json.items);
  check("docs пункт присутствует (сосед жив)", r.json.items.some((i) => i.service === "docs" && i.manifestId === "docs-1"), r.json.items);
  check("drive пункты отсутствуют в items", !r.json.items.some((i) => i.service === "drive"), r.json.items);
  check("сервер добавил X-Consent-Hub-Secret запросу к calendar", neighborCalls.calendar.some((c) => c.secret === SECRET), neighborCalls.calendar);

  // без секрета — тоже 404, как и локальный /pending-consents.
  const noSecret = await getJson("/consent-hub-api/pending");
  check("/consent-hub-api/pending без секрета → 404", noSecret.status === 404, noSecret.status);
}

console.log("\n[11.2] /consent-hub-api/decide: прокси на соседа (docs), секрет браузер не видит, сосед получает его от сервера");
{
  const r = await postJson("/consent-hub-api/decide", { service: "docs", manifestId: "docs-1", decision: "confirm" }, H);
  check("200 ok, проксировано", r.status === 200 && r.json.ok === true, r);
  check("результат — от соседа (docs)", typeof r.json.result === "string" && r.json.result.includes("neighbor-docs-docs-1"), r.json);
  const lastCall = neighborCalls.docs.find((c) => c.method === "POST");
  check("сосед получил X-Consent-Hub-Secret заголовком", lastCall?.secret === SECRET, lastCall);
}

console.log("\n[11.3] /consent-hub-api/decide: свой сервис (gmail) — та же логика, что /pending-consents/decide");
{
  const id = await makeManifest("__test_tool__", { via: "hub-api-own" });
  const r = await postJson("/consent-hub-api/decide", { service: "gmail", manifestId: id, decision: "confirm" }, H);
  check("200 ok", r.status === 200 && r.json.ok === true && r.json.outcome === "confirmed", r);
}

// ═══ [12] страница: узкий/широкий — markup несёт ОБА пути раскладки ═══
console.log("\n[12] GET /consent-hub/<secret>: 200 html, разметка несёт и мобильную (разворот в списке), и десктопную (список+панель) раскладку");
{
  const wrong = await fetch(`${BASE}/consent-hub/not-the-secret`);
  check("неверный секрет в пути → 403", wrong.status === 403, wrong.status);

  const res = await fetch(`${BASE}/consent-hub/${SECRET}`);
  const text = await res.text();
  check("200", res.status === 200, res.status);
  check("Content-Type html", (res.headers.get("content-type") || "").includes("html"), res.headers.get("content-type"));
  check("несёт брейкпоинт адаптива (@media min-width:760px)", /@media\s*\(min-width:\s*760px\)/.test(text));
  check("узкая раскладка: разворот карточки в списке (.detail-inline)", text.includes(".detail-inline"));
  check("широкая раскладка: постоянная панель чтения (.pane)", text.includes('id="pane"') && text.includes(".pane {"));
  check("массовый отбор чекбоксами (bulkbar)", text.includes('id="bulkbar"') && text.includes("data-check"));
  check("финальный экран перед подтверждением (review)", text.includes('id="review"') && text.includes("Подтверждаю"));
  check("три кнопки на пункт (Подтвердить / Отклонить с комментарием / Отклонить)",
    text.includes("Подтвердить") && text.includes("Отклонить с комментарием") && text.includes("Отклонить"));
  check("секрет НЕ напечатан в самой разметке (кроме как в URL, которым её открыли)", !text.includes(SECRET));
}

calServer.close();
sheetsServer.close();
docsServer.close();
await pool.end();

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
