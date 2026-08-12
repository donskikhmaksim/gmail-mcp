#!/usr/bin/env node
/**
 * Владелец попросил "сделай их в одном месте" (2026-08-12) — третья вкладка
 * «Подтверждения» в мини-аппе automation_key (src/automation_key_miniapp.ts),
 * ведущая в хаб подтверждений (docs/TZ_consent_web_hub.md часть 2).
 *
 * Отдельный процесс/файл — тем же приёмом, что и test-consent-hub-no-secret.mjs
 * (CONSENT_HUB_SECRET читается ОДИН раз при импорте http.ts, здесь он ЗАДАН,
 * в отличие от того файла).
 *
 * Проверяется:
 *  1. При заданном CONSENT_HUB_SECRET вкладка присутствует в GET /automation-key-app.
 *  2. Секрет НИКОГДА не попадает в сам HTML статичной страницы (она отдаётся
 *     БЕЗ авторизации — секрет должен приходить только через POST-роут).
 *  3. POST /automation-key-app/consent-hub-url — тот же owner-only initData-чек,
 *     что и «Выпустить ключ» (подделанная подпись / чужой user.id → 403).
 *  4. Валидный initData владельца → 200, url = /consent-hub/<секрет>.
 *
 * Запуск: npm run build && node scripts/test-automation-key-consent-tab.mjs
 */
import { createHmac } from "node:crypto";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const BOT_TOKEN = "TESTTOKEN";
const OWNER_CHAT_ID = "555";
const SECRET = "test-consent-hub-secret-xyz";

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

process.env.TG_APPROVAL_ENABLED = "true";
process.env.TG_BOT_TOKEN = BOT_TOKEN;
process.env.TG_OWNER_CHAT_ID = OWNER_CHAT_ID;
process.env.TG_APPROVAL_WEBHOOK_SECRET = "wh-secret-xyz";
process.env.PUBLIC_BASE_URL = "http://127.0.0.1:0";
process.env.TG_WEBHOOK_OWNER = "true";
process.env.CONSENT_HUB_SECRET = SECRET;
process.env.CONSENT_SERVER = "gmail";

const PORT = 34938;
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

console.log("\n[1] GET /automation-key-app: вкладка «Подтверждения» присутствует, секрет НЕ в разметке");
{
  const res = await fetch(`${BASE}/automation-key-app`);
  const html = await res.text();
  check("200 OK", res.status === 200, res.status);
  check("вкладка «Подтверждения» в разметке", html.includes(">Подтверждения<"));
  check("секрет CONSENT_HUB_SECRET НЕ встречается в HTML", !html.includes(SECRET));
  check("id=\"tabBtnHub\" присутствует", html.includes('id="tabBtnHub"'));
}

console.log("\n[2] POST /automation-key-app/consent-hub-url: подделанная подпись → 403, url не отдан");
{
  const res = await fetch(`${BASE}/automation-key-app/consent-hub-url`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ initData: "hash=deadbeef&user=%7B%22id%22%3A555%7D&auth_date=1" }),
  });
  const json = await res.json().catch(() => ({}));
  check("403", res.status === 403, res.status);
  check("error: invalid_init_data", json.error === "invalid_init_data", JSON.stringify(json));
  check("url отсутствует в ответе", json.url === undefined);
}

console.log("\n[3] POST /automation-key-app/consent-hub-url: валидный initData, но чужой user.id → 403");
{
  const authDateSec = Math.floor(Date.now() / 1000);
  const initData = buildInitData(999, authDateSec);
  const res = await fetch(`${BASE}/automation-key-app/consent-hub-url`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ initData }),
  });
  const json = await res.json().catch(() => ({}));
  check("403", res.status === 403, res.status);
  check("error: forbidden", json.error === "forbidden", JSON.stringify(json));
}

console.log("\n[4] POST /automation-key-app/consent-hub-url: владелец → 200, url = /consent-hub/<секрет>");
{
  const authDateSec = Math.floor(Date.now() / 1000);
  const initData = buildInitData(Number(OWNER_CHAT_ID), authDateSec);
  const res = await fetch(`${BASE}/automation-key-app/consent-hub-url`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ initData }),
  });
  const json = await res.json().catch(() => ({}));
  check("200 ok", res.status === 200, res.status);
  check("ok: true", json.ok === true, JSON.stringify(json));
  check(`url === /consent-hub/${SECRET}`, json.url === `/consent-hub/${SECRET}`, JSON.stringify(json));

  // Ссылка реально ведёт на живую (существующую) страницу хаба.
  const hubPage = await fetch(`${BASE}${json.url}`);
  check("возвращённый url реально открывает 200 html", hubPage.status === 200, hubPage.status);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
