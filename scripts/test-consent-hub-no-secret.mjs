#!/usr/bin/env node
/**
 * Веб-хаб подтверждений (docs/TZ_consent_web_hub.md, часть 2), тест 8:
 * `CONSENT_HUB_SECRET` НЕ задан ⇒ `/pending-consents`, `/pending-consents/decide`,
 * `/consent-hub-api/pending`, `/consent-hub-api/decide` и `/consent-hub/:secret`
 * все отвечают 404 — фича молча выключена (fail-closed), остальной сервис
 * работает как обычно (health-check).
 *
 * Отдельный ПРОЦЕСС/файл — тот же приём, что `test-automation-key-no-master-secret.mjs`:
 * `CONSENT_HUB_SECRET` читается ОДИН раз при импорте `http.ts` (модульный
 * синглтон `consentHubSecret`), в одном процессе оба состояния (заданintre/не
 * задан) не проверить.
 *
 * Не требует БД — все проверяемые роуты отвечают 404 до единого обращения к
 * Postgres (guard срабатывает первым).
 *
 * Запуск: npm run build && node scripts/test-consent-hub-no-secret.mjs
 */
let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

delete process.env.CONSENT_HUB_SECRET;
process.env.CONSENT_SERVER = "gmail";

const PORT = 34931;
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

console.log("\n[8] CONSENT_HUB_SECRET не задан → все хаб-роуты 404, остальной сервис работает");
{
  const health = await fetch(`${BASE}/health`);
  check("health 200 (остальной сервис работает)", health.status === 200, health.status);

  const pending = await fetch(`${BASE}/pending-consents`);
  check("GET /pending-consents → 404", pending.status === 404, pending.status);

  const decide = await fetch(`${BASE}/pending-consents/decide`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ manifestId: "x", decision: "confirm" }),
  });
  check("POST /pending-consents/decide → 404", decide.status === 404, decide.status);

  const hubApiPending = await fetch(`${BASE}/consent-hub-api/pending`);
  check("GET /consent-hub-api/pending → 404", hubApiPending.status === 404, hubApiPending.status);

  const hubApiDecide = await fetch(`${BASE}/consent-hub-api/decide`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ service: "gmail", manifestId: "x", decision: "confirm" }),
  });
  check("POST /consent-hub-api/decide → 404", hubApiDecide.status === 404, hubApiDecide.status);

  const hubPage = await fetch(`${BASE}/consent-hub/anything`);
  check("GET /consent-hub/:secret → 404 (роут не смонтирован без секрета)", hubPage.status === 404, hubPage.status);

  // Даже с заголовком-секретом (пустая строка/любое значение) — всё равно 404.
  const withHeader = await fetch(`${BASE}/pending-consents`, { headers: { "X-Consent-Hub-Secret": "whatever" } });
  check("GET /pending-consents с ЛЮБЫМ заголовком → всё равно 404", withHeader.status === 404, withHeader.status);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
