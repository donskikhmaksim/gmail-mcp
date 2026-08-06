#!/usr/bin/env node
/**
 * #119 — секрет дашборда не должен попадать в логи.
 *
 * Дашборд управления аккаунтами защищён неугадываемым сегментом ПУТИ
 * (`/dashboard/<DASHBOARD_SECRET>`), и сервер печатал этот URL целиком при
 * каждом старте: боевой секрет открытым текстом в логах Railway, навсегда,
 * без ротации. Дашборд умеет отвязывать и привязывать Google-аккаунты, так
 * что доступ к логам был равен доступу к нему.
 *
 * Проверяем то, что видно СНАРУЖИ: перехватываем сам поток stderr (не
 * console-обёртку и не внутренние переменные) и читаем строки, которые
 * реально напечатал НАСТОЯЩИЙ startHttpServer с настоящим слушающим портом.
 *
 * Секрет здесь ВЫДУМАННЫЙ — боевое значение не должно появляться ни в
 * тестах, ни в отчётах.
 *
 * Usage: node scripts/test-log-redaction.mjs
 */
import { startHttpServer } from "../dist/http.js";
import { redactPathSecrets } from "../dist/logRedaction.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

const FAKE_DASHBOARD_SECRET = "fake0dashboard0secret0do0not0use0abcdef";
const FAKE_LINK_TOKEN = "ZmFrZS1saW5rLXRva2Vu.c2lnbmF0dXJl";
const BASE_URL = "https://example-fake.invalid";

/** Перехват настоящего байтового вывода в stderr (console.error пишет туда). */
async function withCapturedStderr(fn) {
  const lines = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => {
    lines.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return orig(chunk, ...rest);
  };
  try {
    await fn();
  } finally {
    process.stderr.write = orig;
  }
  return lines.join("");
}

function onboardingConfig(port) {
  return {
    transport: "http",
    port,
    requireAuth: false,
    users: [],
    onboarding: {
      enabled: true,
      publicBaseUrl: BASE_URL,
      googleClientId: "fake-client-id.apps.googleusercontent.com",
      googleClientSecret: "fake-client-secret",
      dashboardSecret: FAKE_DASHBOARD_SECRET,
    },
    sendingStuckMinutes: 10,
  };
}

try {
  console.log("\n[1] Настоящий старт сервера: строка про дашборд без секрета");
  const printed = await withCapturedStderr(() => startHttpServer(onboardingConfig(34971)));

  check("сервер вообще напечатал строку про дашборд", /Account dashboard at/.test(printed), printed.slice(0, 400));
  check("секрет дашборда НЕ попал в stderr", !printed.includes(FAKE_DASHBOARD_SECRET), "секрет найден в выводе");
  check(
    "путь остался читаемым, секретный сегмент заменён заглушкой",
    printed.includes(`Account dashboard at ${BASE_URL}/dashboard/<dashboard-secret>`),
    printed.match(/Account dashboard at.*/)?.[0],
  );
  check(
    "остальная диагностика старта на месте (порт и режим auth)",
    /MCP listening on :34971/.test(printed) && /auth=/.test(printed),
    printed.match(/MCP listening.*/)?.[0],
  );

  console.log("\n[2] Фильтр не глотает полезное");
  check(
    "обычная строка проходит без изменений",
    redactPathSecrets("MCP listening on :8080  auth=on") === "MCP listening on :8080  auth=on",
    redactPathSecrets("MCP listening on :8080  auth=on"),
  );
  check(
    "короткое значение не вырезается по всему тексту",
    redactPathSecrets("account ok, label ok", "ok") === "account ok, label ok",
    redactPathSecrets("account ok, label ok", "ok"),
  );
  check(
    "но в самом пути маскируется даже короткий секрет",
    redactPathSecrets("/dashboard/ok", "ok") === "/dashboard/<dashboard-secret>",
    redactPathSecrets("/dashboard/ok", "ok"),
  );

  console.log("\n[3] Токен ссылки на вложение — тоже пропуск");
  const dl = redactPathSecrets(`GET ${BASE_URL}/dl/${FAKE_LINK_TOKEN} 200`);
  check("токен /dl/ замаскирован", !dl.includes(FAKE_LINK_TOKEN), dl);
  check("код ответа и форма пути сохранились", dl === `GET ${BASE_URL}/dl/<link-token> 200`, dl);

  console.log("\n[4] Идемпотентность");
  const once = redactPathSecrets(`/dashboard/${FAKE_DASHBOARD_SECRET}`, FAKE_DASHBOARD_SECRET);
  check("повторный прогон ничего не меняет", redactPathSecrets(once, FAKE_DASHBOARD_SECRET) === once, once);
} catch (err) {
  console.error("Unexpected error:", err);
  failures++;
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
