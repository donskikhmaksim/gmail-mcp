#!/usr/bin/env node
/**
 * `scopeCovers`/`checkAutomationKeyFor` — покрытие по МЕТОДАМ, а не только
 * по сервисам целиком (docs/TZ_automation_key_method_catalog.md, тестовый
 * план пп.3-5). Прямой импорт `../src/automation_key.ts` (тот же приём, что
 * `test-automation-key.mjs`) — этот модуль не тянет `server.ts`, только
 * type-only импорт из `config.ts`, стёртый на компиляции, так что раннер
 * может грузить `.ts` напрямую без билда.
 *
 * Запуск: node scripts/test-scope-covers-methods.mjs
 */
import crypto from "node:crypto";
import { scopeCovers, checkAutomationKeyFor, normalizeScopeTokens, humanScopeList } from "../src/automation_key.ts";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

// ═══════════════ [3] scopeCovers — новые кейсы по методам ══════════════════

console.log("\n[3] scopeCovers — точное совпадение по методу, без подстрок/startsWith");
{
  check(
    "service:tool матчит точно этот метод",
    scopeCovers("gmail:gmail_send", "gmail", "gmail_send") === true,
  );
  check(
    "НЕ матчит другой метод того же сервиса",
    scopeCovers("gmail:gmail_send", "gmail", "gmail_reply") === false,
  );
  check(
    "НЕ матчит общий префикс без ':' (gmail:gmail_send vs gmail:gmail_send_extra)",
    scopeCovers("gmail:gmail_send", "gmail", "gmail_send_extra") === false,
  );
  check(
    "и обратно: scope на расширенное имя НЕ матчит короткое",
    scopeCovers("gmail:gmail_send_extra", "gmail", "gmail_send") === false,
  );
  check(
    "bare service по-прежнему покрывает ЛЮБОЙ метод (обратная совместимость)",
    scopeCovers("gmail", "gmail", "gmail_send") === true && scopeCovers("gmail", "gmail", "gmail_archive") === true,
  );
  check("bare service НЕ покрывает другой сервис", scopeCovers("gmail", "calendar", "calendar_event_create") === false);
  check("'all' покрывает всё", scopeCovers("all", "gmail", "gmail_send") === true && scopeCovers("all", "calendar", "anything") === true);
  check(
    "смешанный csv: покрывает целый calendar И только один метод gmail",
    scopeCovers("calendar,gmail:gmail_reply", "calendar", "calendar_event_create") === true &&
      scopeCovers("calendar,gmail:gmail_reply", "gmail", "gmail_reply") === true &&
      scopeCovers("calendar,gmail:gmail_reply", "gmail", "gmail_send") === false,
  );
  check(
    "старый регресс-кейс: 'google-sheets' (сосед по префиксу) НЕ матчит 'sheets'",
    scopeCovers("google-sheets", "sheets", "anything") === false,
  );
}

// ═══════════════ [4] checkAutomationKeyFor(service, store, key, tool) ══════

console.log("\n[4] checkAutomationKeyFor — метод-уровневый scope пропускает только СВОЙ метод");
{
  const nowFixed = () => 1_700_000_000_000;
  const rawToken = "raw-token-method-scope";
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

  function makeStore(scope) {
    const windows = [
      {
        windowId: "w1",
        tokenHash,
        scope,
        label: null,
        createdAt: nowFixed(),
        expiresAt: nowFixed() + 3_600_000,
        revokedAt: null,
        createdByChat: "555",
        tokenEncrypted: null,
      },
    ];
    return { listActiveWindows: async () => windows };
  }

  const store = makeStore("gmail:gmail_send");
  const okSend = await checkAutomationKeyFor("gmail", store, rawToken, "gmail_send", nowFixed);
  const failReply = await checkAutomationKeyFor("gmail", store, rawToken, "gmail_reply", nowFixed);
  check("валидный ключ + scope на gmail_send → ok для gmail_send", okSend.ok === true, JSON.stringify(okSend));
  check(
    "тот же ключ НЕ пропускает gmail_reply (другой гейтированный метод того же сервиса)",
    failReply.ok === false,
    JSON.stringify(failReply),
  );

  // [5] Регресс — bare-service scope по-прежнему покрывает ЛЮБОЙ метод.
  const bareStore = makeStore("gmail");
  const bareSend = await checkAutomationKeyFor("gmail", bareStore, rawToken, "gmail_send", nowFixed);
  const bareReply = await checkAutomationKeyFor("gmail", bareStore, rawToken, "gmail_reply", nowFixed);
  check("[5] регресс: bare 'gmail' scope пропускает gmail_send", bareSend.ok === true);
  check("[5] регресс: bare 'gmail' scope пропускает gmail_reply тоже", bareReply.ok === true);

  // Неверный ключ — всегда {ok:false}, независимо от scope/tool.
  const wrongKey = await checkAutomationKeyFor("gmail", store, "totally-wrong-key", "gmail_send", nowFixed);
  check("неверный ключ → ok:false", wrongKey.ok === false);
}

// ═══════════════ normalizeScopeTokens / humanScopeList (мини-апп бэкенд) ═══

console.log("\n[доп] normalizeScopeTokens / humanScopeList — утилиты для нового HTTP-тела мини-аппа");
{
  check(
    "все 6 bare-сервисов схлопываются в 'all'",
    normalizeScopeTokens(["gmail", "calendar", "drive", "sheets", "docs", "ticktick"]) === "all",
  );
  check(
    "частичный набор остаётся csv (без схлопывания)",
    normalizeScopeTokens(["gmail", "calendar"]) === "gmail,calendar",
  );
  check(
    "дедуп повторов",
    normalizeScopeTokens(["gmail", "gmail", "gmail:gmail_send"]) === "gmail,gmail:gmail_send",
  );
  check("humanScopeList('all') === 'все сервисы'", humanScopeList("all") === "все сервисы");
  check(
    "humanScopeList для смешанного scope — читаемый список токенов",
    humanScopeList("calendar,gmail:gmail_send") === "calendar, gmail:gmail_send",
  );
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
