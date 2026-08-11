/**
 * automation_key_miniapp.ts — Telegram Mini App, второй (более удобный)
 * способ выбора сервисов для `automation_key`, ПОВЕРХ уже рабочей кнопочной
 * версии (`src/automation_key.ts`). Spec: `docs/TZ_automation_key_miniapp.md`.
 *
 * Этот модуль отвечает ровно за две вещи:
 *  1. `renderAutomationKeyMiniAppPage()` — статическая HTML-страница с
 *     чекбоксами, отдаётся БЕЗ авторизации (сама разметка не секрет —
 *     ТЗ раздел 1).
 *  2. `verifyTelegramInitData()` — единственная защита экшена «Получить
 *     ключ»: проверка подписи `Telegram.WebApp.initData` по стандартному
 *     алгоритму (ТЗ раздел 4). Никакой генерации/доставки ключа здесь нет —
 *     это по-прежнему `generateAndDeliverKey` в `automation_key.ts`,
 *     http.ts просто зовёт обе функции по очереди.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { AUTOMATION_SERVICES } from "./automation_key.js";

// ───────────────────────── initData verification ───────────────────────────

/** Окно свежести `auth_date` — Telegram сам не гарантирует свежесть
 * `initData` (страница мини-аппа может оставаться открытой сколь угодно
 * долго), это ответственность backend'а: без этого чека перехваченный
 * `initData` можно переиграть (replay) неограниченно долго (ТЗ раздел 4). */
export const INIT_DATA_MAX_AGE_MS = 5 * 60 * 1000;

export type InitDataVerifyResult =
  | { ok: true; userId: string }
  | { ok: false; reason: "missing" | "unparseable" | "no_hash" | "bad_signature" | "no_auth_date" | "stale" | "no_user" | "bad_user_json" | "no_user_id" };

/**
 * Проверяет `initData` по стандартному алгоритму Telegram Mini Apps
 * (https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app):
 *   secret_key = HMAC_SHA256(key="WebAppData", data=bot_token)
 *   data_check_string = все поля кроме `hash`, отсортированные по ключу,
 *                        склеенные как "key=value" через "\n"
 *   hash_ожидаемый = HMAC_SHA256(key=secret_key, data=data_check_string) (hex)
 * Сравнение с присланным `hash` — ПОСТОЯННОЕ время (`crypto.timingSafeEqual`,
 * тот же приём, что `secretTokenMatches` в `src/tg_approval.ts`) — иначе
 * посимвольное сравнение хэша утекает через тайминг, тот же класс уязвимости,
 * от которой уже защищаются в этом репозитории для секрета вебхука.
 *
 * Отдельно проверяет `auth_date` не старше `maxAgeMs` (replay-защита) и
 * возвращает `user.id` (как строку, для прямого сравнения с
 * `cfg.ownerChatId`) — но НЕ сравнивает его с владельцем сам: это решение
 * вызывающего кода (http.ts), эта функция отвечает только за подлинность и
 * свежесть данных.
 */
export function verifyTelegramInitData(
  botToken: string,
  initData: string,
  now: () => number = Date.now,
  maxAgeMs: number = INIT_DATA_MAX_AGE_MS,
): InitDataVerifyResult {
  if (!botToken || !initData) return { ok: false, reason: "missing" };

  let params: URLSearchParams;
  try {
    params = new URLSearchParams(initData);
  } catch {
    return { ok: false, reason: "unparseable" };
  }

  const providedHash = params.get("hash");
  if (!providedHash) return { ok: false, reason: "no_hash" };
  params.delete("hash");

  const entries: string[] = [];
  params.forEach((value, key) => entries.push(`${key}=${value}`));
  entries.sort();
  const dataCheckString = entries.join("\n");

  const secretKey = createHmac("sha256", "WebAppData").update(botToken).digest();
  const expectedHash = createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

  const a = Buffer.from(expectedHash);
  const b = Buffer.from(providedHash);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, reason: "bad_signature" };
  }

  const authDateRaw = params.get("auth_date");
  const authDateSec = authDateRaw ? Number(authDateRaw) : NaN;
  if (!Number.isFinite(authDateSec)) return { ok: false, reason: "no_auth_date" };
  const ageMs = now() - authDateSec * 1000;
  // И "слишком старый" (обычный replay), И "из будущего" (подделанная/
  // рассинхронизированная метка) — оба вне разумного окна свежести.
  if (Math.abs(ageMs) > maxAgeMs) return { ok: false, reason: "stale" };

  const userRaw = params.get("user");
  if (!userRaw) return { ok: false, reason: "no_user" };
  let user: { id?: number | string };
  try {
    user = JSON.parse(userRaw) as { id?: number | string };
  } catch {
    return { ok: false, reason: "bad_user_json" };
  }
  if (user.id == null) return { ok: false, reason: "no_user_id" };

  return { ok: true, userId: String(user.id) };
}

// ───────────────────────── Static page ──────────────────────────────────────

const SERVICE_LABELS: Record<string, string> = {
  gmail: "Gmail",
  calendar: "Calendar",
  drive: "Drive",
  sheets: "Sheets",
  docs: "Docs",
  ticktick: "TickTick",
};

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/**
 * Единственная страница мини-аппа. Инлайн HTML/CSS/JS в коде роута (как и
 * `/dashboard/:secret` — см. `src/dashboard.ts` — держит одну статическую
 * страницу прямо в TS-модуле, без отдельного билд-шага под фронтенд).
 *
 * Стилизация — под `--tg-theme-*` CSS-переменные, которые сам SDK
 * (`telegram-web-app.js`) прописывает в `<html>` при загрузке, плюс
 * `Telegram.WebApp.colorScheme` как fallback для полей, которых нет в
 * `--tg-theme-*` (ТЗ раздел 1) — минимально, но не белый текст на белом фоне
 * в тёмной теме.
 */
export function renderAutomationKeyMiniAppPage(): string {
  const checkboxes = AUTOMATION_SERVICES.map(
    (svc) =>
      `<label class="row"><input type="checkbox" class="svc" value="${svc}"> ${escapeHtml(SERVICE_LABELS[svc] ?? svc)}</label>`,
  ).join("\n      ");

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>automation_key</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
  :root { color-scheme: light dark; }
  body {
    margin: 0;
    padding: 16px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--tg-theme-bg-color, #ffffff);
    color: var(--tg-theme-text-color, #000000);
  }
  h1 { font-size: 18px; margin: 0 0 12px; }
  .row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    margin-bottom: 8px;
    border-radius: 10px;
    background: var(--tg-theme-secondary-bg-color, #f2f2f2);
  }
  .row input { width: 18px; height: 18px; }
  .sep { height: 1px; background: var(--tg-theme-hint-color, #999); opacity: .3; margin: 12px 0; }
  button {
    width: 100%;
    padding: 12px;
    border: none;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 600;
    background: var(--tg-theme-button-color, #2481cc);
    color: var(--tg-theme-button-text-color, #ffffff);
  }
  button:disabled { opacity: .5; }
  #status { margin-top: 12px; font-size: 14px; color: var(--tg-theme-hint-color, #999); min-height: 1.2em; }
</style>
</head>
<body>
  <h1>automation_key</h1>
  <div id="services">
      ${checkboxes}
  </div>
  <label class="row"><input type="checkbox" id="all"> Все сразу</label>
  <div class="sep"></div>
  <button id="go" disabled>Получить ключ</button>
  <div id="status"></div>

<script>
(function () {
  var tg = window.Telegram && window.Telegram.WebApp;
  if (tg) { tg.ready(); tg.expand(); }

  var svcBoxes = Array.prototype.slice.call(document.querySelectorAll(".svc"));
  var allBox = document.getElementById("all");
  var goBtn = document.getElementById("go");
  var statusEl = document.getElementById("status");

  function selected() {
    return svcBoxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
  }

  function refresh() {
    goBtn.disabled = selected().length === 0;
  }

  allBox.addEventListener("change", function () {
    svcBoxes.forEach(function (b) { b.checked = allBox.checked; });
    refresh();
  });
  svcBoxes.forEach(function (b) {
    b.addEventListener("change", function () {
      if (!b.checked) allBox.checked = false;
      else if (svcBoxes.every(function (x) { return x.checked; })) allBox.checked = true;
      refresh();
    });
  });

  goBtn.addEventListener("click", function () {
    var services = selected();
    if (services.length === 0) return; // fail-closed на фронтенде тоже, но backend не полагается на это
    goBtn.disabled = true;
    statusEl.textContent = "Генерирую...";
    fetch("/automation-key-app/generate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        initData: tg ? tg.initData : "",
        services: services,
      }),
    })
      .then(function (res) {
        if (!res.ok) return res.json().catch(function () { return {}; }).then(function (body) {
          throw new Error(body && body.error ? body.error : ("HTTP " + res.status));
        });
        return res.json();
      })
      .then(function () {
        statusEl.textContent = "Готово — ключ отправлен в чат, исчезнет через 10с.";
        if (tg) setTimeout(function () { tg.close(); }, 1500);
      })
      .catch(function (err) {
        statusEl.textContent = "Ошибка: " + err.message;
        goBtn.disabled = false;
      });
  });

  refresh();
})();
</script>
</body>
</html>`;
}
