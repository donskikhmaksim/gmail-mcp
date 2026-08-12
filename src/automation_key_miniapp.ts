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
import type { ExternalCatalogUrls } from "./config.js";

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
 * Сервисы БЕЗ автосправочника методов (docs/TZ_automation_key_method_catalog.md
 * раздел "Явно НЕ входит") — у ticktick-mcp нет `/automation-key-catalog` и
 * не будет в этом заходе (отдельная Python-архитектура). Клиентский JS
 * никогда не пытается его зафетчить, а рисует явную пометку вместо дерева
 * методов.
 */
const NO_CATALOG_SERVICES: readonly string[] = ["ticktick"];

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
 *
 * `catalogUrls` — базовые URL-ы четырёх соседних сервисов (calendar/drive/
 * sheets/docs), чьи `/automation-key-catalog` клиентский JS зафетчит
 * параллельно со своим собственным (docs/TZ_automation_key_method_catalog.md
 * раздел "Мини-апп — дерево «сервис → методы»"). Передаётся HTTP-роутом
 * (`http.ts`) из env (`loadExternalCatalogUrls`) — сама функция рендера
 * остаётся чистой (без чтения `process.env` внутри), как и раньше.
 */
export function renderAutomationKeyMiniAppPage(catalogUrls: ExternalCatalogUrls, hasConsentHub: boolean): string {
  const checkboxes = AUTOMATION_SERVICES.map(
    (svc) =>
      `<div class="svc-block">\n` +
      `      <label class="row"><input type="checkbox" class="svc" value="${svc}"> ${escapeHtml(SERVICE_LABELS[svc] ?? svc)}</label>\n` +
      `      <div class="methods-wrap" id="methods-${svc}"></div>\n` +
      `    </div>`,
  ).join("\n      ");
  // Тот же список сервисов доступен клиентскому JS как массив/словарь — не
  // задваивает разметку чекбоксов сервером, модалка «Изменить доступ» (второй
  // таб) строит СВОИ чекбоксы динамически этим же списком (переиспользует
  // разметку/стили `.row`/`.svc`, не копирует HTML вручную). Дерево методов
  // (docs/TZ_automation_key_method_catalog.md) — ОДИН и тот же переиспользуемый
  // JS-компонент (`ServiceScopeTree` ниже в `<script>`) в ОБОИХ местах: здесь
  // (таб «Выпустить», прикрепляется к уже отрендеренным `.svc`-чекбоксам выше)
  // и в модалке «Изменить доступ» (таб «Мои ключи», чекбоксы строятся с нуля
  // тем же компонентом).
  const servicesJson = JSON.stringify(AUTOMATION_SERVICES);
  const serviceLabelsJson = JSON.stringify(SERVICE_LABELS);
  const noCatalogServicesJson = JSON.stringify(NO_CATALOG_SERVICES);
  // Собственный каталог этого сервера — same-origin относительный путь (не
  // течёт наружу протокол/хост); четыре соседних — абсолютные URL-ы из env.
  const catalogUrlsJson = JSON.stringify({
    gmail: "/automation-key-catalog",
    calendar: `${catalogUrls.calendar}/automation-key-catalog`,
    drive: `${catalogUrls.drive}/automation-key-catalog`,
    sheets: `${catalogUrls.sheets}/automation-key-catalog`,
    docs: `${catalogUrls.docs}/automation-key-catalog`,
  });

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
  .svc-block { margin-bottom: 2px; }
  .methods-wrap { margin: 0 0 6px 22px; }
  .method-row {
    padding: 6px 10px;
    margin-bottom: 4px;
    border-radius: 8px;
    font-size: 13px;
    background: var(--tg-theme-bg-color, #ffffff);
    border: 1px solid var(--tg-theme-hint-color, #999);
    border-opacity: .2;
  }
  .method-row input { width: 16px; height: 16px; }
  .method-hint {
    font-size: 12px;
    color: var(--tg-theme-hint-color, #999);
    padding: 2px 4px 8px;
  }
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
  button.secondary {
    background: var(--tg-theme-secondary-bg-color, #f2f2f2);
    color: var(--tg-theme-text-color, #000000);
  }
  button.small {
    width: auto;
    padding: 6px 10px;
    font-size: 13px;
    font-weight: 500;
  }
  button.danger { background: #d33; color: #fff; }
  #status { margin-top: 12px; font-size: 14px; color: var(--tg-theme-hint-color, #999); min-height: 1.2em; }
  .field-label { font-size: 13px; color: var(--tg-theme-hint-color, #999); margin: 0 0 6px; }
  .dur-row { display: flex; gap: 8px; margin-bottom: 8px; }
  .dur-row input[type="number"], .dur-row select {
    flex: 1;
    padding: 10px;
    border-radius: 10px;
    border: none;
    background: var(--tg-theme-secondary-bg-color, #f2f2f2);
    color: var(--tg-theme-text-color, #000000);
    font-size: 15px;
  }
  #labelInput {
    width: 100%;
    box-sizing: border-box;
    padding: 10px 12px;
    border-radius: 10px;
    border: none;
    background: var(--tg-theme-secondary-bg-color, #f2f2f2);
    color: var(--tg-theme-text-color, #000000);
    font-size: 15px;
    margin-bottom: 8px;
  }
  .tabs { display: flex; gap: 8px; margin-bottom: 16px; }
  .tab-btn {
    flex: 1;
    padding: 10px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 600;
    background: var(--tg-theme-secondary-bg-color, #f2f2f2);
    color: var(--tg-theme-text-color, #000000);
    opacity: .6;
  }
  .tab-btn.active {
    background: var(--tg-theme-button-color, #2481cc);
    color: var(--tg-theme-button-text-color, #ffffff);
    opacity: 1;
  }
  .win-card {
    padding: 12px;
    margin-bottom: 10px;
    border-radius: 10px;
    background: var(--tg-theme-secondary-bg-color, #f2f2f2);
  }
  .win-title { font-size: 14px; font-weight: 600; margin-bottom: 4px; word-break: break-all; }
  .win-meta { font-size: 13px; color: var(--tg-theme-hint-color, #999); margin-bottom: 8px; }
  .win-actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .win-actions button { width: auto; flex: 0 0 auto; }
  .win-note-link { display: block; margin-top: 8px; word-break: break-all; font-size: 13px; color: var(--tg-theme-link-color, #2481cc); }
  .empty-hint { font-size: 14px; color: var(--tg-theme-hint-color, #999); text-align: center; padding: 24px 0; }
  .modal {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.5);
    display: flex;
    align-items: flex-end;
    justify-content: center;
    z-index: 10;
  }
  .modal-content {
    width: 100%;
    max-width: 480px;
    max-height: 85vh;
    overflow-y: auto;
    box-sizing: border-box;
    padding: 16px;
    border-radius: 16px 16px 0 0;
    background: var(--tg-theme-bg-color, #ffffff);
    color: var(--tg-theme-text-color, #000000);
  }
</style>
</head>
<body>
  <h1>automation_key</h1>
  <div class="tabs">
    <button class="tab-btn active" id="tabBtnGenerate">Выпустить</button>
    <button class="tab-btn" id="tabBtnManage">Мои ключи</button>
    ${hasConsentHub ? '<button class="tab-btn" id="tabBtnHub">Подтверждения</button>' : ""}
  </div>
  <div id="hubStatus" class="field-label" style="display:none;margin:-8px 0 12px"></div>

  <div id="tabGenerate">
  <div id="services">
      ${checkboxes}
  </div>
  <label class="row"><input type="checkbox" id="all"> Все сразу</label>
  <div class="sep"></div>
  <p class="field-label">Срок действия</p>
  <div class="dur-row">
    <input type="number" id="durNum" min="1" step="1" value="3">
    <select id="durUnit">
      <option value="hours" selected>часы</option>
      <option value="days">дни</option>
      <option value="weeks">недели</option>
      <option value="months">месяцы</option>
    </select>
  </div>
  <label class="row"><input type="checkbox" id="infinite"> Бессрочно</label>
  <div class="sep"></div>
  <p class="field-label">Название (необязательно)</p>
  <input type="text" id="labelInput" placeholder="например: рабочий ноутбук">
  <div class="sep"></div>
  <button id="go" disabled>Получить ключ</button>
  <div id="status"></div>
  </div>

  <div id="tabManage" style="display:none">
    <div id="manageStatus" class="field-label"></div>
    <div id="windowList"></div>
  </div>

  <div id="editModal" class="modal" style="display:none">
    <div class="modal-content">
      <p class="field-label">Изменить доступ — <span id="editWindowLabel"></span></p>
      <div id="editServices"></div>
      <label class="row"><input type="checkbox" id="editAll"> Все сразу</label>
      <div class="sep"></div>
      <button id="editSave">Сохранить</button>
      <button id="editCancel" class="secondary" style="margin-top:8px">Отмена</button>
      <div id="editStatus" class="field-label"></div>
    </div>
  </div>

<script>
(function () {
  var tg = window.Telegram && window.Telegram.WebApp;
  if (tg) { tg.ready(); tg.expand(); }

  var ALL_SERVICES = ${servicesJson};
  var SERVICE_LABELS = ${serviceLabelsJson};
  var NO_CATALOG_SERVICES = ${noCatalogServicesJson};
  var CATALOG_URLS = ${catalogUrlsJson};

  function initData() { return tg ? tg.initData : ""; }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function hasCatalogFor(svc) {
    return NO_CATALOG_SERVICES.indexOf(svc) === -1;
  }

  // ── Автосправочник методов (docs/TZ_automation_key_method_catalog.md) ──
  // Фетчится ОДИН РАЗ за загрузку страницы, для собственного сервиса
  // (same-origin '/automation-key-catalog') и для 4 соседних (calendar/
  // drive/sheets/docs — абсолютные URL-ы из CATALOG_URLS, заданы сервером
  // из env). ticktick сюда никогда не идёт (нет роута вовсе, ТЗ раздел
  // "Явно НЕ входит"). CATALOGS[svc] === null означает "недоступен/нет
  // каталога" — единственный сигнал деградации до чекбокса "весь сервис",
  // и для ticktick, и для сбоя сети у любого из четырёх соседей.
  var CATALOGS = {};
  var catalogsReady = Promise.all(
    ALL_SERVICES.map(function (svc) {
      if (!hasCatalogFor(svc)) { CATALOGS[svc] = null; return Promise.resolve(); }
      var url = CATALOG_URLS[svc];
      return fetch(url)
        .then(function (res) { if (!res.ok) throw new Error("HTTP " + res.status); return res.json(); })
        .then(function (data) { CATALOGS[svc] = Array.isArray(data && data.tools) ? data.tools : null; })
        .catch(function () { CATALOGS[svc] = null; }); // деградация — только чекбокс всего сервиса (ТЗ раздел 6, п.2)
    }),
  );

  // ───────────────────────── Дерево «сервис → методы» ────────────────────
  // Переиспользуемый компонент (docs/TZ_automation_key_method_catalog.md,
  // раздел "Мини-апп — дерево «сервис → методы»"): ОДНА и та же логика
  // прикрепления/чтения/применения состояния используется И на табе
  // «Выпустить» (attachToExisting — чекбоксы сервисов уже в статической
  // разметке), И в модалке «Изменить доступ» (buildFresh — чекбоксы
  // создаются с нуля). DOM создаётся по-разному (там разный контекст
  // разметки), но СЕМАНТИКА выбора — общая, в этом объекте.
  var ServiceScopeTree = {
    /** Строит nested-список методов внутри methodsWrapEl для одного
     * сервиса; вешает обработчики, синхронизирующие serviceBoxEl с детьми
     * в обе стороны. Возвращает {serviceBox, methodBoxes}. */
    attachService: function (svc, serviceBoxEl, methodsWrapEl, onChange) {
      methodsWrapEl.innerHTML = "";
      var tools = CATALOGS[svc];
      var methodBoxes = [];

      function syncServiceFromMethods() {
        if (!methodBoxes.length) return;
        serviceBoxEl.checked = methodBoxes.every(function (b) { return b.checked; });
      }

      if (tools === null || tools === undefined) {
        var hint = document.createElement("div");
        hint.className = "method-hint";
        hint.textContent = hasCatalogFor(svc)
          ? "Методы недоступны (справочник сейчас не отвечает) — выдам доступ на весь сервис."
          : "У этого сервиса нет справочника методов — доступ только на весь сервис целиком.";
        methodsWrapEl.appendChild(hint);
      } else if (tools.length === 0) {
        var hint2 = document.createElement("div");
        hint2.className = "method-hint";
        hint2.textContent = "У этого сервиса пока нет гейтированных методов.";
        methodsWrapEl.appendChild(hint2);
      } else {
        tools.forEach(function (t) {
          var mRow = document.createElement("label");
          mRow.className = "row method-row";
          var mBox = document.createElement("input");
          mBox.type = "checkbox";
          mBox.className = "method";
          mBox.value = t.name;
          if (t.description) mBox.title = t.description;
          mRow.appendChild(mBox);
          mRow.appendChild(document.createTextNode(" " + t.name));
          methodsWrapEl.appendChild(mRow);
          methodBoxes.push(mBox);
          mBox.addEventListener("change", function () {
            syncServiceFromMethods();
            onChange();
          });
        });
      }

      serviceBoxEl.addEventListener("change", function () {
        // Чекбокс сервиса = «выбрать все его методы» (если каталог есть).
        methodBoxes.forEach(function (b) { b.checked = serviceBoxEl.checked; });
        onChange();
      });

      return { serviceBox: serviceBoxEl, methodBoxes: methodBoxes };
    },

    /** Строит ВЕСЬ tree (все 6 сервисов, каждый — свежий serviceBox + nested
     * methods) внутри containerEl с нуля — используется модалкой «Изменить
     * доступ», где разметки ещё нет. */
    buildFresh: function (containerEl, onChange) {
      containerEl.innerHTML = "";
      var entries = {};
      ALL_SERVICES.forEach(function (svc) {
        var wrap = document.createElement("div");
        wrap.className = "svc-block";
        var row = document.createElement("label");
        row.className = "row";
        var box = document.createElement("input");
        box.type = "checkbox";
        box.className = "svc edit-svc";
        box.value = svc;
        row.appendChild(box);
        row.appendChild(document.createTextNode(" " + (SERVICE_LABELS[svc] || svc)));
        wrap.appendChild(row);
        var methodsWrap = document.createElement("div");
        methodsWrap.className = "methods-wrap";
        wrap.appendChild(methodsWrap);
        containerEl.appendChild(wrap);
        entries[svc] = ServiceScopeTree.attachService(svc, box, methodsWrap, onChange);
      });
      return entries;
    },

    /** Собирает scope-токены из текущего состояния DOM (ТЗ раздел 6, п.3):
     * весь сервис отмечен ИЛИ все его методы отмечены → bare '<service>';
     * часть методов → '<service>:<tool>' на каждый; ничего не отмечено у
     * сервиса → сервис в токены не попадает вовсе. */
    getTokens: function (entries) {
      var tokens = [];
      ALL_SERVICES.forEach(function (svc) {
        var e = entries[svc];
        if (!e) return;
        if (!e.methodBoxes.length) {
          if (e.serviceBox.checked) tokens.push(svc);
          return;
        }
        var checked = e.methodBoxes.filter(function (b) { return b.checked; });
        if (checked.length === 0) return;
        if (checked.length === e.methodBoxes.length) {
          tokens.push(svc);
        } else {
          checked.forEach(function (b) { tokens.push(svc + ":" + b.value); });
        }
      });
      return tokens;
    },

    /** true, если ХОТЯ БЫ один сервис/метод отмечен где-либо в дереве. */
    anySelected: function (entries) {
      return ServiceScopeTree.getTokens(entries).length > 0;
    },

    /** Отмечает/снимает ВСЁ дерево целиком (кнопка «Все сразу»). */
    setAll: function (entries, checked) {
      ALL_SERVICES.forEach(function (svc) {
        var e = entries[svc];
        if (!e) return;
        e.serviceBox.checked = checked;
        e.methodBoxes.forEach(function (b) { b.checked = checked; });
      });
    },

    /** true, если КАЖДЫЙ сервис в дереве полностью отмечен (для синхронизации
     * верхнего чекбокса «Все сразу»/«editAll» с состоянием дерева). */
    isAllSelected: function (entries) {
      return ALL_SERVICES.every(function (svc) {
        var e = entries[svc];
        if (!e) return false;
        if (!e.methodBoxes.length) return e.serviceBox.checked;
        return e.methodBoxes.every(function (b) { return b.checked; });
      });
    },

    /** Разбирает существующий canonical 'scope' ("all" | csv из bare-service
     * и/или 'service:tool' токенов) в состояние DOM — используется модалкой
     * «Изменить доступ» при открытии на уже выпущенном окне. */
    applyScope: function (entries, scope) {
      var perService = {}; // svc -> true | {tool: true, ...}
      if (scope === "all") {
        ALL_SERVICES.forEach(function (s) { perService[s] = true; });
      } else {
        scope.split(",").map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (t) {
          var idx = t.indexOf(":");
          if (idx === -1) {
            perService[t] = true;
          } else {
            var svc = t.slice(0, idx);
            var tool = t.slice(idx + 1);
            if (perService[svc] !== true) {
              if (!perService[svc]) perService[svc] = {};
              perService[svc][tool] = true;
            }
          }
        });
      }
      ALL_SERVICES.forEach(function (svc) {
        var e = entries[svc];
        if (!e) return;
        var sel = perService[svc];
        if (sel === true) {
          e.serviceBox.checked = true;
          e.methodBoxes.forEach(function (b) { b.checked = true; });
        } else if (sel && typeof sel === "object") {
          e.methodBoxes.forEach(function (b) { b.checked = !!sel[b.value]; });
          // Без каталога методов (methodBoxes пуст), но токены service:tool
          // всё равно пришли (например, каталог соседа временно недоступен
          // именно СЕЙЧАС, хотя при выдаче ключа был доступен) — честно
          // показываем это как "весь сервис", а не молча теряем выбор.
          if (!e.methodBoxes.length) e.serviceBox.checked = true;
          else e.serviceBox.checked = e.methodBoxes.every(function (b) { return b.checked; });
        } else {
          e.serviceBox.checked = false;
          e.methodBoxes.forEach(function (b) { b.checked = false; });
        }
      });
    },
  };

  // ───────────────────────── Таб «Выпустить» ────────────────────────────
  var allBox = document.getElementById("all");
  var goBtn = document.getElementById("go");
  var statusEl = document.getElementById("status");
  var durNum = document.getElementById("durNum");
  var durUnit = document.getElementById("durUnit");
  var infiniteBox = document.getElementById("infinite");
  var labelInput = document.getElementById("labelInput");

  // Прикрепляем дерево методов к уже отрендеренным сервером '.svc'-чекбоксам
  // (id="methods-<svc>" рядом с каждым — см. renderAutomationKeyMiniAppPage).
  // Пока каталоги грузятся — методы просто ещё не показаны (голый чекбокс
  // сервиса работает и без них, тот же деградационный принцип).
  var genEntries = {};
  ALL_SERVICES.forEach(function (svc) {
    var box = document.querySelector('.svc[value="' + svc + '"]');
    var wrap = document.getElementById("methods-" + svc);
    if (box && wrap) genEntries[svc] = ServiceScopeTree.attachService(svc, box, wrap, refresh);
  });
  catalogsReady.then(function () {
    // Каталоги догрузились — перестраиваем дерево генерации с реальными
    // методами (пере-attach на те же DOM-узлы, состояние чекбоксов сервисов
    // сохраняется — просто у них теперь появляются дети).
    ALL_SERVICES.forEach(function (svc) {
      var box = document.querySelector('.svc[value="' + svc + '"]');
      var wrap = document.getElementById("methods-" + svc);
      if (box && wrap) genEntries[svc] = ServiceScopeTree.attachService(svc, box, wrap, refresh);
    });
    refresh();
  });

  // Единицы срока → миллисекунды (ТЗ раздел 1). "months" — условно 30 дней,
  // как и везде в этой экосистеме, где нет полноценного календаря месяцев.
  var UNIT_MS = { hours: 3600000, days: 86400000, weeks: 7 * 86400000, months: 30 * 86400000 };

  function refresh() {
    goBtn.disabled = !ServiceScopeTree.anySelected(genEntries);
    allBox.checked = ServiceScopeTree.isAllSelected(genEntries);
  }

  allBox.addEventListener("change", function () {
    ServiceScopeTree.setAll(genEntries, allBox.checked);
    refresh();
  });

  infiniteBox.addEventListener("change", function () {
    durNum.disabled = infiniteBox.checked;
    durUnit.disabled = infiniteBox.checked;
  });

  // Возвращает { ok: true, durationMs } или { ok: false } — false на кривом
  // вводе (пусто/0/отрицательное/не число), чтобы кнопка отказалась слать
  // запрос ДО backend'а (который тоже проверяет — см. http.ts, ТЗ раздел 1:
  // "не отрицательное, не абсурдно маленькое типа 0").
  function computeDuration() {
    if (infiniteBox.checked) return { ok: true, durationMs: null };
    var n = parseFloat(durNum.value);
    if (!isFinite(n) || n <= 0) return { ok: false };
    var unitMs = UNIT_MS[durUnit.value] || UNIT_MS.hours;
    return { ok: true, durationMs: Math.round(n * unitMs) };
  }

  goBtn.addEventListener("click", function () {
    var scopeTokens = ServiceScopeTree.getTokens(genEntries);
    if (scopeTokens.length === 0) return; // fail-closed на фронтенде тоже, но backend не полагается на это
    var duration = computeDuration();
    if (!duration.ok) {
      statusEl.textContent = "Укажи положительный срок или отметь «Бессрочно».";
      return;
    }
    var label = labelInput.value.trim();
    goBtn.disabled = true;
    statusEl.textContent = "Генерирую...";
    fetch("/automation-key-app/generate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        initData: tg ? tg.initData : "",
        scopeTokens: scopeTokens,
        durationMs: duration.durationMs,
        label: label === "" ? null : label,
      }),
    })
      .then(function (res) {
        if (!res.ok) return res.json().catch(function () { return {}; }).then(function (body) {
          throw new Error(body && body.error ? body.error : ("HTTP " + res.status));
        });
        return res.json();
      })
      .then(function (data) {
        // Ссылка на self-destruct-заметку показывается ПРЯМО НА СТРАНИЦЕ
        // (ТЗ раздел "Где показывается") — не только "отправлено в чат"
        // текстом, как было раньше. Ключ ТАКЖЕ дублируется сообщением в чат
        // той же generateAndDeliverKey на backend'е — сознательное решение
        // не убирать дублирование, страница мини-аппа может закрыться раньше,
        // чем владелец успеет скопировать ссылку.
        statusEl.textContent = "";
        if (data && data.noteLink) {
          var p = document.createElement("div");
          p.textContent = "Готово — ссылка одноразовая, действует час до первого клика (и продублирована в чат):";
          statusEl.appendChild(p);
          var openBtn = document.createElement("button");
          openBtn.textContent = "Открыть заметку";
          openBtn.style.marginTop = "8px";
          openBtn.addEventListener("click", function () {
            if (tg && tg.openLink) tg.openLink(data.noteLink);
            else window.open(data.noteLink, "_blank");
          });
          statusEl.appendChild(openBtn);
          var link = document.createElement("a");
          link.href = data.noteLink;
          link.textContent = data.noteLink;
          link.target = "_blank";
          link.rel = "noopener";
          link.style.cssText = "display:block;margin-top:8px;word-break:break-all;color:var(--tg-theme-link-color,#2481cc);";
          statusEl.appendChild(link);
        } else {
          statusEl.textContent = "Окно создано, но защищённую ссылку выдать не удалось — подробности в чате (сообщение об ошибке).";
        }
      })
      .catch(function (err) {
        statusEl.textContent = "Ошибка: " + err.message;
        goBtn.disabled = false;
      });
  });

  refresh();

  // ───────────────────────── Таб «Мои ключи» (менеджер) ─────────────────────
  var tabBtnGenerate = document.getElementById("tabBtnGenerate");
  var tabBtnManage = document.getElementById("tabBtnManage");
  var tabGenerate = document.getElementById("tabGenerate");
  var tabManage = document.getElementById("tabManage");
  var manageStatusEl = document.getElementById("manageStatus");
  var windowListEl = document.getElementById("windowList");
  var manageLoadedOnce = false;

  function showTab(name) {
    var showGenerate = name === "generate";
    tabGenerate.style.display = showGenerate ? "" : "none";
    tabManage.style.display = showGenerate ? "none" : "";
    tabBtnGenerate.className = "tab-btn" + (showGenerate ? " active" : "");
    tabBtnManage.className = "tab-btn" + (showGenerate ? "" : " active");
    if (!showGenerate) loadWindowList();
  }
  tabBtnGenerate.addEventListener("click", function () { showTab("generate"); });
  tabBtnManage.addEventListener("click", function () { showTab("manage"); });

  // ─────────────────── Вкладка «Подтверждения» (переход в хаб) ──────────────
  // Не переключает локальные панели, как две другие вкладки — уводит на
  // отдельную страницу /consent-hub/<secret> (docs/TZ_consent_web_hub.md
  // часть 2). Секрет НИКОГДА не попадает в статичный HTML этой страницы
  // (она отдаётся без авторизации, ТЗ раздел 1) — ссылку с секретом отдаёт
  // отдельный POST-роут, защищённый тем же initData-owner-чеком, что и
  // «Выпустить»/«Отозвать» ниже.
  var tabBtnHub = document.getElementById("tabBtnHub");
  var hubStatusEl = document.getElementById("hubStatus");
  if (tabBtnHub) {
    tabBtnHub.addEventListener("click", function () {
      tabBtnHub.disabled = true;
      var prevLabel = tabBtnHub.textContent;
      tabBtnHub.textContent = "Открываю…";
      hubStatusEl.style.display = "none";
      fetch("/automation-key-app/consent-hub-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ initData: initData() }),
      })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, body: d }; }); })
        .then(function (res) {
          if (res.ok && res.body && res.body.url) {
            location.href = res.body.url;
            return;
          }
          tabBtnHub.disabled = false;
          tabBtnHub.textContent = prevLabel;
          hubStatusEl.textContent = "Не получилось открыть хаб — попробуйте ещё раз.";
          hubStatusEl.style.display = "";
        })
        .catch(function () {
          tabBtnHub.disabled = false;
          tabBtnHub.textContent = prevLabel;
          hubStatusEl.textContent = "Нет соединения — попробуйте ещё раз.";
          hubStatusEl.style.display = "";
        });
    });
  }

  var STATUS_BADGE = {
    active: "✅ активен",
    expired: "⌛ истёк",
    revoked: "🚫 отозван",
  };

  function formatWhen(ms) {
    if (ms === null || ms === undefined) return "";
    try {
      return new Date(ms).toLocaleString("ru-RU", { timeZone: "America/Los_Angeles", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
    } catch (e) {
      return new Date(ms).toISOString();
    }
  }

  function windowCard(w) {
    var card = document.createElement("div");
    card.className = "win-card";

    var title = document.createElement("div");
    title.className = "win-title";
    title.textContent = "#" + w.windowId + (w.label ? " · " + w.label : "");
    card.appendChild(title);

    var meta = document.createElement("div");
    meta.className = "win-meta";
    var statusText = STATUS_BADGE[w.status] || w.status;
    var durationText = w.status === "revoked"
      ? "отозван " + formatWhen(w.revokedAt)
      : w.expiresAt === null
        ? "♾ бессрочно"
        : w.status === "expired"
          ? "истёк " + formatWhen(w.expiresAt)
          : "до " + formatWhen(w.expiresAt);
    meta.textContent = w.scopeHuman + " · " + statusText + " · " + durationText;
    card.appendChild(meta);

    if (w.status === "active") {
      var actions = document.createElement("div");
      actions.className = "win-actions";

      var revokeBtn = document.createElement("button");
      revokeBtn.className = "small danger";
      revokeBtn.textContent = "Отозвать";
      revokeBtn.addEventListener("click", function () { revokeWindow(w.windowId, card); });
      actions.appendChild(revokeBtn);

      var editBtn = document.createElement("button");
      editBtn.className = "small secondary";
      editBtn.textContent = "Изменить доступ";
      editBtn.addEventListener("click", function () { openEditModal(w); });
      actions.appendChild(editBtn);

      if (w.hasStoredToken) {
        var reissueBtn = document.createElement("button");
        reissueBtn.className = "small secondary";
        reissueBtn.textContent = "Ещё раз показать";
        reissueBtn.addEventListener("click", function () { reissueNote(w.windowId, card); });
        actions.appendChild(reissueBtn);
      }

      card.appendChild(actions);
    }

    var noteArea = document.createElement("div");
    noteArea.className = "win-note-area";
    card.appendChild(noteArea);

    return card;
  }

  function loadWindowList() {
    manageStatusEl.textContent = "Загружаю...";
    windowListEl.innerHTML = "";
    fetch("/automation-key-app/list", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ initData: initData() }),
    })
      .then(function (res) {
        if (!res.ok) return res.json().catch(function () { return {}; }).then(function (body) {
          throw new Error(body && body.error ? body.error : ("HTTP " + res.status));
        });
        return res.json();
      })
      .then(function (data) {
        manageLoadedOnce = true;
        var windows = (data && data.windows) || [];
        if (windows.length === 0) {
          manageStatusEl.textContent = "";
          var empty = document.createElement("div");
          empty.className = "empty-hint";
          empty.textContent = "Ключей ещё не выдавалось.";
          windowListEl.appendChild(empty);
          return;
        }
        manageStatusEl.textContent = data.total > windows.length
          ? "Показаны последние " + windows.length + " из " + data.total
          : "";
        windows.forEach(function (w) { windowListEl.appendChild(windowCard(w)); });
      })
      .catch(function (err) {
        manageStatusEl.textContent = "Ошибка: " + err.message;
      });
  }

  function revokeWindow(windowId, card) {
    if (!window.confirm("Отозвать окно #" + windowId + "?")) return;
    fetch("/automation-key-app/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ initData: initData(), windowId: windowId }),
    })
      .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
      .then(function (r) {
        if (r.status !== 200 || !r.body.ok) throw new Error((r.body && r.body.error) || ("HTTP " + r.status));
        loadWindowList();
      })
      .catch(function (err) {
        var note = card.querySelector(".win-note-area");
        note.textContent = "Ошибка отзыва: " + err.message;
      });
  }

  var REISSUE_ERROR_TEXT = {
    window_not_found: "окно не найдено",
    window_revoked: "окно уже отозвано",
    window_expired: "окно уже истекло",
    no_stored_token: "для этого окна нет сохранённого ключа (выпущено до включения этой возможности или без настроенного мастер-секрета)",
    master_secret_not_configured: "перевыпуск выключен — не задан AUTOMATION_KEY_MASTER_SECRET",
    decrypt_failed: "не удалось расшифровать сохранённый ключ",
    note_service_unavailable: "сервис self-destroyed-notes сейчас недоступен, попробуй ещё раз позже",
  };

  function reissueNote(windowId, card) {
    var note = card.querySelector(".win-note-area");
    note.textContent = "Готовлю ссылку...";
    fetch("/automation-key-app/reissue-note", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ initData: initData(), windowId: windowId }),
    })
      .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
      .then(function (r) {
        if (r.status !== 200 || !r.body.ok) {
          var reason = (r.body && r.body.error) || "";
          throw new Error(REISSUE_ERROR_TEXT[reason] || reason || ("HTTP " + r.status));
        }
        note.innerHTML = "";
        var p = document.createElement("div");
        p.textContent = "Готово — одноразовая ссылка (действует час до первого клика):";
        note.appendChild(p);
        var link = document.createElement("a");
        link.href = r.body.noteLink;
        link.textContent = r.body.noteLink;
        link.target = "_blank";
        link.rel = "noopener";
        link.className = "win-note-link";
        note.appendChild(link);
      })
      .catch(function (err) {
        note.textContent = "Ошибка: " + err.message;
      });
  }

  // ── Модалка «Изменить доступ» ──
  var editModal = document.getElementById("editModal");
  var editServicesEl = document.getElementById("editServices");
  var editAllBox = document.getElementById("editAll");
  var editWindowLabel = document.getElementById("editWindowLabel");
  var editSaveBtn = document.getElementById("editSave");
  var editCancelBtn = document.getElementById("editCancel");
  var editStatusEl = document.getElementById("editStatus");
  var editWindowId = null;

  var editEntries = {};

  function refreshEditAll() {
    editAllBox.checked = ServiceScopeTree.isAllSelected(editEntries);
  }

  /** Строит дерево «сервис → методы» модалки — ТЕМ ЖЕ переиспользуемым
   * компонентом ('ServiceScopeTree'), что и таб «Выпустить» выше, и
   * применяет текущий 'scope' окна как начальное состояние (docs/
   * TZ_automation_key_method_catalog.md: "смена scope там ТОЖЕ должна
   * получить возможность выбора по методам"). Каталоги к этому моменту уже
   * либо загружены, либо гарантированно провалились ('catalogsReady') — ждём
   * его перед построением, чтобы не показать пустое дерево, которое через
   * секунду перестроится под ногами у владельца.
   */
  function openEditModal(w) {
    editWindowId = w.windowId;
    editWindowLabel.textContent = "#" + w.windowId + (w.label ? " · " + w.label : "");
    editStatusEl.textContent = "";
    editServicesEl.innerHTML = '<div class="method-hint">Загружаю методы...</div>';
    editModal.style.display = "flex";
    catalogsReady.then(function () {
      if (editWindowId !== w.windowId) return; // модалку успели закрыть/открыть заново на другое окно
      editEntries = ServiceScopeTree.buildFresh(editServicesEl, refreshEditAll);
      ServiceScopeTree.applyScope(editEntries, w.scope);
      refreshEditAll();
    });
  }

  editAllBox.addEventListener("change", function () {
    ServiceScopeTree.setAll(editEntries, editAllBox.checked);
  });

  editCancelBtn.addEventListener("click", function () {
    editModal.style.display = "none";
    editWindowId = null;
  });

  editSaveBtn.addEventListener("click", function () {
    var scopeTokens = ServiceScopeTree.getTokens(editEntries);
    if (scopeTokens.length === 0) {
      editStatusEl.textContent = "Отметь хотя бы один сервис или метод.";
      return;
    }
    editSaveBtn.disabled = true;
    editStatusEl.textContent = "Сохраняю...";
    fetch("/automation-key-app/update-scope", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ initData: initData(), windowId: editWindowId, scopeTokens: scopeTokens }),
    })
      .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
      .then(function (r) {
        editSaveBtn.disabled = false;
        if (r.status !== 200 || !r.body.ok) throw new Error((r.body && r.body.error) || ("HTTP " + r.status));
        editModal.style.display = "none";
        editWindowId = null;
        loadWindowList();
      })
      .catch(function (err) {
        editSaveBtn.disabled = false;
        editStatusEl.textContent = "Ошибка: " + err.message;
      });
  });
})();
</script>
</body>
</html>`;
}
