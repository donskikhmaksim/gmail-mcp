/**
 * consent_hub.ts — веб-хаб подтверждений (docs/TZ_consent_web_hub.md, часть 2).
 *
 * Два самостоятельных куска, специально в одном файле (та же логика, что
 * держит `dashboard.ts` рядом с его собственным HTML — один маленький
 * фичевый модуль, не размазанный по http.ts):
 *
 *  1. `summarizePendingManifest` — ЧЕСТНО ДЕГРАДИРУЮЩЕЕ извлечение
 *     `title`/`summary`/`preview` из уже сохранённого `payload` манифеста.
 *
 *     РЕШЕНИЕ, ЗАФИКСИРОВАННОЕ В ОТЧЁТЕ (ТЗ часть 2 п.1 прямо это допускает):
 *     `consent_manifests` НЕ хранит текст превью, который видела модель/
 *     Telegram (`ConsentPlan.preview` — эфемерный, строится закрытием
 *     `plan()` внутри каждого тула и живёт только в момент вызова, в БД не
 *     пишется — см. `consent.ts`). Схему не трогаем (ТЗ явно запрещает
 *     миграцию ради этого), поэтому title/summary/preview для хаба строятся
 *     ЗАНОВО, ОБЩИМ (не per-tool) способом — из `tool` + уже сохранённого
 *     `payload` (JSONB), который переживает манифест целиком. Это НЕ то же
 *     самое, что видела модель в Telegram (там могли быть точные суммы,
 *     здесь — только то, что есть в payload), но честно достаточно для
 *     «прочитать и решить» в хабе.
 *
 *  2. `renderConsentHubPage` — адаптивная HTML-страница. Разметка/CSS/JS
 *     взяты за основу из `scratchpad/consent_web_demo.html` (готовый
 *     прототип, ТЗ явно велит не изобретать заново), демо-массив `ITEMS`
 *     заменён на `fetch("/consent-hub-api/pending")`, кнопки подключены к
 *     `POST /consent-hub-api/decide`.
 */

import type { PendingConsentRow } from "./store.js";

// ───────────────────────── 1. Превью для списка ────────────────────────────

/** Человекочитаемые заголовки для уже известных инструментов — только
 * косметика (заголовок карточки), отсутствие записи не ломает ничего:
 * фолбэк — само имя тула. */
const TOOL_TITLES: Record<string, string> = {
  gmail_send: "Отправить письмо",
  gmail_reply: "Ответить на письмо",
  gmail_forward: "Переслать письмо",
  gmail_create_draft: "Создать черновик",
  gmail_archive: "Архивировать",
  gmail_trash: "Удалить (в корзину)",
  gmail_modify_labels: "Изменить метки",
  gmail_snooze: "Отложить письмо",
  gmail_schedule_send: "Запланировать отправку",
  gmail_cancel_scheduled_send: "Отменить запланированную отправку",
  gmail_save_attachment_to_drive: "Сохранить вложение в Drive",
  gmail_create_label: "Создать метку",
  gmail_update_label: "Переименовать метку",
  gmail_delete_label: "Удалить метку",
  gmail_export_thread_eml: "Экспортировать переписку",
  gmail_create_upload_session: "Загрузить вложение",
  gmail_get_download_url: "Выдать ссылку на скачивание",
};

function truncate(s: string, max: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  if (one.length <= max) return one;
  let out = "";
  for (const ch of one) {
    if (out.length + ch.length > max) break;
    out += ch;
  }
  return out + "…";
}

/** Первый непустой batch-массив в payload — общая для ВСЕХ инструментов
 * форма (`{account, messages:[...]}` / `{account, items:[...]}` / …), без
 * per-tool ветвления. */
function firstBatchArray(payload: unknown): unknown[] {
  if (!payload || typeof payload !== "object") return [];
  const obj = payload as Record<string, unknown>;
  for (const key of ["messages", "replies", "items", "drafts", "labels", "files", "labelsAdd"]) {
    const v = obj[key];
    if (Array.isArray(v) && v.length) return v;
  }
  return [];
}

function pickBits(first: Record<string, unknown>): string[] {
  const bits: string[] = [];
  const to = first.to;
  if (typeof to === "string") bits.push(to);
  else if (Array.isArray(to) && typeof to[0] === "string") bits.push(to[0]);
  if (typeof first.subject === "string" && first.subject) bits.push(`«${truncate(first.subject, 50)}»`);
  if (typeof first.name === "string" && first.name) bits.push(first.name);
  if (typeof first.filename === "string" && first.filename) bits.push(first.filename);
  if (typeof first.messageId === "string" && first.messageId) bits.push(first.messageId.slice(0, 12));
  return bits;
}

/** Короткая строка-сводка для списка — best-effort, из первого элемента
 * batch-массива (см. `firstBatchArray`). Пусто — фолбэк на имя тула. */
function summarize(tool: string, payload: unknown): string {
  const arr = firstBatchArray(payload);
  if (!arr.length) return tool;
  const first = arr[0];
  const bits = first && typeof first === "object" ? pickBits(first as Record<string, unknown>) : [];
  let summary = bits.length ? bits.join(" — ") : tool;
  if (arr.length > 1) summary += ` (+${arr.length - 1})`;
  return summary;
}

export interface PendingConsentItem {
  manifestId: string;
  tool: string;
  title: string;
  summary: string;
  preview: string;
  createdAt: number;
  expiresAt: number;
  accountLabel: string;
}

/** Строит `title`/`summary`/`preview` из уже сохранённой строки манифеста —
 * см. doc-comment файла про то, почему это фолбэк, а не точный пересказ
 * того, что видела модель/Telegram. */
export function summarizePendingManifest(row: PendingConsentRow): PendingConsentItem {
  const title = TOOL_TITLES[row.tool] ?? row.tool;
  const summary = truncate(summarize(row.tool, row.payload), 90);
  const preview = `### ${title}\n\n${JSON.stringify(row.payload, null, 2)}`;
  return {
    manifestId: row.id,
    tool: row.tool,
    title,
    summary,
    preview: truncate(preview, 4000),
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    accountLabel: row.accountLabel,
  };
}

// ───────────────────────── 2. HTML-страница хаба ────────────────────────────

/**
 * Секрет НЕ подставляется в JS буквально — страница отдаётся уже ПО
 * секретному пути (`/consent-hub/<secret>`), а браузер шлёт его обратно как
 * заголовок `X-Consent-Hub-Secret` на `/consent-hub-api/*` (тот же секрет,
 * прочитанный из URL текущей страницы через `location.pathname` — сервер не
 * обязан второй раз печатать его в разметке).
 */
export function renderConsentHubPage(): string {
  return `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Подтверждения — gmail-mcp hub</title>
<style>
:root {
  --paper: #f6f6f3; --paper-raised: #ffffff; --ink: #1b1d1c; --ink-soft: #55584f; --ink-mute: #8a8d82;
  --line: #dedcd3; --line-strong: #c7c4b7; --accent: #3a4a5e; --accent-soft: #e7ebee; --accent-ink: #22303f;
  --good: #2f6b4f; --good-soft: #e3efe7; --bad: #a4402f; --bad-soft: #f5e6e2;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace;
  --sans: -apple-system, "Segoe UI", system-ui, sans-serif;
  --svc-gmail: #3a5a8c; --svc-calendar: #3f7a63; --svc-drive: #96562f; --svc-sheets: #4a7a3d; --svc-docs: #6b4f8c;
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper: #17181a; --paper-raised: #202225; --ink: #e9e9e6; --ink-soft: #a9ac9f; --ink-mute: #75776c;
    --line: #33352f; --line-strong: #45483f; --accent: #8fa6bd; --accent-soft: #26333f; --accent-ink: #cfe0ee;
    --good: #7cc79f; --good-soft: #1e3327; --bad: #e08a76; --bad-soft: #3a2420;
    --svc-gmail: #7fa3d6; --svc-calendar: #7ecbaa; --svc-drive: #d69b6b; --svc-sheets: #9fd188; --svc-docs: #b79fdb;
  }
}
:root[data-theme="dark"] {
  --paper: #17181a; --paper-raised: #202225; --ink: #e9e9e6; --ink-soft: #a9ac9f; --ink-mute: #75776c;
  --line: #33352f; --line-strong: #45483f; --accent: #8fa6bd; --accent-soft: #26333f; --accent-ink: #cfe0ee;
  --good: #7cc79f; --good-soft: #1e3327; --bad: #e08a76; --bad-soft: #3a2420;
  --svc-gmail: #7fa3d6; --svc-calendar: #7ecbaa; --svc-drive: #d69b6b; --svc-sheets: #9fd188; --svc-docs: #b79fdb;
}
:root[data-theme="light"] {
  --paper: #f6f6f3; --paper-raised: #ffffff; --ink: #1b1d1c; --ink-soft: #55584f; --ink-mute: #8a8d82;
  --line: #dedcd3; --line-strong: #c7c4b7; --accent: #3a4a5e; --accent-soft: #e7ebee; --accent-ink: #22303f;
  --good: #2f6b4f; --good-soft: #e3efe7; --bad: #a4402f; --bad-soft: #f5e6e2;
  --svc-gmail: #3a5a8c; --svc-calendar: #3f7a63; --svc-drive: #96562f; --svc-sheets: #4a7a3d; --svc-docs: #6b4f8c;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--paper); color: var(--ink); font-family: var(--sans); }
body { padding: 0 0 3rem; }
button { font-family: inherit; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.topbar { display: flex; align-items: center; gap: 10px; padding: 14px 20px; border-bottom: 0.5px solid var(--line); position: sticky; top: 0; background: var(--paper); z-index: 5; }
.topbar .name { font-size: 15px; font-weight: 600; letter-spacing: -0.01em; }
.topbar .sub { font-size: 12px; color: var(--ink-mute); font-family: var(--mono); }
.topbar .count { margin-left: auto; font-family: var(--mono); font-size: 12px; background: var(--accent-soft); color: var(--accent-ink); padding: 3px 9px; border-radius: 999px; }
.hint { margin: 14px 20px 0; padding: 10px 14px; border: 0.5px dashed var(--line-strong); border-radius: 8px; font-size: 12.5px; color: var(--ink-soft); font-family: var(--mono); display: flex; gap: 8px; align-items: baseline; }
.hint.bad { border-color: var(--bad); color: var(--bad); }
.wrap { max-width: 1080px; margin: 0 auto; padding: 18px 20px 0; }
.filters { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }
.chip { font-family: var(--mono); font-size: 12px; padding: 5px 11px; border-radius: 999px; border: 0.5px solid var(--line-strong); color: var(--ink-soft); cursor: pointer; background: transparent; }
.chip.active { background: var(--accent); color: var(--paper-raised); border-color: var(--accent); }
.board { display: grid; grid-template-columns: 1fr; gap: 18px; }
.list { display: flex; flex-direction: column; gap: 8px; }
.empty { padding: 30px 10px; text-align: center; color: var(--ink-mute); font-size: 13px; }
.row { background: var(--paper-raised); border: 0.5px solid var(--line); border-radius: 10px; padding: 12px 14px; cursor: pointer; }
.row.open { border-color: var(--line-strong); }
.row-head { display: flex; align-items: flex-start; gap: 10px; }
.row-head input[type="checkbox"] { margin-top: 4px; width: 16px; height: 16px; accent-color: var(--accent); flex: 0 0 auto; }
.row-main { flex: 1; min-width: 0; }
.row-meta { display: flex; align-items: center; gap: 7px; font-family: var(--mono); font-size: 11.5px; color: var(--ink-mute); margin-bottom: 3px; }
.svc-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; }
.row-title { font-size: 14px; font-weight: 600; letter-spacing: -0.005em; }
.row-sum { font-size: 13px; color: var(--ink-soft); margin-top: 1px; }
.chev { font-family: var(--mono); font-size: 13px; color: var(--ink-mute); margin-top: 2px; }
.detail-inline { margin-top: 10px; padding-top: 10px; border-top: 0.5px solid var(--line); }
.detail-body { font-family: var(--mono); font-size: 12.5px; line-height: 1.65; white-space: pre-wrap; color: var(--ink-soft); background: var(--paper); border: 0.5px solid var(--line); border-radius: 8px; padding: 10px 12px; margin: 0 0 10px; max-height: 50vh; overflow: auto; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
.btn { font-size: 12.5px; font-weight: 600; padding: 7px 13px; border-radius: 7px; border: 0.5px solid var(--line-strong); background: transparent; color: var(--ink); cursor: pointer; }
.btn:hover { border-color: var(--ink-mute); }
.btn:disabled { opacity: 0.5; cursor: default; }
.btn.confirm { background: var(--good-soft); color: var(--good); border-color: transparent; }
.btn.reject { background: var(--bad-soft); color: var(--bad); border-color: transparent; }
.btn.ghost { color: var(--ink-soft); }
.pane { background: var(--paper-raised); border: 0.5px solid var(--line); border-radius: 10px; padding: 20px; display: none; }
.pane .row-meta { font-size: 12px; margin-bottom: 6px; }
.pane .row-title { font-size: 17px; margin-bottom: 14px; }
.pane .detail-body { font-size: 13px; padding: 14px 16px; margin-bottom: 16px; }
.commentbox { display: none; margin: 10px 0; }
.commentbox textarea { width: 100%; min-height: 60px; font-family: var(--sans); font-size: 13px; padding: 8px 10px; border-radius: 7px; border: 0.5px solid var(--line-strong); background: var(--paper); color: var(--ink); }
.bulkbar { position: sticky; bottom: 14px; margin-top: 16px; background: var(--paper-raised); border: 0.5px solid var(--line-strong); border-radius: 10px; padding: 11px 16px; display: none; align-items: center; justify-content: space-between; gap: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
.bulkbar .n { font-size: 13px; color: var(--ink-soft); font-family: var(--mono); }
.bulkbar .btn { background: var(--accent); color: var(--paper-raised); border: none; }
.review { margin-top: 16px; padding: 16px; border: 0.5px solid var(--line-strong); border-radius: 10px; background: var(--paper-raised); display: none; }
.review p { margin: 0 0 12px; font-size: 13px; color: var(--ink-soft); }
.review-item { padding: 8px 10px; border-radius: 7px; background: var(--paper); margin-bottom: 6px; font-size: 13px; }
.review-item b { display: block; font-size: 13.5px; }
@media (min-width: 760px) {
  .wrap { padding-top: 24px; }
  .board { grid-template-columns: 340px 1fr; align-items: start; }
  .detail-inline { display: none; }
  .pane { display: block; position: sticky; top: 74px; }
}
</style>

<div class="topbar">
  <span class="name">Подтверждения</span>
  <span class="sub">gmail-mcp hub</span>
  <span class="count" id="pendingCount"></span>
</div>
<div class="hint" id="statusline" style="display:none"></div>
<div class="wrap">
  <div class="filters" id="filters"></div>
  <div class="board">
    <div class="list" id="list"></div>
    <div class="pane" id="pane"></div>
  </div>
  <div class="bulkbar" id="bulkbar">
    <span class="n" id="bulkcount"></span>
    <button class="btn" id="bulkbtn">Проверить и подтвердить</button>
  </div>
  <div class="review" id="review">
    <p>Финальная проверка — полный текст каждого пункта, прежде чем что-либо произойдёт.</p>
    <div id="reviewlist"></div>
    <button class="btn confirm" id="confirmall" style="width:auto"></button>
  </div>
</div>

<script>
var SERVICES = {
  gmail: { label: "Gmail", color: "var(--svc-gmail)" },
  calendar: { label: "Calendar", color: "var(--svc-calendar)" },
  drive: { label: "Drive", color: "var(--svc-drive)" },
  sheets: { label: "Sheets", color: "var(--svc-sheets)" },
  docs: { label: "Docs", color: "var(--svc-docs)" }
};

var SECRET = location.pathname.split("/").filter(Boolean).pop();
var ITEMS = [];
var UNAVAILABLE = [];
var checked = {};
var openId = null;
var filter = "all";
var openComment = null;

function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function isWide() { return window.matchMedia("(min-width: 760px)").matches; }
function visibleItems() { return ITEMS.filter(function (i) { return filter === "all" || i.service === filter; }); }
function byId(id) { return ITEMS.filter(function (i) { return i.manifestId === id; })[0]; }

function api(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({ "X-Consent-Hub-Secret": SECRET }, opts.headers || {});
  return fetch(path, opts).then(function (res) {
    return res.json().then(function (json) { return { status: res.status, json: json }; });
  });
}

function setStatus(text, bad) {
  var el = document.getElementById("statusline");
  if (!text) { el.style.display = "none"; return; }
  el.style.display = "flex";
  el.className = "hint" + (bad ? " bad" : "");
  el.textContent = text;
}

function load() {
  api("/consent-hub-api/pending", { method: "GET" }).then(function (r) {
    if (r.status !== 200) { setStatus("Не удалось загрузить список (" + r.status + ")", true); return; }
    ITEMS = r.json.items || [];
    UNAVAILABLE = r.json.unavailable || [];
    setStatus(UNAVAILABLE.length ? "Недоступны: " + UNAVAILABLE.join(", ") : "", !!UNAVAILABLE.length);
    if (openId !== null && !ITEMS.some(function (i) { return i.manifestId === openId; })) openId = null;
    renderFilters();
    render();
    renderBulk();
  }).catch(function () { setStatus("Сеть недоступна", true); });
}

function renderFilters() {
  var el = document.getElementById("filters");
  var groups = [{ key: "all", label: "Все · " + ITEMS.length }].concat(
    Object.keys(SERVICES).map(function (k) {
      var n = ITEMS.filter(function (i) { return i.service === k; }).length;
      return { key: k, label: SERVICES[k].label + " · " + n };
    })
  );
  el.innerHTML = groups.map(function (g) {
    return '<button class="chip' + (g.key === filter ? " active" : "") + '" data-f="' + g.key + '">' + esc(g.label) + "</button>";
  }).join("");
  Array.prototype.forEach.call(el.querySelectorAll("[data-f]"), function (b) {
    b.addEventListener("click", function () { filter = b.getAttribute("data-f"); openId = null; render(); });
  });
}

function actionsHtml(id) {
  return '<div class="actions">' +
    '<button class="btn confirm" data-confirm="' + id + '">Подтвердить</button>' +
    '<button class="btn ghost" data-commentbtn="' + id + '">Отклонить с комментарием</button>' +
    '<button class="btn reject" data-reject="' + id + '">Отклонить</button>' +
    "</div>" +
    '<div class="commentbox" id="comment-' + id + '">' +
      '<textarea id="commenttext-' + id + '" placeholder="Комментарий пользователю модели — что не так"></textarea>' +
      '<div class="actions"><button class="btn reject" data-rejectcomment="' + id + '">Отклонить с этим комментарием</button></div>' +
    "</div>";
}

function render() {
  document.getElementById("pendingCount").textContent = ITEMS.length + " ожидает";
  var items = visibleItems();
  var wide = isWide();
  if (wide && openId === null && items.length) openId = items[0].manifestId;

  var list = document.getElementById("list");
  if (!items.length) {
    list.innerHTML = '<div class="empty">Нечего подтверждать</div>';
  } else {
    list.innerHTML = items.map(function (i) {
      var svc = SERVICES[i.service] || { label: i.service, color: "var(--ink-mute)" };
      var open = openId === i.manifestId;
      return (
        '<div class="row' + (open ? " open" : "") + '" data-row="' + i.manifestId + '">' +
          '<div class="row-head">' +
            '<input type="checkbox" data-check="' + i.manifestId + '"' + (checked[i.manifestId] ? " checked" : "") + ' aria-label="Выбрать">' +
            '<div class="row-main" data-open="' + i.manifestId + '">' +
              '<div class="row-meta"><span class="svc-dot" style="background:' + svc.color + '"></span>' + esc(svc.label) + '<span style="margin-left:auto">' + esc(i.accountLabel || "") + "</span></div>" +
              '<div class="row-title">' + esc(i.title) + "</div>" +
              '<div class="row-sum">' + esc(i.summary) + "</div>" +
            "</div>" +
            '<span class="chev" data-open="' + i.manifestId + '">' + (open ? "▲" : "▼") + "</span>" +
          "</div>" +
          (!wide && open ? '<div class="detail-inline"><pre class="detail-body">' + esc(i.preview) + "</pre>" + actionsHtml(i.manifestId) + "</div>" : "") +
        "</div>"
      );
    }).join("");
  }

  var pane = document.getElementById("pane");
  var openItem = items.filter(function (i) { return i.manifestId === openId; })[0];
  if (wide && openItem) {
    var svc2 = SERVICES[openItem.service] || { label: openItem.service, color: "var(--ink-mute)" };
    pane.style.display = "block";
    pane.innerHTML =
      '<div class="row-meta"><span class="svc-dot" style="background:' + svc2.color + '"></span>' + esc(svc2.label) + " · " + esc(openItem.accountLabel || "") + "</div>" +
      '<div class="row-title">' + esc(openItem.title) + "</div>" +
      '<pre class="detail-body">' + esc(openItem.preview) + "</pre>" +
      actionsHtml(openItem.manifestId);
  } else {
    pane.style.display = "none";
    pane.innerHTML = "";
  }

  Array.prototype.forEach.call(document.querySelectorAll("[data-open]"), function (el) {
    el.addEventListener("click", function () {
      var id = el.getAttribute("data-open");
      openId = openId === id && !isWide() ? null : id;
      render();
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-check]"), function (c) {
    c.addEventListener("click", function (e) { e.stopPropagation(); });
    c.addEventListener("change", function () { checked[c.getAttribute("data-check")] = c.checked; renderBulk(); });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-confirm]"), function (b) {
    b.addEventListener("click", function (e) { e.stopPropagation(); decide(b.getAttribute("data-confirm"), "confirm"); });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-reject]"), function (b) {
    b.addEventListener("click", function (e) { e.stopPropagation(); decide(b.getAttribute("data-reject"), "reject"); });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-commentbtn]"), function (b) {
    b.addEventListener("click", function (e) {
      e.stopPropagation();
      var id = b.getAttribute("data-commentbtn");
      var box = document.getElementById("comment-" + id);
      box.style.display = box.style.display === "block" ? "none" : "block";
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-rejectcomment]"), function (b) {
    b.addEventListener("click", function (e) {
      e.stopPropagation();
      var id = b.getAttribute("data-rejectcomment");
      var text = document.getElementById("commenttext-" + id).value;
      decide(id, "reject", text);
    });
  });
}

function decide(id, decision, comment) {
  var item = byId(id);
  if (!item) return;
  api("/consent-hub-api/decide", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ service: item.service, manifestId: id, decision: decision, comment: comment })
  }).then(function (r) {
    if (r.status === 200 && r.json.ok) {
      setStatus((decision === "confirm" ? "Подтверждено: " : "Отклонено: ") + item.title, false);
    } else {
      setStatus("Не получилось (" + (r.json.error || r.status) + ")", true);
    }
    delete checked[id];
    load();
  }).catch(function () { setStatus("Сеть недоступна", true); });
}

function renderBulk() {
  var ids = Object.keys(checked).filter(function (k) { return checked[k]; });
  var bar = document.getElementById("bulkbar");
  bar.style.display = ids.length ? "flex" : "none";
  document.getElementById("bulkcount").textContent = "Выбрано: " + ids.length;
  if (!ids.length) document.getElementById("review").style.display = "none";
}

document.getElementById("bulkbtn").addEventListener("click", function () {
  var ids = Object.keys(checked).filter(function (k) { return checked[k]; });
  var box = document.getElementById("reviewlist");
  box.innerHTML = ids.map(function (id) {
    var i = byId(id);
    return i ? '<div class="review-item"><b>' + esc(i.title) + "</b>" + esc(i.summary) + "</div>" : "";
  }).join("");
  var btn = document.getElementById("confirmall");
  btn.textContent = "Подтверждаю " + ids.length + " действи" + (ids.length === 1 ? "е" : "я");
  document.getElementById("review").style.display = "block";
});

document.getElementById("confirmall").addEventListener("click", function () {
  var ids = Object.keys(checked).filter(function (k) { return checked[k]; });
  document.getElementById("confirmall").disabled = true;
  Promise.all(ids.map(function (id) {
    var item = byId(id);
    if (!item) return Promise.resolve();
    return api("/consent-hub-api/decide", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ service: item.service, manifestId: id, decision: "confirm" })
    });
  })).then(function () {
    checked = {};
    document.getElementById("review").style.display = "none";
    setStatus("Пакет подтверждён (" + ids.length + ")", false);
    load();
  });
});

window.addEventListener("resize", render);
load();
setInterval(load, 15000);
</script>
`;
}
