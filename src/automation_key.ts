/**
 * automation_key.ts — единая генерация временного `automation_key` на всю
 * экосистему MCP-серверов (gmail/calendar/drive/sheets/docs/ticktick).
 *
 * Spec: `docs/TZ_automation_key_hub.md`. Живёт ТОЛЬКО в gmail-mcp: после
 * консолидации ботов (2026-08-10/11) единственный вебхук Telegram
 * зарегистрирован здесь — остальные пять сервисов свой вебхук больше не
 * держат, поэтому весь интерактивный флоу (кнопки, накопление выбора,
 * генерация) обязан жить в этом одном месте. Каждый читающий сервис (в этом
 * ТЗ — только ticktick-mcp) лишь SELECT'ит `tg_automation_windows` и
 * проверяет scope — ничего сюда не пишет и не рисует кнопки.
 *
 * Состояние текущего (незавершённого) выбора НЕ хранится ни в памяти, ни в
 * БД — оно целиком закодировано в `callback_data` кнопок самого сообщения
 * (битовая маска из 6 бит), так что Telegram хранит его между нажатиями
 * бесплатно (ТЗ, раздел "gmail-mcp — интерактивный флоу", п.3).
 */

import { randomBytes, createHash } from "node:crypto";
import { fetch as undiciFetch } from "undici";
import type { TgApprovalConfig, AutomationKeyConfig } from "./config.js";

// Намеренно НЕТ runtime-импорта из `tg_approval.ts`/`consent.ts` (`tgCall`/
// `formatLaTime`), несмотря на то что оба уже существуют там байт-в-байт
// одинаковые: `consent.ts`'s собственный doc-comment объясняет тот же приём
// — эти файлы переносятся/тестируются НАПРЯМУЮ (`node scripts/test-*.mjs`
// импортирует `../src/*.ts` без сборки), а относительный импорт вида
// `./tg_approval.js` не резолвится в `src/tg_approval.ts` при таком запуске
// (только в `dist/` после `tsc`, где оба файла реально скомпилированы рядом
// друг с другом). Крошечное дублирование здесь — цена той же тестируемости,
// не забывчивость.

const TELEGRAM_API = "https://api.telegram.org";

interface TgCallResult {
  ok: boolean;
  result?: unknown;
  description?: string;
}

async function tgCall(cfg: TgApprovalConfig, method: string, body: unknown): Promise<TgCallResult> {
  const res = await undiciFetch(`${TELEGRAM_API}/bot${cfg.botToken}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let json: { ok?: boolean; result?: unknown; description?: string } = {};
  try {
    json = (await res.json()) as typeof json;
  } catch {
    /* non-JSON response — fall through, ok stays false */
  }
  return { ok: !!json.ok && res.ok, result: json.result, description: json.description };
}

const LA_TZ = "America/Los_Angeles";

/** Время в America/Los_Angeles как «5 авг, 07:15» (ТЗ A.4 — всегда LA, не
 * UTC; глобальное правило владельца). Дубликат `consent.ts`'s `formatLaTime`
 * — см. комментарий выше про отсутствие runtime-импортов между этими файлами. */
function formatLaTime(epochMs: number): string {
  return new Intl.DateTimeFormat("ru-RU", {
    timeZone: LA_TZ,
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(epochMs));
}

// ───────────────────────── DI contract (store.ts on the other side) ────────

export interface AutomationWindowRow {
  windowId: string;
  tokenHash: string;
  scope: string;
  label: string | null;
  createdAt: number;
  expiresAt: number;
  revokedAt: number | null;
  createdByChat: string;
}

export interface AutomationWindowStore {
  createWindow(input: {
    windowId: string;
    tokenHash: string;
    scope: string;
    createdAt: number;
    expiresAt: number;
    createdByChat: string;
  }): Promise<void>;
  listActiveWindows(nowMs: number): Promise<AutomationWindowRow[]>;
  getWindow(windowId: string): Promise<AutomationWindowRow | null>;
  /** true = действительно отозвано сейчас; false = не найдено ИЛИ уже было отозвано. */
  revokeWindow(windowId: string, nowMs: number): Promise<boolean>;
}

// ───────────────────────── Каноническая модель сервисов ────────────────────

/** Канонические имена — ровно так, строчными (ТЗ). Порядок фиксирует бит
 * каждого сервиса в маске выбора (индекс = номер бита) и порядок кнопок. */
export const AUTOMATION_SERVICES = ["gmail", "calendar", "drive", "sheets", "docs", "ticktick"] as const;
export type AutomationService = (typeof AUTOMATION_SERVICES)[number];

const ALL_MASK = (1 << AUTOMATION_SERVICES.length) - 1; // 0b111111 = 63

function serviceBit(name: string): number {
  const i = AUTOMATION_SERVICES.indexOf(name as AutomationService);
  return i < 0 ? 0 : 1 << i;
}

/** csv отмеченных сервисов, или буквально "all", если отмечены все 6. */
export function maskToScope(mask: number): string {
  if (mask === ALL_MASK) return "all";
  return AUTOMATION_SERVICES.filter((_, i) => (mask & (1 << i)) !== 0).join(",");
}

/** Человеческий список отмеченных сервисов для текста сообщения с ключом. */
function maskToHumanList(mask: number): string {
  if (mask === ALL_MASK) return "все сервисы";
  return AUTOMATION_SERVICES.filter((_, i) => (mask & (1 << i)) !== 0).join(", ");
}

// ───────────────────────── Клавиатура выбора ────────────────────────────────

interface TgButton {
  text: string;
  callback_data: string;
}

/** 3 ряда по 2 сервиса, затем «Все сразу», затем «Получить ключ». Маска
 * зашита в `callback_data` КАЖДОЙ кнопки — она отражает состояние выбора
 * ДО этого конкретного нажатия (обработчик считает XOR/новую маску сам и
 * перерисовывает клавиатуру заново с этой новой маской в каждой кнопке). */
function buildSelectionKeyboard(mask: number): { inline_keyboard: TgButton[][] } {
  const rows: TgButton[][] = [];
  for (let i = 0; i < AUTOMATION_SERVICES.length; i += 2) {
    const row: TgButton[] = [];
    for (let j = i; j < Math.min(i + 2, AUTOMATION_SERVICES.length); j++) {
      const svc = AUTOMATION_SERVICES[j];
      const checked = (mask & (1 << j)) !== 0;
      row.push({ text: `${checked ? "✓" : "✗"} ${svc}`, callback_data: `ak:toggle:${svc}:${mask}` });
    }
    rows.push(row);
  }
  const allChecked = mask === ALL_MASK;
  rows.push([{ text: `${allChecked ? "✓" : "✗"} Все сразу`, callback_data: `ak:all:${mask}` }]);
  rows.push([{ text: "Получить ключ", callback_data: `ak:gen:${mask}` }]);
  return { inline_keyboard: rows };
}

const SELECTION_PROMPT = "Выбери сервисы, на которые должен действовать automation_key:";

// ───────────────────────── Owner-only guard ─────────────────────────────────

function isOwner(cfg: TgApprovalConfig, chatId: string | number | undefined): boolean {
  const id = String(chatId ?? "");
  return id !== "" && id === cfg.ownerChatId;
}

// ───────────────────────── Генерация ключа + сохранение ────────────────────

function sha256Hex(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

/** `crypto.randomBytes(32).toString('base64url')` — сырой токен, НИКОГДА не
 * попадает в БД, только его sha256-хэш (см. createWindow ниже). */
function generateRawToken(): string {
  return randomBytes(32).toString("base64url");
}

function generateWindowId(): string {
  return randomBytes(6).toString("hex");
}

/** Отправляет токен ОТДЕЛЬНЫМ сообщением и планирует его самоудаление через
 * `delayMs` (по умолчанию 10с — ТЗ п.6). Порт идеи из ticktick-mcp
 * (`schedule_message_delete`/`sweep_scheduled_deletes` в `tg_approval.py`),
 * НЕ копия кода 1:1 — там периодический sweep по БД (Python-процесс),
 * здесь — просто `setTimeout` в живом Node-процессе: этот сервер уже держит
 * долгоживущий HTTP-процесс (в отличие от возможного serverless-деплоя
 * ticktick-mcp), так что отдельная таблица расписания удалений не нужна —
 * `.unref()` не держит процесс живым ради одного таймера, но пока процесс
 * жив (обычный случай), сообщение удалится вовремя.
 */
function scheduleMessageDelete(cfg: TgApprovalConfig, chatId: string, messageId: number, delayMs = 10_000): void {
  setTimeout(() => {
    tgCall(cfg, "deleteMessage", { chat_id: chatId, message_id: messageId }).catch((err) =>
      console.error(`automation_key: не удалось удалить сообщение с ключом (chat=${chatId}, msg=${messageId}):`, err),
    );
  }, delayMs).unref();
}

// ───────────────────────── Список / текст ───────────────────────────────────

function formatWindowLine(w: AutomationWindowRow, index: number): string {
  return `${index + 1}. #${w.windowId} · ${w.scope} · до ${formatLaTime(w.expiresAt)}`;
}

async function renderActiveList(
  store: AutomationWindowStore,
  now: number,
): Promise<{ text: string; keyboard: { inline_keyboard: TgButton[][] } }> {
  const windows = await store.listActiveWindows(now);
  if (!windows.length) {
    return { text: "Нет активных окон automation_key.", keyboard: { inline_keyboard: [] } };
  }
  const text = "Активные окна automation_key:\n\n" + windows.map(formatWindowLine).join("\n");
  const keyboard = {
    inline_keyboard: windows.map((w) => [{ text: `Отозвать #${w.windowId}`, callback_data: `ak:revoke:${w.windowId}` }]),
  };
  return { text, keyboard };
}

// ───────────────────────── Text-command entry point ────────────────────────

export interface AutomationKeyMessage {
  chatId: string | number | undefined;
  fromId: string | number | undefined;
  text: string;
}

/**
 * Обрабатывает ОДНО текстовое сообщение, уже прошедшее секрет вебхука
 * (http.ts). Возвращает `true`, если сообщение относилось к `/automation_key`
 * (обработано или молча отклонено как не-владелец) — `false`, если это вообще
 * не команда `/automation_key*` и вызывающий должен идти дальше своим путём.
 */
export async function handleAutomationKeyMessage(
  cfg: TgApprovalConfig,
  store: AutomationWindowStore,
  msg: AutomationKeyMessage,
  now: () => number = Date.now,
): Promise<boolean> {
  const text = (msg.text ?? "").trim();
  if (!/^\/automation_key\b/.test(text)) return false;

  // Owner-only — тот же chat_id-чек, что и у callback_query (handleWebhook).
  if (!isOwner(cfg, msg.fromId)) return true; // молча игнорируется, как и в handleWebhook

  const chatId = String(msg.chatId ?? cfg.ownerChatId);
  const rest = text.slice("/automation_key".length).trim();

  if (rest === "" ) {
    await tgCall(cfg, "sendMessage", {
      chat_id: chatId,
      text: SELECTION_PROMPT,
      reply_markup: buildSelectionKeyboard(0),
    });
    return true;
  }

  if (rest === "list") {
    const { text: listText, keyboard } = await renderActiveList(store, now());
    await tgCall(cfg, "sendMessage", { chat_id: chatId, text: listText, reply_markup: keyboard });
    return true;
  }

  const revokeMatch = /^revoke\s+(\S+)$/.exec(rest);
  if (revokeMatch) {
    const windowId = revokeMatch[1];
    const ok = await store.revokeWindow(windowId, now());
    await tgCall(cfg, "sendMessage", {
      chat_id: chatId,
      text: ok ? `Окно #${windowId} отозвано.` : `Окно #${windowId} не найдено или уже отозвано.`,
    });
    return true;
  }

  await tgCall(cfg, "sendMessage", {
    chat_id: chatId,
    text: "Не понял команду. Доступно: /automation_key, /automation_key list, /automation_key revoke <id>.",
  });
  return true;
}

// ───────────────────────── Callback (button) entry point ───────────────────

export interface AutomationKeyCallback {
  id: string;
  fromId: string | number | undefined;
  data: string;
  chatId: string | number | undefined;
  messageId: number | undefined;
}

/**
 * Обрабатывает ОДНО нажатие кнопки с `callback_data`, начинающимся на `ak:`
 * (toggle/all/gen/revoke). Возвращает `true`, если данные принадлежали этому
 * модулю (обработаны или молча отклонены как не-владелец/не наш формат) —
 * `false`, если `data` не начинается на `ak:` и вызывающий должен передать
 * update дальше (обычному гейту подтверждения в `handleWebhook`).
 */
export async function handleAutomationKeyCallback(
  cfg: TgApprovalConfig,
  akCfg: AutomationKeyConfig,
  store: AutomationWindowStore,
  cq: AutomationKeyCallback,
  now: () => number = Date.now,
): Promise<boolean> {
  if (!cq.data.startsWith("ak:")) return false;

  if (!isOwner(cfg, cq.fromId)) {
    // Молча гасим спиннер у не-владельца, ничего не делаем — как handleWebhook.
    await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id }).catch(() => {});
    return true;
  }

  const chatId = String(cq.chatId ?? cfg.ownerChatId);
  const parts = cq.data.split(":");

  // ak:toggle:<service>:<mask>
  if (parts[0] === "ak" && parts[1] === "toggle") {
    const service = parts[2] ?? "";
    const mask = Number(parts[3] ?? "0") | 0;
    const newMask = mask ^ serviceBit(service);
    if (cq.messageId != null) {
      await tgCall(cfg, "editMessageReplyMarkup", {
        chat_id: chatId,
        message_id: cq.messageId,
        reply_markup: buildSelectionKeyboard(newMask),
      }).catch(() => {});
    }
    await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id }).catch(() => {});
    return true;
  }

  // ak:all:<mask> — тоггл "все 6" целиком.
  if (parts[0] === "ak" && parts[1] === "all") {
    const mask = Number(parts[2] ?? "0") | 0;
    const newMask = mask === ALL_MASK ? 0 : ALL_MASK;
    if (cq.messageId != null) {
      await tgCall(cfg, "editMessageReplyMarkup", {
        chat_id: chatId,
        message_id: cq.messageId,
        reply_markup: buildSelectionKeyboard(newMask),
      }).catch(() => {});
    }
    await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id }).catch(() => {});
    return true;
  }

  // ak:gen:<mask> — сгенерировать ключ по текущему выбору.
  if (parts[0] === "ak" && parts[1] === "gen") {
    const mask = Number(parts[2] ?? "0") | 0;
    if (mask === 0) {
      await tgCall(cfg, "answerCallbackQuery", {
        callback_query_id: cq.id,
        text: "Сначала отметь хотя бы один сервис.",
        show_alert: true,
      }).catch(() => {});
      return true; // ничего не создано в БД (ТЗ п.5 / п.8 тестового плана)
    }

    const scope = maskToScope(mask);
    const rawToken = generateRawToken();
    const windowId = generateWindowId();
    const nowMs = now();
    await store.createWindow({
      windowId,
      tokenHash: sha256Hex(rawToken),
      scope,
      createdAt: nowMs,
      expiresAt: nowMs + akCfg.ttlMs,
      createdByChat: chatId,
    });

    if (cq.messageId != null) {
      await tgCall(cfg, "editMessageReplyMarkup", {
        chat_id: chatId,
        message_id: cq.messageId,
        reply_markup: { inline_keyboard: [] },
      }).catch(() => {});
    }
    await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id, text: "Ключ сгенерирован" }).catch(() => {});

    const sent = await tgCall(cfg, "sendMessage", {
      chat_id: chatId,
      text:
        `🔑 ${rawToken}\n\n` +
        `Действует на: ${maskToHumanList(mask)}\n` +
        `До: ${formatLaTime(nowMs + akCfg.ttlMs)}\n\n` +
        `Сообщение самоудалится через 10 секунд.`,
    });
    const sentMessageId = (sent.result as { message_id?: number } | undefined)?.message_id;
    if (sent.ok && sentMessageId != null) {
      scheduleMessageDelete(cfg, chatId, sentMessageId);
    }
    return true;
  }

  // ak:revoke:<windowId> — кнопка «Отозвать» в списке.
  if (parts[0] === "ak" && parts[1] === "revoke") {
    const windowId = parts.slice(2).join(":"); // window_id — hex, но на всякий случай не режем по ':'
    const ok = await store.revokeWindow(windowId, now());
    await tgCall(cfg, "answerCallbackQuery", {
      callback_query_id: cq.id,
      text: ok ? "Отозвано" : "Уже отозвано или не найдено",
    }).catch(() => {});
    const { text: listText, keyboard } = await renderActiveList(store, now());
    if (cq.messageId != null) {
      await tgCall(cfg, "editMessageText", {
        chat_id: chatId,
        message_id: cq.messageId,
        text: listText,
        reply_markup: keyboard,
      }).catch(() => {});
    }
    return true;
  }

  // Незнакомый ak:* формат — гасим спиннер и молча выходим.
  await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id }).catch(() => {});
  return true;
}
