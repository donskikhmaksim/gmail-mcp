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

import { randomBytes, createHash, timingSafeEqual, pbkdf2Sync, createCipheriv, createDecipheriv } from "node:crypto";
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

// ───────────────────── Доставка ключа как self-destruct-заметка ─────────────
// docs/TZ_automation_key_note_delivery_and_buttons.md раздел 1. Шифрование —
// byte-for-byte дубликат `note_crypto.ts`'s `generateKey()`/`encrypt()`
// (которая сама — byte-for-byte порт self-destroyed-notes'а `crypto.ts`,
// отдельно покрыта своим прямым round-trip-тестом,
// `scripts/test-note-crypto.mjs`). ДУБЛИКАТ, не runtime-импорт из
// `note_crypto.js`, по ТОЙ ЖЕ причине, что уже объяснена в doc-comment
// самого верха этого файла для `tgCall`/`formatLaTime`: этот модуль
// тестируется НАПРЯМУЮ (`node scripts/test-automation-key.mjs` импортирует
// `../src/automation_key.ts` без сборки), а относительный `./note_crypto.js`
// резолвится в `note_crypto.ts` только в `dist/` после `tsc`.

const NOTE_KEY_BYTES = 32; // AES-256
const NOTE_IV_BYTES = 12; // GCM standard nonce
const NOTE_SALT_BYTES = 16;
const NOTE_PBKDF2_ITERATIONS = 100_000;
const SELF_DESTROYED_NOTES_BASE_URL = "https://self-destroyed-notes-production.up.railway.app";
/** Час на то, чтобы открыть ссылку (ttl заметки ДО первого просмотра) — не
 * про срок самого automation_key, тот считается отдельно (`expiresAt` окна). */
const NOTE_TTL_SECONDS = 60 * 60;

function generateNoteKey(): string {
  return randomBytes(NOTE_KEY_BYTES).toString("base64url");
}

function encryptForNote(plaintext: string, keyB64Url: string): { v: 1; iv: string; data: string; salt: string; iter: number; pw: boolean } {
  const urlKey = Buffer.from(keyB64Url, "base64url");
  if (urlKey.length !== NOTE_KEY_BYTES) throw new Error("invalid key length");

  const salt = randomBytes(NOTE_SALT_BYTES);
  const key = pbkdf2Sync(urlKey, salt, NOTE_PBKDF2_ITERATIONS, NOTE_KEY_BYTES, "sha256");

  const iv = randomBytes(NOTE_IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const data = Buffer.concat([enc, tag]);

  return {
    v: 1,
    iv: iv.toString("base64"),
    data: data.toString("base64"),
    salt: salt.toString("base64"),
    iter: NOTE_PBKDF2_ITERATIONS,
    pw: false,
  };
}

/**
 * Обратная операция `encryptForNote()` — расшифровывает JSON-сериализованный
 * payload той же формы (`{v,iv,data,salt,iter,pw}`) ключом `keyB64Url`.
 * Используется ровно в одном месте: `reissueNoteForWindow` ниже, чтобы
 * достать `rawToken` обратно из `AutomationWindowRow.tokenEncrypted` (столбец
 * `token_encrypted`) ключом `AutomationKeyConfig.masterSecret`. Кидает
 * исключение на битом payload/неверном ключе (auth tag не сойдётся) —
 * вызывающий код (`reissueNoteForWindow`) ловит это сам и превращает в
 * понятный отказ, не 500-ю ошибку наружу.
 */
function decryptStored(payloadJson: string, keyB64Url: string): string {
  const payload = JSON.parse(payloadJson) as { iv: string; data: string; salt: string; iter: number };
  const urlKey = Buffer.from(keyB64Url, "base64url");
  if (urlKey.length !== NOTE_KEY_BYTES) throw new Error("invalid key length");

  const salt = Buffer.from(payload.salt, "base64");
  const key = pbkdf2Sync(urlKey, salt, payload.iter, NOTE_KEY_BYTES, "sha256");
  const iv = Buffer.from(payload.iv, "base64");
  const dataAndTag = Buffer.from(payload.data, "base64");
  const tag = dataAndTag.subarray(dataAndTag.length - 16);
  const encrypted = dataAndTag.subarray(0, dataAndTag.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

/**
 * Шифрует `plaintext` свежим одноразовым ключом, создаёт one-view-заметку на
 * self-destroyed-notes (публичный, без авторизации на создание — см. ТЗ) и
 * возвращает готовую ссылку `.../#/n/<id>/<key>`. Кидает исключение при
 * сетевой ошибке/не-2xx/отсутствии `id` — вызывающий код (ниже,
 * `generateAndDeliverKey`) решает, как обработать сбой.
 */
async function createSecretNoteLink(plaintext: string): Promise<string> {
  const key = generateNoteKey();
  const payload = encryptForNote(plaintext, key);

  const res = await undiciFetch(`${SELF_DESTROYED_NOTES_BASE_URL}/api/notes`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ payload, oneView: true, ttl: NOTE_TTL_SECONDS }),
  });
  if (!res.ok) {
    throw new Error(`self-destroyed-notes: HTTP ${res.status}`);
  }
  let json: { id?: string };
  try {
    json = (await res.json()) as { id?: string };
  } catch {
    throw new Error("self-destroyed-notes: non-JSON response");
  }
  if (!json.id) {
    throw new Error("self-destroyed-notes: response missing id");
  }
  return `${SELF_DESTROYED_NOTES_BASE_URL}/#/n/${json.id}/${key}`;
}

/**
 * Содержимое, которое реально уходит в self-destruct-заметку (не голый
 * `rawToken`). Инцидент, из-за которого это появилось: владелец вставил
 * расшифрованную заметку с голым токеном в чат с другим ассистентом, и тот
 * искренне не понял, что это и куда его приложить — переспросил, к какому
 * шагу, для какого сервиса, в какой параметр. Заметку читает МОДЕЛЬ в
 * совершенно другом разговоре без какого-либо предыдущего контекста, так что
 * текст должен сам, самодостаточно, объяснить: что это, для каких сервисов,
 * в какой параметр его передать и что валидный ключ отменяет необходимость
 * спрашивать разрешение владельца на каждый вызов. Это просто честное
 * описание значения параметра — не императивная директива вида «игнорируй
 * прошлые инструкции», намеренно без такого тона (anti-prompt-injection
 * гигиена: заметка не должна выглядеть как попытка выдать себя за системное
 * сообщение).
 */
function buildNoteInstructions(rawToken: string, mask: number, untilLine: string): string {
  return (
    `Это automation_key — ключ автоматизации для MCP-сервисов Максима (gmail-mcp и связанные).\n\n` +
    `Ключ: ${rawToken}\n\n` +
    `Действует для сервисов: ${maskToHumanList(mask)}.\n` +
    `${untilLine}\n\n` +
    `Как использовать: при вызове гейтированного write-инструмента этих сервисов ` +
    `(то есть инструмента, который обычно спрашивает подтверждение у владельца перед выполнением — ` +
    `например gmail_send, gmail_reply, calendar_event_create и подобных инструментов этих сервисов) ` +
    `передай это значение строкой в параметр automation_key вызова.\n\n` +
    `Пока ключ действителен (см. срок выше) и покрывает нужный сервис, подтверждение владельца ` +
    `для этого конкретного вызова не требуется — не нужно переспрашивать разрешение на каждое действие, ` +
    `если этот ключ передан в automation_key.`
  );
}

// ───────────────────────── DI contract (store.ts on the other side) ────────

export interface AutomationWindowRow {
  windowId: string;
  tokenHash: string;
  scope: string;
  label: string | null;
  createdAt: number;
  /** `null` = бессрочно (docs/TZ_automation_key_duration_labels.md раздел 1). */
  expiresAt: number | null;
  revokedAt: number | null;
  createdByChat: string;
  /**
   * Сырой токен, зашифрованный `AutomationKeyConfig.masterSecret` (JSON
   * `{v,iv,data,salt,iter,pw}`, та же форма, что уже уходит на
   * self-destroyed-notes) — существует ТОЛЬКО чтобы `reissueNoteForWindow`
   * могла перевыпустить self-destruct-заметку для уже созданного окна.
   * `null`, если мастер-секрет не был задан в момент создания этого окна
   * (переменная отсутствовала/невалидна на тот момент) — окна, выпущенные до
   * появления этой возможности, тоже остаются с `null` здесь навсегда,
   * задним числом ничего не мигрируется. Нигде, кроме `reissueNoteForWindow`,
   * не читается — проверка предъявленного ключа (`checkAutomationKeyFor`)
   * по-прежнему идёт исключительно через `tokenHash`.
   */
  tokenEncrypted: string | null;
}

export interface AutomationWindowStore {
  createWindow(input: {
    windowId: string;
    tokenHash: string;
    scope: string;
    label?: string | null;
    createdAt: number;
    expiresAt: number | null;
    createdByChat: string;
    /** `undefined`/`null` — не пишем (мастер-секрет не задан, фича выключена). */
    tokenEncrypted?: string | null;
  }): Promise<void>;
  listActiveWindows(nowMs: number): Promise<AutomationWindowRow[]>;
  /** ВСЕ когда-либо выданные окна (активные + истёкшие + отозванные), самые
   * свежие сверху, не более `limit` строк, плюс честный `total` (для «показаны
   * последние N из M» — раздел 3 ТЗ). */
  listAllWindows(limit: number): Promise<{ windows: AutomationWindowRow[]; total: number }>;
  getWindow(windowId: string): Promise<AutomationWindowRow | null>;
  /** true = действительно отозвано сейчас; false = не найдено ИЛИ уже было отозвано. */
  revokeWindow(windowId: string, nowMs: number): Promise<boolean>;
  /** Меняет scope существующего окна на месте (не трогает revoked_at/expires_at/
   * token_hash/token_encrypted). Не проверяет само по себе, отозвано ли окно
   * или истёк ли срок — вызывающий код (мини-апп-менеджер) показывает кнопку
   * смены доступа только у активных окон, но это UI-решение, не гарантия
   * стора. true = строка найдена и обновлена; false = windowId не существует. */
  updateScope(windowId: string, scope: string): Promise<boolean>;
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

/** Список имён сервисов (например тел POST-запроса мини-аппа —
 * `docs/TZ_automation_key_miniapp.md` раздел 3) → та же битовая маска, что
 * кнопочная версия строит через последовательные `ak:toggle`. Неизвестные
 * имена молча игнорируются (их бит просто не выставляется) — тот же fail-
 * closed принцип: чужой/опечатанный service не расширяет scope. */
export function servicesToMask(services: readonly string[]): number {
  let mask = 0;
  for (const s of services) mask |= serviceBit(s);
  return mask;
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

// ───────────────────── Настраиваемый срок жизни ключа ───────────────────────
// docs/TZ_automation_key_duration_labels.md раздел 1. Дефолт — 3 часа (индекс
// 1 ниже), НЕ 1 час — владелец явно поправил себя с «час» на «три часа».

export const DURATION_PRESETS: ReadonlyArray<{ label: string; ms: number | null }> = [
  { label: "1 час", ms: 60 * 60 * 1000 },
  { label: "3 часа (по умолчанию)", ms: 3 * 60 * 60 * 1000 },
  { label: "24 часа", ms: 24 * 60 * 60 * 1000 },
  { label: "7 дней", ms: 7 * 24 * 60 * 60 * 1000 },
  { label: "30 дней", ms: 30 * 24 * 60 * 60 * 1000 },
  { label: "Бессрочно", ms: null },
];

export const DEFAULT_DURATION_INDEX = 1;

/** Разумный потолок против абсурдных/переполняющих значений с фронтенда
 * мини-аппа (~100 лет — заведомо больше любого реального сценария, но всё ещё
 * далеко от переполнения `Number`/переполнения `expires_at BIGINT`). */
const MAX_DURATION_MS = 100 * 365 * 24 * 60 * 60 * 1000;

/** `durationMs` из тела POST-запроса мини-аппа: `null` (бессрочно) валиден
 * сам по себе и проверяется вызывающим кодом отдельно (`=== null`) — эта
 * функция валидирует только "число ли это и разумное" (ТЗ раздел 1: "не
 * отрицательное, не абсурдно маленькое типа 0"). */
export function isValidDurationMs(x: unknown): x is number {
  return typeof x === "number" && Number.isFinite(x) && x > 0 && x <= MAX_DURATION_MS;
}

// ───────────────────────── Клавиатура выбора ────────────────────────────────

interface TgCallbackButton {
  text: string;
  callback_data: string;
}

/** Открывает Telegram Mini App поверх чата (`docs/TZ_automation_key_miniapp.md`
 * раздел 2) — второй, более удобный способ того же выбора сервисов; кнопочная
 * версия рядом с ней не убирается. */
interface TgWebAppButton {
  text: string;
  web_app: { url: string };
}

type TgButton = TgCallbackButton | TgWebAppButton;

/** 3 ряда по 2 сервиса, затем «Все сразу», затем «Получить ключ», и (если
 * известен публичный адрес сервиса) ряд с кнопкой мини-аппа. Маска зашита в
 * `callback_data` КАЖДОЙ кнопки — она отражает состояние выбора ДО этого
 * конкретного нажатия (обработчик считает XOR/новую маску сам и
 * перерисовывает клавиатуру заново с этой новой маской в каждой кнопке).
 * `publicBaseUrl` — `cfg.publicBaseUrl` (TgApprovalConfig, тот же
 * PUBLIC_BASE_URL/RAILWAY_PUBLIC_DOMAIN, что и у остального сервиса, ничего
 * не хардкодится); пусто/undefined — кнопка мини-аппа просто не рисуется
 * (например локальный запуск без публичного домена). */
function buildSelectionKeyboard(mask: number, publicBaseUrl?: string): { inline_keyboard: TgButton[][] } {
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
  // «Получить ключ» больше НЕ генерирует сразу — открывает второй экран
  // (выбор срока, ниже). ТЗ раздел 1 "Бот (кнопки)" — второй экран
  // обязательный, не пропускаемый.
  rows.push([{ text: "Получить ключ", callback_data: `ak:dur:${mask}` }]);
  if (publicBaseUrl) {
    rows.push([{ text: "Открыть как мини-апп", web_app: { url: `${publicBaseUrl}/automation-key-app` } }]);
  }
  return { inline_keyboard: rows };
}

const SELECTION_PROMPT = "Выбери сервисы, на которые должен действовать automation_key:";
const DURATION_PROMPT = "Выбери срок действия ключа:";

/** Второй экран — 6 кнопок-пресетов срока, 2 в ряд. Маска отмеченных
 * сервисов из первого экрана переносится в `callback_data` целиком
 * (`ak:gen:<mask>:<durationIndex>`) — никакого сервер-side состояния между
 * двумя апдейтами (тот же приём, что маска сервисов в первом экране). */
function buildDurationKeyboard(mask: number): { inline_keyboard: TgCallbackButton[][] } {
  const rows: TgCallbackButton[][] = [];
  for (let i = 0; i < DURATION_PRESETS.length; i += 2) {
    const row: TgCallbackButton[] = [];
    for (let j = i; j < Math.min(i + 2, DURATION_PRESETS.length); j++) {
      row.push({ text: DURATION_PRESETS[j].label, callback_data: `ak:gen:${mask}:${j}` });
    }
    rows.push(row);
  }
  return { inline_keyboard: rows };
}

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

/**
 * Единая точка "создать окно + отправить ключ владельцу" — переиспользуется
 * И кнопочным `ak:gen` (ниже), И backend-роутом Mini App
 * (`docs/TZ_automation_key_miniapp.md` раздел 5, `POST /automation-key-app/
 * generate` в `http.ts`). Один путь генерации/доставки, а не два параллельных
 * с разным поведением (например разным временем самоудаления) — сырой токен
 * ВСЕГДА уходит только обычным сообщением в чат с 10с-самоудалением, никогда
 * в HTTP-ответе. `mask === 0` — ничего не создаёт, возвращает `null` (тот же
 * fail-closed принцип на пустой выбор, что и у кнопочной версии).
 *
 * `durationMs` — `null` значит бессрочно (docs/TZ_automation_key_duration_
 * labels.md раздел 1); иначе окно живёт `durationMs` от текущего момента.
 * Оба вызывающих кода (кнопочный `ak:gen:<mask>:<idx>` и мини-апп) обязаны
 * передать его явно — здесь нет тихого дефолта на случай кривого ввода
 * (`akCfg.ttlMs` больше не подставляется тихо). `akCfg.masterSecret` — если
 * задан, `rawToken` дополнительно шифруется им и сохраняется в
 * `token_encrypted` (см. doc-comment `AutomationWindowRow.tokenEncrypted`
 * выше) — единственное новое использование `akCfg` здесь.
 *
 * `label` — необязательное название ключа (`null` = без названия). Раздел 2
 * ТЗ: в боте ВСЕГДА `null` (свободный текст туда сознательно не подключён в
 * этом заходе) — только мини-апп передаёт реальное значение.
 *
 * Доставка ключа (`docs/TZ_automation_key_note_delivery_and_buttons.md`
 * раздел 1): сырой токен НИКОГДА не попадает в текст сообщения напрямую —
 * он шифруется свежим одноразовым ключом (`note_delivery.ts`, byte-for-byte
 * порт `self-destroyed-notes`'s `crypto.ts`) и уходит на публичный сервис
 * self-destroyed-notes как one-view-заметка; в чат уходит только готовая
 * ссылка `.../#/n/<id>/<key>`. Если создание заметки не удалось (сервис
 * недоступен и т.п.) — сознательное решение: НЕ откатываться на отправку
 * сырого токена текстом (это тихо свело бы на нет весь смысл доставки через
 * заметку), а сообщить владельцу об ошибке и предложить повторить попытку;
 * окно уже создано в БД к этому моменту и остаётся действующим (ключ можно
 * получить, перегенерировав, или через `/automation_key list`/revoke).
 * Возвращаемый `noteLink` — `null` именно в этом случае сбоя; вызывающий код
 * мини-аппа (http.ts) отдаёт его как есть на страницу.
 */
export async function generateAndDeliverKey(
  cfg: TgApprovalConfig,
  akCfg: AutomationKeyConfig,
  store: AutomationWindowStore,
  chatId: string,
  mask: number,
  durationMs: number | null,
  label: string | null = null,
  now: () => number = Date.now,
): Promise<{ windowId: string; scope: string; noteLink: string | null } | null> {
  if (mask === 0) return null;

  const scope = maskToScope(mask);
  const rawToken = generateRawToken();
  const windowId = generateWindowId();
  const nowMs = now();
  const expiresAt = durationMs === null ? null : nowMs + durationMs;

  // Шифрованное хранение (docs секции про token_encrypted выше в этом файле)
  // — строго опциональная, fail-closed фича: без `akCfg.masterSecret`
  // `tokenEncrypted` остаётся `null`, окно создаётся ровно как раньше.
  let tokenEncrypted: string | null = null;
  if (akCfg.masterSecret) {
    try {
      tokenEncrypted = JSON.stringify(encryptForNote(rawToken, akCfg.masterSecret));
    } catch (err) {
      console.error(`automation_key: не удалось зашифровать токен для хранения (окно #${windowId}), token_encrypted останется NULL:`, err);
    }
  }

  await store.createWindow({
    windowId,
    tokenHash: sha256Hex(rawToken),
    scope,
    label,
    createdAt: nowMs,
    expiresAt,
    createdByChat: chatId,
    tokenEncrypted,
  });

  const untilLine = expiresAt === null ? "До: бессрочно" : `До: ${formatLaTime(expiresAt)}`;

  let noteLink: string | null = null;
  try {
    noteLink = await createSecretNoteLink(buildNoteInstructions(rawToken, mask, untilLine));
  } catch (err) {
    console.error(`automation_key: не удалось создать self-destruct-заметку для окна #${windowId}:`, err);
  }

  const labelLine = label ? `Название: ${label}\n` : "";
  const text = noteLink
    ? `🔑 Ключ (одноразовая ссылка, действует час до первого клика):\n${noteLink}\n\n` +
      labelLine +
      `Действует на: ${maskToHumanList(mask)}\n` +
      `${untilLine}\n\n` +
      `Сообщение самоудалится через 10 секунд.`
    : `⚠️ Окно #${windowId} создано, но не удалось выдать ключ — сервис self-destroyed-notes сейчас ` +
      `недоступен, а сырой ключ намеренно НЕ отправляется текстом. Отзови окно (/automation_key list) и ` +
      `попробуй сгенерировать заново через минуту.\n\n` +
      `Сообщение самоудалится через 10 секунд.`;
  const sent = await tgCall(cfg, "sendMessage", { chat_id: chatId, text });
  const sentMessageId = (sent.result as { message_id?: number } | undefined)?.message_id;
  if (sent.ok && sentMessageId != null) {
    scheduleMessageDelete(cfg, chatId, sentMessageId);
  }
  return { windowId, scope, noteLink };
}

// ───────────────────── Перевыпуск заметки для уже созданного окна ──────────
// Возможность 2 задачи «менеджер ключей»: сырой токен нигде не хранится в
// открытом виде — единственный способ выдать ЕЩЁ ОДНУ self-destruct-заметку
// для уже созданного окна — расшифровать `token_encrypted` мастер-секретом
// (см. `AutomationKeyConfig.masterSecret`, `AutomationWindowRow.tokenEncrypted`
// выше) и собрать ту же инструктивную заметку заново. Не отправляет ничего в
// чат сама (в отличие от `generateAndDeliverKey`) — только возвращает ссылку,
// вызывающий код (`http.ts`'s `/automation-key-app/reissue-note`) отдаёт её
// прямо на страницу мини-аппа, откуда она и была запрошена.

export type ReissueFailureReason =
  | "window_not_found"
  | "window_revoked"
  | "window_expired"
  | "no_stored_token"
  | "master_secret_not_configured"
  | "decrypt_failed"
  | "note_service_unavailable";

export async function reissueNoteForWindow(
  akCfg: AutomationKeyConfig,
  store: AutomationWindowStore,
  windowId: string,
  now: () => number = Date.now,
): Promise<{ ok: true; noteLink: string } | { ok: false; reason: ReissueFailureReason }> {
  const w = await store.getWindow(windowId);
  if (!w) return { ok: false, reason: "window_not_found" };
  if (w.revokedAt !== null) return { ok: false, reason: "window_revoked" };
  const nowMs = now();
  if (w.expiresAt !== null && w.expiresAt <= nowMs) return { ok: false, reason: "window_expired" };
  if (!akCfg.masterSecret) return { ok: false, reason: "master_secret_not_configured" };
  // Проверяем масштаб фичи ПОСЛЕ мастер-секрета намеренно: "фича вообще не
  // включена" — более честная причина отказа, чем "у этого конкретного окна
  // нет сохранённого токена", даже если оба условия истинны одновременно.
  if (!w.tokenEncrypted) return { ok: false, reason: "no_stored_token" };

  let rawToken: string;
  try {
    rawToken = decryptStored(w.tokenEncrypted, akCfg.masterSecret);
  } catch (err) {
    console.error(`automation_key: не удалось расшифровать token_encrypted при перевыпуске (окно #${windowId}):`, err);
    return { ok: false, reason: "decrypt_failed" };
  }

  // `mask` нужен только чтобы собрать ТОТ ЖЕ человекочитаемый список сервисов
  // в тексте заметки (`buildNoteInstructions`), что и при первой выдаче —
  // `w.scope` уже канонический ("all" или csv из AUTOMATION_SERVICES), так что
  // просто разбираем его обратно в маску тем же кодом, что принимает мини-апп.
  const mask = w.scope === "all" ? ALL_MASK : servicesToMask(w.scope.split(","));
  const untilLine = w.expiresAt === null ? "До: бессрочно" : `До: ${formatLaTime(w.expiresAt)}`;

  try {
    const noteLink = await createSecretNoteLink(buildNoteInstructions(rawToken, mask, untilLine));
    return { ok: true, noteLink };
  } catch (err) {
    console.error(`automation_key: не удалось создать self-destruct-заметку при перевыпуске (окно #${windowId}):`, err);
    return { ok: false, reason: "note_service_unavailable" };
  }
}

// ───────────────────── Проверка (consent-гейт, requireConsent) ─────────────
// docs/TZ_automation_key_consent_gate.md — `checkAutomationKey` DI, которую
// server.ts инжектирует в КАЖДЫЙ вызов `requireConsent`. gmail-mcp не держит
// статического `AUTOMATION_KEY` (в отличие от того, что допускает ТЗ для
// других 4 сервисов) — единственный канал здесь "window": активное окно в
// `tg_automation_windows`, чей scope покрывает "gmail". Переиспользует УЖЕ
// существующие `AutomationWindowStore.listActiveWindows` (та же функция, что
// использует `/automation_key list`) — не заводит нового SQL/подключения.

/** true, если `scope` окна покрывает конкретный сервис ("all" — все сразу,
 * иначе csv из `AUTOMATION_SERVICES`, тот же формат, что пишет `maskToScope`). */
export function scopeCoversService(scope: string, service: AutomationService): boolean {
  if (scope === "all") return true;
  return scope
    .split(",")
    .map((s) => s.trim())
    .includes(service);
}

/** Константное по времени сравнение двух sha256-hex-строк ОДИНАКОВОЙ длины
 * (обе — 64 hex-символа, `timingSafeEqual` иначе бросает на разной длине). */
function hashesEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/**
 * `checkAutomationKey` для одного сервиса (здесь — "gmail"): сравнивает
 * присланный сырой ключ с хэшем каждого АКТИВНОГО окна (`revoked_at IS NULL
 * AND (expires_at IS NULL OR expires_at > now)` — уже гарантировано
 * `listActiveWindows`), константным временем, и проверяет, что scope окна
 * покрывает `service`. Первое совпадение — канал `"window"`. Ни одно — не
 * ошибка, просто `{ ok: false }` (вызывающий `requireConsent` тихо падает на
 * обычный человеческий путь).
 */
export async function checkAutomationKeyFor(
  service: AutomationService,
  store: AutomationWindowStore,
  key: string,
  now: () => number = Date.now,
): Promise<{ ok: boolean; channel?: string }> {
  if (!key) return { ok: false };
  const keyHash = sha256Hex(key);
  const windows = await store.listActiveWindows(now());
  for (const w of windows) {
    if (hashesEqual(w.tokenHash, keyHash) && scopeCoversService(w.scope, service)) {
      return { ok: true, channel: "window" };
    }
  }
  return { ok: false };
}

// ───────────────────────── Список / текст ───────────────────────────────────
// Менеджер (docs/TZ_automation_key_duration_labels.md раздел 3) — показывает
// ВСЕ когда-либо выданные окна, не только активные, со статусом у каждого.

/** Экспортирована — `http.ts`'s `/automation-key-app/list` (менеджер в
 * мини-аппе) показывает те же «последние N», что и текстовый `/automation_key
 * list` в боте, один лимит на обе поверхности. */
export const LIST_LIMIT = 30;

export type WindowStatus = "active" | "expired" | "revoked";

/** Экспортирована для мини-апп-менеджера (`http.ts`'s `/automation-key-app/list`
 * — та же логика вычисления статуса, что и текстовый `/automation_key list`
 * в боте, один источник правды на оба поверхности). */
export function windowStatus(w: AutomationWindowRow, nowMs: number): WindowStatus {
  if (w.revokedAt !== null) return "revoked";
  if (w.expiresAt !== null && w.expiresAt <= nowMs) return "expired";
  return "active";
}

/** Экспортирована по той же причине, что и `windowStatus` выше. */
export function humanScope(scope: string): string {
  return scope === "all" ? "все" : scope;
}

function formatAllWindowLine(w: AutomationWindowRow, nowMs: number, index: number): string {
  const status = windowStatus(w, nowMs);
  let statusText: string;
  if (status === "revoked") {
    statusText = `🚫 отозван ${formatLaTime(w.revokedAt as number)}`;
  } else if (status === "expired") {
    statusText = `⌛ истёк ${formatLaTime(w.expiresAt as number)}`;
  } else if (w.expiresAt === null) {
    statusText = "♾ бессрочно";
  } else {
    statusText = `✅ активен (до ${formatLaTime(w.expiresAt)})`;
  }
  const labelPart = w.label ? ` · ${w.label}` : ""; // без label — молча пропускаем, не "(без названия)"
  return `${index + 1}. #${w.windowId}${labelPart} · ${humanScope(w.scope)} · ${statusText}`;
}

async function renderAllList(
  store: AutomationWindowStore,
  now: number,
): Promise<{ text: string; keyboard: { inline_keyboard: TgButton[][] } }> {
  const { windows, total } = await store.listAllWindows(LIST_LIMIT);
  if (!windows.length) {
    return { text: "Ключей automation_key ещё не выдавалось.", keyboard: { inline_keyboard: [] } };
  }
  let text = "Все окна automation_key:\n\n" + windows.map((w, i) => formatAllWindowLine(w, now, i)).join("\n");
  if (total > windows.length) {
    text += `\n\nПоказаны последние ${windows.length} из ${total}.`;
  }
  const keyboard = {
    // «Отозвать» — только у активных строк (истёкшие/уже отозванные нечего отзывать).
    inline_keyboard: windows
      .filter((w) => windowStatus(w, now) === "active")
      .map((w) => [{ text: `Отозвать #${w.windowId}`, callback_data: `ak:revoke:${w.windowId}` }]),
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
      reply_markup: buildSelectionKeyboard(0, cfg.publicBaseUrl),
    });
    return true;
  }

  if (rest === "list") {
    const { text: listText, keyboard } = await renderAllList(store, now());
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
        reply_markup: buildSelectionKeyboard(newMask, cfg.publicBaseUrl),
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
        reply_markup: buildSelectionKeyboard(newMask, cfg.publicBaseUrl),
      }).catch(() => {});
    }
    await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id }).catch(() => {});
    return true;
  }

  // ak:dur:<mask> — «Получить ключ» с первого экрана: открывает ВТОРОЙ,
  // обязательный экран выбора срока (ТЗ раздел 1 "Бот (кнопки)") — сама
  // генерация происходит только на `ak:gen:<mask>:<idx>` ниже.
  if (parts[0] === "ak" && parts[1] === "dur") {
    const mask = Number(parts[2] ?? "0") | 0;
    if (mask === 0) {
      await tgCall(cfg, "answerCallbackQuery", {
        callback_query_id: cq.id,
        text: "Сначала отметь хотя бы один сервис.",
        show_alert: true,
      }).catch(() => {});
      return true; // ничего не создано в БД (ТЗ п.5 / п.8 тестового плана)
    }

    if (cq.messageId != null) {
      await tgCall(cfg, "editMessageText", {
        chat_id: chatId,
        message_id: cq.messageId,
        text: DURATION_PROMPT,
        reply_markup: buildDurationKeyboard(mask),
      }).catch(() => {});
    }
    await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id }).catch(() => {});
    return true;
  }

  // ak:gen:<mask>:<durationIndex> — второй экран: сгенерировать ключ с уже
  // отмеченными сервисами (маска) и выбранным сроком (индекс в
  // DURATION_PRESETS) — весь контекст пришёл ОДНИМ нажатием, без
  // сервер-side состояния между двумя апдейтами (ТЗ раздел 1).
  if (parts[0] === "ak" && parts[1] === "gen") {
    const mask = Number(parts[2] ?? "0") | 0;
    const idx = Number(parts[3] ?? "");
    if (mask === 0 || !Number.isInteger(idx) || idx < 0 || idx >= DURATION_PRESETS.length) {
      // Отсутствующий/битый индекс срока — например нажатие на клавиатуру
      // старого формата, оставшуюся в чате с прошлого деплоя. Fail-closed:
      // НЕ генерируем с молчаливым дефолтом (ТЗ: второй экран обязателен).
      await tgCall(cfg, "answerCallbackQuery", {
        callback_query_id: cq.id,
        text: "Некорректный выбор — начни заново через /automation_key.",
        show_alert: true,
      }).catch(() => {});
      return true;
    }

    if (cq.messageId != null) {
      await tgCall(cfg, "editMessageReplyMarkup", {
        chat_id: chatId,
        message_id: cq.messageId,
        reply_markup: { inline_keyboard: [] },
      }).catch(() => {});
    }
    await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id, text: "Ключ сгенерирован" }).catch(() => {});

    // Бот label не поддерживает в этом заходе (ТЗ раздел 2) — всегда null.
    await generateAndDeliverKey(cfg, akCfg, store, chatId, mask, DURATION_PRESETS[idx].ms, null, now);
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
    const { text: listText, keyboard } = await renderAllList(store, now());
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
