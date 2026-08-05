/**
 * consent.ts — единая точка согласия (consent-гейт) plan → execute.
 *
 * Нормативная спецификация: `mcp-development-standard/references/gate.md` §3.
 * ТЗ: раздел A (`TZ-google-mcp-consent-gate.md`).
 *
 * Это GENERIC-модуль. Он НЕ импортирует ни store, ни config сервера напрямую —
 * `store`, `cfg` и per-tool колбэки (`plan`, `rehash`) приходят параметрами
 * (dependency injection). Благодаря этому файл переносится ПОБАЙТОВО на 4 других
 * репо (sheets/calendar/docs/drive-mcp) — различаются только константа `server`
 * в cfg и per-tool билдеры превью/хеша, которые живут вне этого файла.
 *
 * Через `requireConsent(...)` обязаны проходить ВСЕ write-инструменты сервера
 * (gate.md §3.1: «инструмент, который мутирует, минуя require_consent, — дефект
 * уровня блокер»).
 *
 * ЧЕСТНЫЙ ОСТАТОЧНЫЙ ПРЕДЕЛ (ТЗ A.6 / gate.md §3.4 — НЕ притворяемся, что закрыт):
 * сервер физически НЕ может доказать, что `user_reply` не сочинён самой моделью.
 * Всё, что сервер вернул в тексте, модель уже знает; протокол MCP не даёт серверу
 * сигнала «пришёл новый ход пользователя». Поэтому гейт здесь ПОВЕДЕНЧЕСКИЙ, а не
 * криптографический: он превращает тихое само-подтверждение в ЯВНУЮ ЛОЖЬ, которая
 * остаётся в аудит-логе. Для неадверсариальной модели это работает как гейт, но
 * это компромисс. Целевая миграция: как только claude.ai получит form-mode
 * elicitation — брать подтверждение оттуда вместо `user_reply`, без смены сигнатур.
 *
 * automation_key-ветка (легальный обход для headless-автоматов) СОЗНАТЕЛЬНО не
 * реализована в этой версии: пре-чек потребителей не нашёл автоматов, зовущих
 * инструменты отправки напрямую (YAGNI). Единственный вход доверия — `user_reply`.
 */

import { createHash, randomUUID } from "node:crypto";

// ───────────────────────── Типы контракта ──────────────────────────────────

/** Строка манифеста, как её хранит и отдаёт store. Времена — epoch-миллисекунды. */
export interface ConsentManifestRow {
  id: string;
  server: string;
  tool: string;
  accountLabel: string;
  /** Весь батч целиком — источник истины для исполнения (НЕ аргументы вызова). */
  payload: unknown;
  objectHash: string;
  status: "AWAITING_CONSENT" | "DONE" | "INVALIDATED";
  createdAt: number;
  expiresAt: number;
  consumedAt?: number | null;
  userReply?: string | null;
}

/** Запись аудита. Двухфазная: создаётся на решении гейта, дополняется исходом. */
export interface ConsentAuditEntry {
  id: string;
  ts: number;
  server: string;
  tool: string;
  accountLabel: string;
  manifestId?: string | null;
  objectHash?: string | null;
  /** `user_reply` ДОСЛОВНО, как прислала модель (без пересказа). */
  userReply: string;
  /** Результат каждой из проверок раздела 3.3. */
  checks: Record<string, string>;
  outcome: "confirmed" | "refused" | "invalidated";
  refusalReason?: string | null;
  /** "human" всегда в этой версии; "automation:<имя>" — будущая ветка. */
  actor: string;
}

/**
 * Интерфейс хранилища, который ОЖИДАЕТ этот модуль. Реализуется пакетом A1
 * (`src/store.ts`) поверх Postgres. Все запросы обязаны фильтровать по
 * `server` (общая таблица на 5 серверов — колонка `server`).
 *
 * A1 обязан реализовать РОВНО эти 6 функций под эти сигнатуры:
 */
export interface ConsentStore {
  /** Вставляет новый манифест в состоянии AWAITING_CONSENT. */
  createManifest(input: {
    id: string;
    server: string;
    tool: string;
    accountLabel: string;
    payload: unknown;
    objectHash: string;
    createdAt: number;
    expiresAt: number;
  }): Promise<void>;

  /** Читает манифест по id в рамках своего server; null если нет. */
  getManifest(id: string, server: string): Promise<ConsentManifestRow | null>;

  /**
   * АТОМАРНЫЙ one-shot. Помечает DONE + consumed_at + user_reply ТОЛЬКО если
   * строка ещё AWAITING_CONSENT и не истекла по TTL. Возвращает обновлённую
   * строку при успехе, иначе null (уже исполнен / истёк / инвалидирован / нет).
   * Гонка «двойной execute» закрывается структурно здесь, а не проверкой в JS.
   * Эталон реализации — `consumeCode` в store.ts (UPDATE … WHERE … RETURNING).
   */
  consumeManifest(
    id: string,
    server: string,
    userReply: string,
  ): Promise<ConsentManifestRow | null>;

  /** Помечает манифест INVALIDATED (явное отрицание пользователя). */
  invalidateManifest(
    id: string,
    server: string,
    userReply: string,
  ): Promise<void>;

  /** Append-only: пишет фазу согласия/отказа. */
  appendConsentAudit(entry: ConsentAuditEntry): Promise<void>;

  /**
   * Дополняет ранее записанную аудит-строку исходом мутации и post-verify.
   * Зовётся ИНСТРУМЕНТОМ (пакет A3) ПОСЛЕ мутации, не этим модулем — объявлен
   * здесь только чтобы зафиксировать контракт для A1.
   *
   * `preSnapshot` добавлен пакетом A3 (identity-postverify.md §5.2): снимок
   * исходящего объекта (account/to/cc/bcc/subject/начало тела — БЕЗ полного
   * тела) ДО необратимой мутации. Это не gmail-специфика — то же самое
   * потребуется T2 на остальных 4 серверах, поэтому поле в общем контракте,
   * а не только в store.ts.
   */
  updateConsentAuditOutcome(
    auditId: string,
    outcome: {
      outcome?: "confirmed" | "failed";
      postVerify?: string | null;
      error?: string | null;
      preSnapshot?: unknown;
    },
  ): Promise<void>;
}

/**
 * Опциональный внеполосный (out-of-band) фактор поверх `user_reply` — нажатие
 * кнопки в Telegram (gate.md §3.4: «модель может сфабриковать `user_reply` —
 * это не закрыто»; кнопка модели недоступна). DI, тем же приёмом, что и
 * `ConsentStore` выше: этот модуль НЕ импортирует `tg_approval.ts` — конкретную
 * реализацию инжектирует server.ts, типизируя её `: TgApprovalGate` там (как
 * `consentStoreAdapter`), чтобы дрейф сигнатур падал на СБОРКЕ, а не в проде.
 * Поэтому `consent.ts` остаётся переносимым ПОБАЙТОВО на другие 4 сервера
 * независимо от того, подключён там Telegram или нет.
 *
 * Инвариант совместимости: `tg` не передан (undefined) → ни одна из веток
 * ниже не выполняется, поведение гейта побайтово как до этой правки.
 */
export interface TgApprovalGate {
  /** true, если ДЛЯ ЭТОГО инструмента нужен внеполосный ТГ-фактор
   * (TG_APPROVAL_ENABLED и (TG_APPROVAL_TOOLS пусто ИЛИ содержит tool)). */
  enabledFor(tool: string): boolean;
  /**
   * Отправляет превью плана в Telegram с кнопками [✅ Подтвердить][🛑 Отклонить].
   * Зовётся ТОЛЬКО когда `enabledFor(tool)` истинно, сразу после
   * `createManifest`. Провал — FAIL-CLOSED (это расширение честного правила
   * gate.md §4 на этот слой): вызывающий код обязан НЕ оставлять манифест
   * живым, если это вернуло `{ ok: false }`.
   */
  notifyPlan(
    manifestId: string,
    previewBody: string,
    /** `expiresAt` — CONSENT-манифеста (не самого ТГ-запроса): реализация
     * обязана взять его как ВЕРХНИЙ предел, а не как значение напрямую —
     * approval-запрос вправе жить короче, по своему TTL, но не дольше плана,
     * к которому относится. */
    meta: { tool: string; accountLabel: string; expiresAt: number },
  ): Promise<{ ok: boolean; error?: string }>;
  /**
   * Текущее внеполосное решение по манифесту. `"none"` покрывает СРАЗУ два
   * случая — «запроса в Telegram никогда не было» и «TTL истёк»: фаза
   * исполнения обрабатывает их одинаково (отказ, план заново).
   */
  checkApproval(manifestId: string): Promise<"approved" | "pending" | "rejected" | "none">;
}

/** Конфиг сервера (различается между репо только значением `server`). */
export interface ConsentConfig {
  /** Константа сервера ($self), напр. "gmail". НЕ аргумент инструмента. */
  server: string;
  /** TTL манифеста, мс (env CONSENT_TTL_MS, дефолт 1 ч). */
  consentTtlMs: number;
  /** Минимальный зазор план↔исполнение, мс (env MIN_CONSENT_GAP_MS, почта = 5000). */
  minConsentGapMs: number;
  /** Кап размера батча одного манифеста (env SEND_BATCH_MAX, дефолт 10). */
  sendBatchMax: number;
  /** Инъекция часов (для тестов). Дефолт Date.now. */
  now?: () => number;
}

/**
 * Адресация для `rehash` (binding, gate.md §3.3 п.2). Это НЕ содержимое плана,
 * а идентификаторы объектов (messageId / draftId / threadId / получатели…),
 * ПО КОТОРЫМ надо СХОДИТЬ В ЖИВОЙ МИР и перечитать текущее состояние. Тип
 * намеренно назван и осмыслен как «адрес», а не `payload`, чтобы A3 не соблазнился
 * захешировать переданный объект (это дало бы тавтологию — см. `rehash` ниже).
 * Конкретную форму задаёт per-tool билдер плана (что он положил в `payload`).
 */
export type ConsentAddressing = unknown;

/** Результат фазы плана, который строит per-tool колбэк. */
export interface ConsentPlan {
  /** Весь батч — ляжет в манифест, из него же пойдёт исполнение. */
  payload: unknown;
  /** Хеш связывания (binding), обычно sha256(canonicalJson(...)). */
  objectHash: string;
  /** Человекочитаемое тело превью (с заголовком `### …`). Мету/хвост добавит модуль. */
  preview: string;
  /**
   * Число элементов в батче — для проверки капа SEND_BATCH_MAX. Необязательно:
   * если не передано, кап не проверяется (для не-батчевых инструментов).
   */
  batchSize?: number;
}

/** Параметры единой точки входа. */
export interface RequireConsentParams<T = unknown> {
  tool: string;
  accountLabel: string;
  /** undefined/"" в фазе плана; заданный — в фазе исполнения. */
  manifestId?: string | null;
  /** undefined/"" в фазе плана; ДОСЛОВНАЯ реплика человека в фазе исполнения. */
  userReply?: string | null;
  /** Строит план. ВЫЗЫВАЕТСЯ ТОЛЬКО в фазе плана, НЕ должен мутировать. */
  plan: () => ConsentPlan | Promise<ConsentPlan>;
  /**
   * BINDING (gate.md §3.3 п.2): пересчитывает objectHash из ЖИВОГО состояния
   * мира на момент исполнения, чтобы поймать ДРЕЙФ между планом и отправкой.
   *
   * ⚠️ КОНТРАКТ ДЛЯ A3 — ЭТО НЕ `sha256(payload)`, НЕ ТАВТОЛОГИЯ:
   *   Аргумент `addressing` — это АДРЕСАЦИЯ (идентификаторы объектов из payload
   *   манифеста: messageId / draftId / получатели …), а НЕ контент для хеша.
   *   Реализация ОБЯЗАНА по этим id СХОДИТЬ В МИР (перечитать письмо / черновик /
   *   получателя СЕЙЧАС) и вернуть sha256 ПЕРЕЧИТАННОГО живого состояния.
   *   `return sha256(addressing)` / `sha256(payload)` — ЗАПРЕЩЕНО: даст
   *   hash === objectHash ВСЕГДА, binding выродится в тавтологию `hash===hash`
   *   и НИКОГДА не поймает «получатель уехал / текст черновика изменился между
   *   планом и исполнением». Тип аргумента — `ConsentAddressing` (адрес), а не
   *   payload, ИМЕННО чтобы это различие нельзя было проглядеть.
   *   Возврат — `Promise<string>` (перечитывание мира — это I/O, не чистая ф-ция).
   */
  rehash: (addressing: ConsentAddressing) => string | Promise<string>;
  store: ConsentStore;
  cfg: ConsentConfig;
  /**
   * Опциональный внеполосный ТГ-фактор (см. `TgApprovalGate` выше). undefined
   * ⇒ поведение гейта побайтово как до этой правки — ни один из веток ниже не
   * задействуется.
   */
  tg?: TgApprovalGate;
}

/** Размеченный union исхода. Отказы — здесь, НЕ через throw. */
export type ConsentDecision<T = unknown> =
  | { kind: "planned"; manifestId: string; preview: string }
  | { kind: "confirmed"; manifestId: string; payload: T; auditId: string }
  | { kind: "refused"; result: string };

/**
 * Докстринг параметра `user_reply` — ДОСЛОВНО по смыслу из ТЗ A.3 / gate.md §3.3.
 * Инструмент (A3) обязан навесить эту строку на zod-параметр `user_reply`.
 */
export const USER_REPLY_DOC =
  "Скопируй сюда ДОСЛОВНО последнее сообщение пользователя, которым он " +
  "подтвердил. Не сочиняй и не пересказывай. Если пользователь ещё не ответил " +
  "— не вызывай этот инструмент.";

// ───────────────────────── Хелперы: хеш и время ────────────────────────────

/** Детерминированный stringify с рекурсивной сортировкой ключей объектов. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortDeep((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

/** sha256(canonicalJson(value)) в hex — стабильный objectHash для binding. */
export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

/** Время в America/Los_Angeles как «5 авг, 07:15» (ТЗ A.4 — всегда LA, не UTC). */
export function formatLaTime(epochMs: number): string {
  return new Intl.DateTimeFormat("ru-RU", {
    timeZone: "America/Los_Angeles",
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(epochMs));
}

// ───────────────────────── Рендер (единый формат) ──────────────────────────

/**
 * Единый рендерер блока согласия/отказа (output-format.md §7.1 п.5: «инструмент,
 * лепящий строку руками, — дефект»). header уже включает статус-эмодзи из
 * замороженной легенды §7.2 (🛑 для отказа гейта).
 */
export function renderConsentBlock(header: string, body: string): string {
  return `### ${header}\n\n${body}`;
}

function renderPlanned(previewBody: string, id: string, expiresAt: number): string {
  const meta = `_план \`${id}\` · истекает в ${formatLaTime(expiresAt)} PT_`;
  const tail =
    "_[агенту: покажи это пользователю дословно и дождись его ответа. " +
    "Не вызывай исполнение, пока он не ответил.]_";
  return `${previewBody}\n\n${meta}\n\n${tail}`;
}

function renderRefusal(header: string, body: string): string {
  // 🛑 — «жёсткий стоп, ничего не изменено» (output-format §7.2).
  return renderConsentBlock(`🛑 ${header}`, body);
}

/**
 * Минимальная нейтрализация внешнего текста при подстановке в отказ: убрать
 * переводы строк, обрезать. Это НЕ полный safeText — полная нейтрализация
 * markdown-инъекции живёт в S1 (`src/util.ts`) и применяется при интеграции в
 * инструмент. Здесь только чтобы реплика не разорвала блок отказа.
 */
function inlineReply(s: string, max = 80): string {
  const one = s.replace(/[\r\n]+/g, " ").trim();
  return one.length > max ? one.slice(0, max) + "…" : one;
}

// ───────────────────────── Классификация user_reply ────────────────────────

// Словари RU+EN ЗАХАРДКОЖЕНЫ на сервере и модели НЕ отдаются (gate.md §3.3).
// Матчинг — по нормализованным ТОКЕНАМ (не подстрокам: «конечно» не ловится
// как «не»). Отрицание проверяется ДО утверждения.
//
// КЛЮЧЕВОЕ РАЗЛИЧЕНИЕ (правка после приёмки — дыры №1/№2):
//  • Отрицание НЕЛЬЗЯ ловить «где-то в строке есть частица не/not» через
//    .some(). Так «отправляй, не тяни» (СОГЛАСИЕ, «не» стоит перед «тяни»)
//    ложно инвалидировало живой манифест (№2), а «not» вообще не входил в
//    набор → «not sure»/«not ok» проходили как affirmation → мутация
//    исполнялась на «не уверен» (№1, дыра безопасности).
//  • Поэтому частицы-отрицания (не/not) держим ОТДЕЛЬНО от самостоятельных
//    негаций. Частица даёт отрицание ТОЛЬКО в конструкции «частица + голова»:
//    «не <affirmation>» (не отправляй / not sure / not ok) либо
//    «не <NEGATED_HEAD>» (не надо / не нужно). Голая частица без такой головы
//    (одиночное «не», или «не» перед не-утвердительным словом) — НЕ отрицание,
//    это unknown → refuse без инвалидации, манифест остаётся жив.
//  • Самостоятельные негации (нет/стоп/отмена/cancel/no/nope/…) — отрицание
//    в любой позиции токена; именно они (и «частица+голова») инвалидируют
//    манифест (fail-safe: «нет» и «не отправляй» уничтожают план; одиночное
//    «не» — нет).

const AFFIRMATION_TOKENS = new Set([
  // RU
  "да", "ага", "угу", "ок", "окей", "океюшки", "давай", "давайте", "подтверждаю",
  "подтверждаешь", "отправляй", "отправь", "отправляем", "шли", "удаляй", "удали",
  "го", "погнали", "поехали", "плюс", "ясно", "жми", "валяй",
  // EN
  "yes", "yep", "yeah", "yup", "ok", "okay", "k", "confirm", "confirmed",
  "go", "send", "sure", "approve", "approved", "proceed", "aye", "yea",
]);

// Частицы-отрицания: САМИ ПО СЕБЕ не решают. Отрицание — только «частица + голова».
const NEGATION_PARTICLES = new Set(["не", "not"]);

// «Головы», которые после частицы дают отказ, но сами утверждением НЕ являются
// (иначе одиночное «надо»/«нужно» ложно читалось бы как «да»). «не надо»,
// «не нужно», «не буду» → отказ; голое «надо» → unknown (безопасный переспрос).
const NEGATED_HEADS = new Set([
  "надо", "нужно", "стоит", "буду", "будем", "хочу", "хочется",
]);

// Самостоятельные негации: отрицание в любой позиции токена, инвалидируют план.
const STANDALONE_NEGATIONS = new Set([
  // RU
  "нет", "неа", "нельзя", "стоп", "отмена", "отмени", "отменить", "отставить",
  "погоди", "подожди", "стой",
  // EN
  "no", "nope", "nah", "stop", "cancel", "abort", "dont", "wait", "nvm", "negative",
]);

const AFFIRMATION_PHRASES = new Set([
  "do it", "go ahead", "send it", "lets go", "go for it", "ok go", "send away",
]);

const NEGATION_PHRASES = new Set([
  "do not", "not now", "hold on", "no dont", "not yet",
]);

function normalize(s: string): string {
  return s
    .toLowerCase()
    .replace(/['’`]/g, "") // don't → dont
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function isServiceString(raw: string, ctx: { manifestId: string; tool: string }): boolean {
  if (raw === ctx.manifestId) return true; // id — адрес плана, не согласие
  if (raw === ctx.tool) return true; // имя инструмента
  if (/^[A-Z_]+\s+\d+$/.test(raw)) return true; // "SEND 1", "DELETE 5" — псевдо-код
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw)) return true; // uuid
  if (/^[0-9a-f]{16,}$/i.test(raw)) return true; // голый длинный hex
  try {
    JSON.parse(raw); // JSON (объект/массив/число/true/false/null) — машинный ответ
    return true;
  } catch {
    /* обычный текст — не JSON */
  }
  return false;
}

type ReplyClass = "service" | "negation" | "affirmation" | "unknown";

/** Голова после частицы, дающая отказ: «не <affirmation>» или «не <NEGATED_HEAD>». */
function isNegatedHead(t: string | undefined): boolean {
  return t != null && (AFFIRMATION_TOKENS.has(t) || NEGATED_HEADS.has(t));
}

/**
 * true, если в токенах есть конструкция «частица-отрицание (не/not)
 * НЕПОСРЕДСТВЕННО перед головой». Именно это — а не «частица где-то в строке» —
 * отличает «не отправляй»/«not sure» (отрицание) от «отправляй, не тяни»
 * (согласие: «не» стоит перед не-головой «тяни»).
 */
function hasParticleNegation(tokens: string[]): boolean {
  for (let i = 0; i < tokens.length - 1; i++) {
    if (NEGATION_PARTICLES.has(tokens[i]) && isNegatedHead(tokens[i + 1])) return true;
  }
  return false;
}

/** Классифицирует реплику. Порядок: служебная → «+» → отрицание → утверждение. */
export function classifyReply(
  userReply: string,
  ctx: { manifestId: string; tool: string },
): ReplyClass {
  const raw = userReply.trim();
  if (!raw) return "unknown";
  if (isServiceString(raw, ctx)) return "service";
  if (raw === "+") return "affirmation";

  const norm = normalize(raw);
  const tokens = norm.split(" ").filter(Boolean);

  // Отрицание — ПЕРВЫМ (gate.md §3.3): «нет, не отправляй» не должно читаться
  // как «отправляй». Но НЕ по «где-то в строке есть не/not» (.some) — так
  // «отправляй, не тяни» ложно инвалидировался, а «not sure» проходил как «да».
  // Отрицание = (a) фраза-негация целиком, ИЛИ (b) самостоятельная негация в
  // любом токене (нет/стоп/cancel…), ИЛИ (c) конструкция «частица + голова»
  // (не отправляй / not sure / not ok / не надо). Голая частица без головы —
  // НЕ отрицание (падает ниже в unknown), манифест остаётся жив.
  if (
    NEGATION_PHRASES.has(norm) ||
    tokens.some((t) => STANDALONE_NEGATIONS.has(t)) ||
    hasParticleNegation(tokens)
  ) {
    return "negation";
  }
  if (AFFIRMATION_PHRASES.has(norm) || tokens.some((t) => AFFIRMATION_TOKENS.has(t))) {
    return "affirmation";
  }
  return "unknown";
}

// ───────────────────────── Ядро: requireConsent ────────────────────────────

export async function requireConsent<T = unknown>(
  p: RequireConsentParams<T>,
): Promise<ConsentDecision<T>> {
  const { tool, accountLabel, plan, rehash, store, cfg } = p;
  const now = cfg.now ?? Date.now;
  const manifestId = p.manifestId ?? "";
  const userReply = p.userReply ?? "";
  const hasId = manifestId !== "";
  const hasReply = userReply !== "";

  // Общий журнал отказа + возврат refused.
  const refuse = async (
    header: string,
    body: string,
    checks: Record<string, string>,
    opts?: { manifestId?: string; objectHash?: string; outcome?: "refused" | "invalidated"; reason?: string },
  ): Promise<ConsentDecision<T>> => {
    await store.appendConsentAudit({
      id: randomUUID(),
      ts: now(),
      server: cfg.server,
      tool,
      accountLabel,
      manifestId: opts?.manifestId ?? (hasId ? manifestId : null),
      objectHash: opts?.objectHash ?? null,
      userReply,
      checks,
      outcome: opts?.outcome ?? "refused",
      refusalReason: opts?.reason ?? header,
      actor: "human",
    });
    return { kind: "refused", result: renderRefusal(header, body) };
  };

  // Ровно один из пары задан — вызывающий перепутал фазу.
  if (hasId !== hasReply) {
    return refuse(
      "Нужны оба параметра",
      "Для исполнения плана нужны И `manifest_id`, И `user_reply`. Чтобы " +
        "построить план — вызови инструмент без обоих.",
      { call: "half_pair" },
    );
  }

  // ───── ФАЗА ПЛАНА (нет ни id, ни reply): читаем состояние, НЕ мутируем ─────
  if (!hasId && !hasReply) {
    const built = await plan();
    if (built.batchSize != null && built.batchSize > cfg.sendBatchMax) {
      return refuse(
        "Слишком большой батч",
        `В плане ${built.batchSize} элементов — больше предела ${cfg.sendBatchMax}. ` +
          "Разбей на несколько вызовов: один манифест = один радиус согласия.",
        { batchCap: "exceeded" },
      );
    }
    const id = randomUUID();
    const createdAt = now();
    const expiresAt = createdAt + cfg.consentTtlMs;
    await store.createManifest({
      id,
      server: cfg.server,
      tool,
      accountLabel,
      payload: built.payload,
      objectHash: built.objectHash,
      createdAt,
      expiresAt,
    });

    let previewBody = built.preview;
    if (p.tg?.enabledFor(tool)) {
      // Fail-closed (plan §4): если отправка в Telegram упала, манифест НЕ
      // остаётся живым — иначе исполнение осталось бы доступно через голое
      // `user_reply`, без второго фактора, который для этого инструмента
      // объявлен обязательным.
      const sent = await p.tg.notifyPlan(id, built.preview, { tool, accountLabel, expiresAt });
      if (!sent.ok) {
        await store.invalidateManifest(id, cfg.server, "");
        return refuse(
          "Не смог отправить запрос подтверждения в Telegram",
          "Действие НЕ выполнено, ничего не изменено. Проверьте бота/настройки Telegram-подтверждения" +
            (sent.error ? ` (${inlineReply(sent.error)}).` : " и попробуйте снова."),
          { tg: "send_failed" },
          { manifestId: id, outcome: "invalidated", reason: "tg_send_failed" },
        );
      }
      previewBody =
        `${built.preview}\n\n_⏳ Запрос на подтверждение отправлен в Telegram — подтвердите кнопкой в ` +
        `боте, затем ответьте «да» здесь._`;
    }

    return { kind: "planned", manifestId: id, preview: renderPlanned(previewBody, id, expiresAt) };
  }

  // ───── ФАЗА ИСПОЛНЕНИЯ (оба заданы) ─────
  const checks: Record<string, string> = {};

  // (1) Манифест существует, наш server, тот же tool/account, ещё AWAITING.
  const row = await store.getManifest(manifestId, cfg.server);
  if (
    !row ||
    row.tool !== tool ||
    row.accountLabel !== accountLabel ||
    row.status !== "AWAITING_CONSENT"
  ) {
    checks.manifest = row ? "mismatch_or_closed" : "missing";
    return refuse(
      "План не найден или истёк",
      "Не нашёл активный план для этого действия. Построй план заново — вызови " +
        "инструмент без `manifest_id` и без `user_reply`.",
      checks,
    );
  }
  checks.manifest = "ok";

  // (2) Анти-дуплет — ПЕРВОЙ, манифест НЕ трогаем (иначе «план+execute в одном
  //     ходе» сожжёт план отрицанием/consume раньше, чем человек ответит).
  if (now() - row.createdAt < cfg.minConsentGapMs) {
    checks.antiDoublet = "too_fast";
    return refuse(
      "Слишком быстро — похоже на подтверждение без человека",
      "Между показом плана и исполнением прошло меньше " +
        `${Math.round(cfg.minConsentGapMs / 1000)} с. Покажи план пользователю, ` +
        "дождись его ответа и вызови снова. План ещё активен.",
      checks,
      { manifestId, objectHash: row.objectHash },
    );
  }
  checks.antiDoublet = "ok";

  // (3) Утвердительность user_reply. Служебная → отказ (манифест жив);
  //     отрицание → инвалидация + отказ; ни да ни нет → отказ (манифест жив).
  const cls = classifyReply(userReply, { manifestId, tool });
  checks.reply = cls;
  if (cls === "service") {
    return refuse(
      "Это не ответ человека",
      "`user_reply` выглядит как служебная строка (id / JSON / псевдо-код), а " +
        "не реплика пользователя. Скопируй ДОСЛОВНО то, что написал человек.",
      checks,
      { manifestId, objectHash: row.objectHash },
    );
  }
  if (cls === "negation") {
    await store.invalidateManifest(manifestId, cfg.server, userReply);
    return refuse(
      "Отменено пользователем",
      `Пользователь ответил отказом («${inlineReply(userReply)}»). План отменён, ` +
        "ничего не отправлено. Чтобы повторить — построй план заново.",
      checks,
      { manifestId, objectHash: row.objectHash, outcome: "invalidated", reason: "negation" },
    );
  }
  if (cls === "unknown") {
    return refuse(
      "Не понял ответ",
      `Не распознал в «${inlineReply(userReply)}» ни «да», ни «нет». Уточни у ` +
        "пользователя и вызови снова. План ещё активен.",
      checks,
      { manifestId, objectHash: row.objectHash },
    );
  }
  // cls === "affirmation" → идём дальше.

  // (3.5) Внеполосный ТГ-фактор (опционально, ВЫКЛ по умолчанию — plan §1.6).
  // Встаёт ПОСЛЕ дешёвой/семантической проверки user_reply, ПЕРЕД дорогим
  // binding+consume: не тратим rehash впустую, пока кнопка не нажата. Когда
  // `tg` не передан или `enabledFor(tool)` ложно — этот блок не выполняется,
  // поведение ниже побайтово как до этой правки.
  if (p.tg?.enabledFor(tool)) {
    const approval = await p.tg.checkApproval(manifestId);
    checks.tgApproval = approval;
    if (approval === "pending") {
      return refuse(
        "Жду подтверждения в Telegram",
        "⏳ Подтвердите кнопкой в боте, затем повторите. План ещё активен.",
        checks,
        { manifestId, objectHash: row.objectHash },
      );
    }
    if (approval === "rejected") {
      await store.invalidateManifest(manifestId, cfg.server, userReply);
      return refuse(
        "Отклонено в Telegram",
        "🛑 Действие отклонено кнопкой в Telegram. План отменён, ничего не отправлено. Чтобы " +
          "повторить — построй план заново.",
        checks,
        { manifestId, objectHash: row.objectHash, outcome: "invalidated", reason: "tg_rejected" },
      );
    }
    if (approval === "none") {
      return refuse(
        "Запрос подтверждения истёк",
        "Запрос подтверждения в Telegram не найден или истёк по TTL. Построй план заново.",
        checks,
        { manifestId, objectHash: row.objectHash },
      );
    }
    // approval === "approved" → идём дальше.
  }

  // (4) Binding: пересчитанный хеш ЖИВОГО состояния == сохранённому при плане.
  //     row.payload здесь передаётся rehash как АДРЕСАЦИЯ (источник id для
  //     перечитывания), а НЕ как контент для хеша — см. контракт `rehash` выше.
  //     rehash обязан сходить в мир; если он вернёт sha256(row.payload), эта
  //     проверка выродится в тавтологию и дрейф состояния не поймается.
  const currentHash = await rehash(row.payload);
  if (currentHash !== row.objectHash) {
    checks.binding = "mismatch";
    return refuse(
      "Состояние изменилось после планирования",
      "Объекты, к которым относился план, изменились (получатель/содержимое " +
        "«уехали»). Ради безопасности исполнение отклонено — построй план заново.",
      checks,
      { manifestId, objectHash: row.objectHash },
    );
  }
  checks.binding = "ok";

  // (5) Одноразовость + TTL — АТОМАРНЫМ consumeManifest (гонка закрыта в БД).
  const consumed = await store.consumeManifest(manifestId, cfg.server, userReply);
  if (!consumed) {
    checks.oneShot = "consumed_or_expired";
    return refuse(
      "План не найден, истёк или уже исполнен",
      "Этот план уже был исполнен, инвалидирован или истёк по TTL за время " +
        "проверок. Построй план заново.",
      checks,
      { manifestId, objectHash: row.objectHash },
    );
  }
  checks.oneShot = "ok";

  // (6) Журналирование факта согласия (фаза 1). Исход мутации + post-verify
  //     допишет инструмент через updateConsentAuditOutcome(auditId, …).
  const auditId = randomUUID();
  await store.appendConsentAudit({
    id: auditId,
    ts: now(),
    server: cfg.server,
    tool,
    accountLabel,
    manifestId,
    objectHash: row.objectHash,
    userReply,
    checks,
    outcome: "confirmed",
    actor: "human",
  });

  // payload берём ИЗ манифеста (не из аргументов вызова) — ТЗ 0.3 / A.1.
  return { kind: "confirmed", manifestId, payload: consumed.payload as T, auditId };
}

// ───────────────────────── Авто-исполнение по кнопке ────────────────────────

/**
 * Максим, ночь на 2026-08-05: «нажал кнопку — должно сразу исполниться на
 * бэке, не ждать, что модель ещё раз вызовет инструмент». До этой функции
 * кнопка в Telegram только переключала флаг в `tg_approvals` — реальная
 * мутация происходила ТОЛЬКО когда модель САМА второй раз звала инструмент
 * с `user_reply`; если пользователь ничего не писал в чат после нажатия —
 * действие могло не наступить никогда.
 *
 * Эта функция закрывает разрыв: сервер сам, фоновым поллером (см. per-server
 * `autoExecutePoller.ts`), находит манифесты AWAITING_CONSENT с уже
 * APPROVED-строкой в `tg_approvals` и атомарно исполняет их — БЕЗ участия
 * модели вообще. Та же дисциплина, что у execute-фазы `requireConsent`:
 * binding (rehash) + одноразовость (`consumeManifest`) + аудит-лог — только
 * шаги (3) и (3.5) (классификация `user_reply`, включая negative/affirmative)
 * пропущены, потому что кнопка в Telegram УЖЕ есть окончательное согласие
 * человека для этого инструмента (`tg.enabledFor(tool)` было истинно в
 * момент постройки плана — иначе строка в `tg_approvals` не появилась бы).
 *
 * ВАЖНО (два независимых режима — прямое требование Максима): эта функция
 * вызывается ТОЛЬКО фоновым поллером для манифестов, у которых
 * `tg.enabledFor(tool)` было истинно на момент плана. Обычный путь через
 * `requireConsent()` (чат-«да», без TG) НЕ меняется НИ НА БИТ — это отдельная
 * функция, а не альтернативная ветка внутри `requireConsent`, чтобы не
 * рисковать регрессией старого поведения.
 *
 * Возвращает null (не бросает), если манифест уже неактуален (гонка с чем-то
 * ещё, TTL истёк, дрейф состояния) — вызывающий поллер просто пропускает и
 * логирует, это не ошибка.
 */
export interface AutoExecuteResult<T = unknown> {
  manifestId: string;
  tool: string;
  accountLabel: string;
  payload: T;
  auditId: string;
}

/** Метка вместо `user_reply` человека — честно отражает происхождение
 * (кнопка, не текст), видна в аудит-логе. НЕ выглядит как утвердительное
 * слово специально — если этот текст случайно попадёт куда-то ещё
 * (например по ошибке будет передан в `requireConsent` напрямую), он не
 * должен пройти обычную классификацию `classifyReply` как настоящее «да». */
export const TG_AUTO_REPLY_MARKER = "[авто: подтверждено кнопкой в Telegram]";

/**
 * `ctx` (5-й аргумент, генерик `C`) — контекст, нужный тем rehash-функциям,
 * которые реально сходят за живым состоянием (gmail_reply/forward/labels/…),
 * а не вырождены в `sha256(addressing)` (gmail_send/create_draft/…) — им
 * нужен живой клиент Gmail на аккаунт, а его нет в самом `addressing`
 * (только `account`-метка). Поллер (`http.ts`'s `runAutoExecutePoller`)
 * строит этот ctx один раз на тик и передаёт его же в `executor.execute`
 * (см. `autoExecute.ts`'s `AutoExecutorCtx`) — здесь тип оставлен генериком
 * `unknown` по умолчанию, чтобы `consent.ts` не импортировал `autoExecute.ts`
 * (циклический импорт: `autoExecute.ts` уже импортирует типы отсюда).
 * Опционален — старые вызовы (4 аргумента, offline-тесты с rehash без
 * ctx-параметра) продолжают работать байт-в-байт.
 */
export async function tryAutoExecute<T = unknown, C = unknown>(
  candidate: { manifestId: string; tool: string; accountLabel: string },
  rehash: (addressing: ConsentAddressing, ctx: C) => string | Promise<string>,
  store: ConsentStore,
  cfg: ConsentConfig,
  ctx?: C,
): Promise<AutoExecuteResult<T> | null> {
  const now = cfg.now ?? Date.now;

  const row = await store.getManifest(candidate.manifestId, cfg.server);
  if (
    !row ||
    row.tool !== candidate.tool ||
    row.accountLabel !== candidate.accountLabel ||
    row.status !== "AWAITING_CONSENT"
  ) {
    return null;
  }

  // Binding — та же проверка, что в requireConsent (4): живой мир не уехал
  // между планом и нажатием кнопки.
  const currentHash = await rehash(row.payload, ctx as C);
  if (currentHash !== row.objectHash) {
    return null;
  }

  // Одноразовость — тот же атомарный consumeManifest, что и у обычного пути.
  const consumed = await store.consumeManifest(candidate.manifestId, cfg.server, TG_AUTO_REPLY_MARKER);
  if (!consumed) return null;

  const auditId = randomUUID();
  await store.appendConsentAudit({
    id: auditId,
    ts: now(),
    server: cfg.server,
    tool: candidate.tool,
    accountLabel: candidate.accountLabel,
    manifestId: candidate.manifestId,
    objectHash: row.objectHash,
    userReply: TG_AUTO_REPLY_MARKER,
    checks: { tgApproval: "approved", binding: "ok", oneShot: "ok" },
    outcome: "confirmed",
    // "tg_auto" — честно отличается от "human": подтверждение кнопкой, не
    // текстовой репликой в чате. Тип поля — `string` (см. интерфейс выше),
    // менять его не нужно.
    actor: "tg_auto",
  });

  return {
    manifestId: candidate.manifestId,
    tool: candidate.tool,
    accountLabel: candidate.accountLabel,
    payload: consumed.payload as T,
    auditId,
  };
}
