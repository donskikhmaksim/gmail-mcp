/**
 * autoExecute.ts — реестр «ядер исполнения» гейтованных тулов, вызываемых
 * фоновым поллером НАПРЯМУЮ (в обход MCP-транспорта и модели вообще) — см.
 * consent.ts's `tryAutoExecute` doc-comment (Максим, 2026-08-05: «нажал
 * кнопку — сразу исполнилось на бэке»).
 *
 * КРИТИЧНО ПРО БЕЗОПАСНОСТЬ: этот реестр НИКОГДА не выставляется как
 * MCP-параметр инструмента (никакого `auto_confirmed: true` в схеме) — модель
 * не может вызвать `execute` отсюда никаким аргументом. Единственный
 * вызывающий — поллер сервера (`http.ts`'s `runAutoExecutePoller`), который
 * САМ находит кандидатов через `store.listApprovedUnexecuted()` (Postgres,
 * не аргумент вызова) и вызывает `tryAutoExecute()` (не пропускает binding/
 * one-shot, только классификацию текстовой реплики — TG-кнопка уже была
 * единственным доказанным согласием для этого тула).
 *
 * Регистрация — на уровне МОДУЛЯ (при импорте), не внутри `registerXTools()`
 * (та функция вызывается ПОВТОРНО на каждый MCP-запрос — реестр не должен
 * зависеть от того, приходил ли уже хоть один запрос).
 */

import type { UserClients } from "./accounts.js";
import type { ConsentStore, ConsentAddressing } from "./consent.js";
import type { SafeFetchDeps } from "./safeFetch.js";

/** Минимальная структурная поверхность, нужная snooze/schedule_send для
 * персистентности — то же самое, что `tools/gmail.ts`'s локальный `PgStore`
 * покрывает своими `addSnooze`/`addScheduledSend`, но описано здесь заново
 * (а не импортировано оттуда), чтобы избежать циклического импорта
 * (gmail.ts уже импортирует ЭТОТ модуль). Держать поля 1:1 с `PgStore`. */
export interface AutoExecutorPgStore {
  addSnooze(args: { userToken: string | null; accountName: string; messageId: string; subject?: string; unsnoozeAt: Date }): Promise<void>;
  addScheduledSend(args: {
    userToken: string | null;
    accountName: string;
    rawMessage: string;
    toPreview: string;
    subjectPreview: string;
    sendAt: Date;
  }): Promise<number>;
}

export interface AutoExecutorCtx {
  clients: UserClients;
  consentStore: ConsentStore;
  /** `user.token` для онбордингового multi-tenant (обычно `null` в
   * self-host-однопользовательском случае) — тот же смысл, что у
   * `GmailSnoozeContext.userToken` в `tools/gmail.ts`. Прокинут сюда, чтобы
   * тулы, которые персистят через юзер-scoped строки store.ts (snooze/
   * scheduled_send), тоже могли авто-исполняться поллером — иначе им негде
   * взять этот токен вне обычного per-request пути. */
  userToken: string | null;
  /** Тот же Postgres-адаптер, что per-request путь получает как
   * `GmailSnoozeContext.store` (`null`, когда DATABASE_URL не настроен) —
   * ИНЖЕКТИРУЕТСЯ вызывающим (`http.ts`'s поллер передаёт server.ts's
   * `pgStoreAdapter`), а не хардкожен на уровне модуля gmail.ts: так и
   * per-request, и авто-путь используют ОДИН настоящий адаптер в проде, а
   * офлайн-тесты могут подставить фейковый через тот же `ctx`. */
  store: AutoExecutorPgStore | null;
  /**
   * Подменяемый транспорт для исходящих запросов к Google (`safeGoogleFetch`),
   * тот же смысл, что у `GmailSnoozeContext.safeFetch`: ПРОД ЭТО НЕ ПЕРЕДАЁТ
   * (поллер в http.ts строит ctx без него ⇒ реальная сеть), поле существует,
   * чтобы офлайн-тесты могли проверить и АВТО-путь (исполнение по кнопке в
   * Telegram) тем же способом, что и обычный вызов инструмента. Это не
   * MCP-параметр — модель сюда ничего положить не может.
   */
  safeFetch?: SafeFetchDeps;
}

/** `ctx` — второй параметр, нужен ТОЛЬКО rehash-функциям с настоящим
 * биндингом (сходят за живым состоянием в Gmail через `ctx.clients.resolve
 * (account)`, `account` берётся из самого `addressing`) — вырожденные
 * `(addressing) => sha256(addressing)` (gmail_send и т.п.) его просто
 * игнорируют, TS это разрешает (функция с меньшим числом параметров
 * подходит под тип с большим). */
export type RehashFn = (addressing: ConsentAddressing, ctx: AutoExecutorCtx) => string | Promise<string>;
/** Возвращает ГОТОВЫЙ человекочитаемый текст отчёта — то же самое, что тул
 * вернул бы модели в чат при обычном (не-авто) исполнении, включая ссылку/
 * артефакт, если тул её производит (см. `_extractText` в http.ts). */
export type ExecuteFn = (payload: unknown, auditId: string, ctx: AutoExecutorCtx) => Promise<string>;

export interface AutoExecutorEntry {
  rehash: RehashFn;
  execute: ExecuteFn;
}

const registry = new Map<string, AutoExecutorEntry>();

export function registerAutoExecutor(tool: string, entry: AutoExecutorEntry): void {
  if (registry.has(tool)) {
    // Может случиться при hot-reload в dev — в проде импорт модуля происходит
    // ровно один раз, так что молчаливая перезапись здесь безобиднее, чем
    // падение, но лог всё равно печатаем, чтобы не потерять сигнал о баге.
    console.error(`autoExecute: tool "${tool}" уже зарегистрирован — перезаписываю`);
  }
  registry.set(tool, entry);
}

export function getAutoExecutor(tool: string): AutoExecutorEntry | undefined {
  return registry.get(tool);
}

export function registeredAutoExecuteTools(): string[] {
  return [...registry.keys()];
}
