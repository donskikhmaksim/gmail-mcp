/**
 * Маскировка секретов пути в том, что уходит в лог (#119).
 *
 * ЗАЧЕМ. Дашборд управления аккаунтами защищён НЕ паролем, а неугадываемым
 * сегментом пути: `/dashboard/<DASHBOARD_SECRET>` (см. http.ts). При старте
 * сервер печатал этот URL целиком — то есть боевой секрет открытым текстом
 * оседал в логах Railway, а логи видит всякий, у кого есть доступ к проекту;
 * они же попадают в выгрузки и в скриншоты при отладке. Секрет не истекает
 * и не ротируется, так что доступ к логам = доступ к дашборду (а дашборд
 * умеет отвязывать аккаунты и привязывать новые).
 *
 * ЧТО ДЕЛАЕМ. Строка лога проходит через фильтр, который подменяет секретный
 * сегмент заглушкой:
 *
 *     Account dashboard at https://app.up.railway.app/dashboard/<dashboard-secret>
 *
 * Снаружи не меняется ничего: URL прежний, клиенты (браузер, коннекторы) не
 * замечают разницы — меняется только текст, попадающий в лог. Всё полезное
 * остаётся: адрес сервера, наличие дашборда, форма пути; скрыт ровно тот
 * сегмент, который является паролем.
 *
 * ЧЕГО ЭТО НЕ ДЕЛАЕТ. Секреты, уже попавшие в старые логи, остаются там —
 * их надо считать скомпрометированными и ротировать отдельно.
 *
 * Файл СПЕЦИАЛЬНО одинаков во всех пяти Google-серверах (gmail/drive/docs/
 * sheets/calendar-mcp) — та же дисциплина побайтового переноса, что у
 * tg_approval.ts: чинить утечку в одном репозитории и разойтись в остальных
 * ровно так и получается.
 */

/** Заглушка вместо DASHBOARD_SECRET. */
export const DASHBOARD_SECRET_PLACEHOLDER = "<dashboard-secret>";
/** Заглушка вместо одноразового токена ссылки на вложение (/dl/<токен>). */
export const LINK_TOKEN_PLACEHOLDER = "<link-token>";

/**
 * Ниже этой длины подстроку НЕ вырезаем по всему тексту: короткое значение
 * («ok», «id») может встретиться в осмысленном сообщении, и слепая замена
 * сделает логи бесполезными. Секрет короче 8 символов и так не секрет, а
 * позиционное правило ниже накроет его независимо от длины.
 */
const MIN_INLINE_SECRET_LEN = 8;

/** Сегмент сразу после /dashboard/ или /dl/ — это и есть пропуск. */
const DASHBOARD_PATH_RE = /(\/dashboard\/)([^/?\s"'`]+)/g;
const LINK_PATH_RE = /(\/dl\/)([^/?\s"'`]+)/g;

/** Экранирование для построения RegExp из произвольного значения секрета. */
function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Вернуть текст с замаскированными секретами пути. Идемпотентна: повторный
 * прогон уже отфильтрованной строки ничего не меняет.
 */
export function redactPathSecrets(text: string, secret?: string): string {
  if (!text) return text;
  let out = text;
  if (secret && secret.length >= MIN_INLINE_SECRET_LEN) {
    out = out.replace(new RegExp(escapeForRegExp(secret), "g"), DASHBOARD_SECRET_PLACEHOLDER);
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) {
      out = out.replace(new RegExp(escapeForRegExp(encoded), "g"), DASHBOARD_SECRET_PLACEHOLDER);
    }
  }
  out = out.replace(DASHBOARD_PATH_RE, (_m, prefix: string) => prefix + DASHBOARD_SECRET_PLACEHOLDER);
  out = out.replace(LINK_PATH_RE, (_m, prefix: string) => prefix + LINK_TOKEN_PLACEHOLDER);
  return out;
}

/**
 * Напечатать, где живёт дашборд, НЕ печатая его секрет.
 *
 * Отдельная экспортируемая функция, а не строчка внутри startHttpServer, —
 * чтобы тест мог позвать ровно тот код, который работает в бою, и прочитать
 * реально напечатанную строку (scripts/test-log-redaction.mjs).
 */
export function logDashboardLocation(baseUrl: string, dashboardPath: string, secret?: string): void {
  console.error(redactPathSecrets(`Account dashboard at ${baseUrl}${dashboardPath}`, secret));
}
