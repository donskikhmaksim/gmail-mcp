/**
 * safeFetch.ts — исходящий HTTP только на Google, с защитой от SSRF
 * (server-side request forgery: сервер по чужой указке стучится туда, куда
 * сам вызывающий не дотянулся бы — во внутреннюю сеть, на метаданные облака,
 * на localhost — и возвращает ответ наружу).
 *
 * ЗАЧЕМ. `gmail_confirm_upload` раньше ходил по адресу, ПРИШЕДШЕМУ В
 * АРГУМЕНТЕ инструмента (`uploadUrl`), без единой проверки, и возвращал тело
 * ответа обратно в диалог: модель, которой скормили нужный текст, могла
 * заставить сервер сделать запрос на `http://169.254.169.254/…` (метаданные
 * облака) и получить ответ наружу. Основное лечение — вообще не принимать
 * адрес от модели (см. `uploadSessions.ts`: адрес сессии сервер выдал сам и
 * хранит у себя, наружу уходит только непрозрачный `sessionId`). Этот модуль
 * — ВТОРОЙ рубеж: даже адрес, взятый из собственного хранилища или
 * полученный от Google в заголовке `Location`, всё равно проходит проверку,
 * прежде чем по нему пойдёт соединение.
 *
 * ТРИ УРОВНЯ ПРОВЕРКИ (каждый закрывает то, что не закрывает предыдущий):
 *  1. Разбор адреса (`assertAllowedGoogleUrl`): только https, только хосты
 *     Google (точное совпадение или поддомен из
 *     `ALLOWED_GOOGLE_HOST_SUFFIXES`), только стандартный порт, без
 *     встроенных логина/пароля. Это отсекает и IP-литералы
 *     (`http://10.0.0.1/`, `http://[::1]/`) — они никогда не подходят под
 *     суффикс `googleapis.com`.
 *  2. Проверка адреса, по которому РЕАЛЬНО идёт соединение: имя хоста
 *     резолвится ОДИН раз, каждый полученный адрес проходит `isBlockedIp`, и
 *     соединение ПРИБИВАЕТСЯ (`pinnedLookup`) именно к этим проверенным
 *     адресам — HTTP-клиенту не дают резолвить имя заново. Это закрывает
 *     подмену разрешения имени (DNS rebinding: «первый резолв отдал
 *     публичный адрес, второй — 127.0.0.1»), которую проверка строки адреса
 *     не видит в принципе.
 *  3. Перенаправления не выполняются вслепую: `redirect: "manual"`, и адрес
 *     из `Location` проходит ровно те же проверки (1)+(2), прежде чем по нему
 *     пойдёт следующий запрос. Иначе разрешённый хост мог бы одним 302
 *     увести сервер на `169.254.169.254`.
 *
 * ВАЖНО ПРО 308: Google отвечает `308 Resume Incomplete` на статус-запрос
 * возобновляемой загрузки — это НЕ перенаправление. Поэтому перенаправлением
 * считается только ответ, у которого ЕСТЬ заголовок `Location` (у 308 от
 * Google его нет — там `Range`).
 *
 * ПРО undici: используется undici's ОWN `fetch` + `Agent` (один и тот же
 * экземпляр модуля), а не глобальный `fetch` Node с чужим диспетчером — см.
 * длинный комментарий у `fetchAttachmentSafely` в `tools/gmail.ts`: версии
 * встроенного в Node undici и npm-пакета расходятся, и передача «чужого»
 * диспетчера в глобальный fetch падает на несовпадении внутреннего
 * интерфейса.
 */

import { Agent as UndiciAgent, fetch as undiciFetch } from "undici";
import net from "node:net";
import dns from "node:dns/promises";

/** Хосты, на которые этому серверу вообще позволено ходить по адресам,
 * которые он не составил сам из констант. Только Google. */
export const ALLOWED_GOOGLE_HOST_SUFFIXES = ["googleapis.com", "googleusercontent.com"] as const;

const FETCH_TIMEOUT_MS = 20_000;

// ───────────────────────── Проверка IP-адресов ──────────────────────────────

function parseIpv4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return nums;
}

function ipv4Blocked(a: number[]): boolean {
  const [a0, a1] = a;
  if (a0 === 0) return true; // 0.0.0.0/8 — «этот хост»
  if (a0 === 10) return true; // приватная сеть
  if (a0 === 127) return true; // loopback
  if (a0 === 100 && a1 >= 64 && a1 <= 127) return true; // CGNAT 100.64/10
  if (a0 === 169 && a1 === 254) return true; // link-local, включая 169.254.169.254 (метаданные облака)
  if (a0 === 172 && a1 >= 16 && a1 <= 31) return true; // приватная сеть
  if (a0 === 192 && a1 === 0) return true; // 192.0.0.0/24 (IETF) + 192.0.2.0/24 (TEST-NET-1)
  if (a0 === 192 && a1 === 168) return true; // приватная сеть
  if (a0 === 192 && a1 === 88 && a[2] === 99) return true; // 6to4 relay anycast
  if (a0 === 198 && (a1 === 18 || a1 === 19)) return true; // benchmark
  if (a0 === 198 && a1 === 51) return true; // TEST-NET-2
  if (a0 === 203 && a1 === 0) return true; // TEST-NET-3
  if (a0 >= 224) return true; // multicast, зарезервированное, 255.255.255.255
  return false;
}

/**
 * true — по этому адресу ходить нельзя: локальный хост, приватный диапазон,
 * link-local (в том числе адрес метаданных облака), multicast и прочее
 * «не-публичное». Неразобранный адрес тоже считается небезопасным
 * (fail-closed). Экспортируется отдельно, чтобы это можно было проверять
 * тестом независимо от сети.
 *
 * ЭТА функция — единственная таблица диапазонов на весь сервер: `tools/
 * gmail.ts` реэкспортирует её же для url-вложений, чтобы не разъезжались две
 * копии.
 */
export function isBlockedIp(ip: string): boolean {
  const raw = String(ip).trim().replace(/^\[|\]$/g, "").split("%")[0].toLowerCase();
  const v4 = parseIpv4(raw);
  if (v4) return ipv4Blocked(v4);
  if (net.isIP(raw) !== 6) return true; // не разобрали — считаем небезопасным (fail-closed)

  if (raw === "::" || raw === "::1") return true;

  // IPv4, завёрнутый в IPv6 (::ffff:127.0.0.1, ::127.0.0.1, 64:ff9b::127.0.0.1).
  const dotted = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(raw);
  if (dotted) {
    const inner = parseIpv4(dotted[1]);
    if (inner && ipv4Blocked(inner)) return true;
  }

  const groups = expandIpv6(raw);
  if (!groups) return true; // не разобрали — fail-closed
  const [g0, g1] = groups;
  // ::ffff:7f00:1 — тот же IPv4-mapped, но в hex-форме.
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const mapped = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff];
    if (ipv4Blocked(mapped)) return true;
  }
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 — приватные (в т.ч. fd00:ec2::254, метаданные AWS)
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 — link-local
  if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 — multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // документационный диапазон
  return false;
}

/** Разворачивает IPv6 в 8 групп по 16 бит; null, если разобрать не удалось. */
function expandIpv6(ip: string): number[] | null {
  let s = ip;
  const dotted = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (dotted) {
    const v4 = parseIpv4(dotted[1]);
    if (!v4) return null;
    const hex = `${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
    s = s.slice(0, dotted.index) + hex;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 0 : fill !== 0) return null;
  const parts = [...head, ...Array<string>(halves.length === 2 ? fill : 0).fill("0"), ...tail];
  if (parts.length !== 8) return null;
  const nums = parts.map((p) => (/^[0-9a-f]{1,4}$/.test(p) ? parseInt(p, 16) : NaN));
  return nums.some((n) => Number.isNaN(n)) ? null : nums;
}

// ───────────────────────── Проверка самого адреса ───────────────────────────

/** Ошибка, которую бросают проверки этого модуля (чтобы вызывающий мог
 * отличить «мы сами отказались идти» от «сеть/Google ответили ошибкой»). */
export class BlockedUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlockedUrlError";
  }
}

function hostAllowed(host: string, suffixes: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, ""); // «www.googleapis.com.» — тот же хост
  return suffixes.some((s) => h === s || h.endsWith(`.${s}`));
}

/**
 * Рубеж 1. Проверяет адрес и возвращает разобранный URL. Бросает
 * `BlockedUrlError` с человекочитаемым русским объяснением, если адрес
 * недопустим.
 *
 * Отсекает: не-https, чужие хосты, «похожие» хосты вида
 * `www.googleapis.com.evil.example`, IP-литералы (в том числе
 * `169.254.169.254` и `[::1]`), нестандартные порты, встроенные учётные
 * данные (`https://user:pass@host`).
 */
export function assertAllowedGoogleUrl(
  raw: string,
  allowedHostSuffixes: readonly string[] = ALLOWED_GOOGLE_HOST_SUFFIXES,
): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new BlockedUrlError(`🛑 адрес не разобрался как URL: ${String(raw).slice(0, 120)}`);
  }
  if (url.protocol !== "https:") {
    throw new BlockedUrlError(`🛑 разрешён только https, а адрес начинается с «${url.protocol}»`);
  }
  if (url.username || url.password) {
    throw new BlockedUrlError("🛑 в адресе встроены логин/пароль — такие адреса не принимаем");
  }
  if (url.port && url.port !== "443") {
    throw new BlockedUrlError(`🛑 нестандартный порт ${url.port} — разрешён только 443`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host) !== 0) {
    throw new BlockedUrlError(`🛑 адрес указан числовым IP (${host}) — принимаются только имена хостов Google`);
  }
  if (!hostAllowed(host, allowedHostSuffixes)) {
    throw new BlockedUrlError(
      `🛑 хост ${host} не входит в список разрешённых (${allowedHostSuffixes.join(", ")})`,
    );
  }
  return url;
}

// ───────────── Рубеж 2: адрес, по которому реально идёт соединение ──────────

/** Подменяемый резолвер имён (тесты подставляют свой — настоящий DNS не нужен). */
export type LookupFn = (host: string) => Promise<{ address: string }[]>;
const defaultLookup: LookupFn = (host) => dns.lookup(host, { all: true });

/**
 * Резолвит имя и требует, чтобы КАЖДЫЙ полученный адрес был публичным.
 * Возвращает проверенные адреса, чтобы соединение можно было прибить именно
 * к ним (см. `pinnedLookup`).
 */
export async function resolveVettedAddresses(
  host: string,
  lookup: LookupFn,
): Promise<{ address: string; family: 4 | 6 }[]> {
  let resolved: { address: string }[];
  try {
    resolved = await lookup(host);
  } catch {
    throw new BlockedUrlError(`🛑 не удалось разрешить имя хоста ${host} — запрос не выполнен`);
  }
  if (!resolved.length) {
    throw new BlockedUrlError(`🛑 имя ${host} не разрешается ни в один адрес — запрос не выполнен`);
  }
  const addrs: { address: string; family: 4 | 6 }[] = [];
  for (const a of resolved) {
    if (isBlockedIp(a.address)) {
      throw new BlockedUrlError(
        `🛑 имя ${host} разрешается в закрытый адрес ${a.address} (локальный/приватный/служебный) — соединение не устанавливаю`,
      );
    }
    addrs.push({ address: a.address, family: (net.isIP(a.address) === 6 ? 6 : 4) as 4 | 6 });
  }
  return addrs;
}

/**
 * `net.connect`/`tls.connect`-совместимая функция `lookup`, которая
 * ИГНОРИРУЕТ переданное ей имя и всегда отвечает заранее проверенным списком
 * адресов — то есть не делает никакого собственного резолва. Именно это
 * закрывает подмену разрешения имени: свежий резолв в момент соединения
 * (который контролирует атакующий с коротким TTL записи) не выполняется
 * вообще.
 *
 * Обрабатывает обе формы вызова, которыми пользуются коннекторы Node:
 * `{all:true}` (массив `{address,family}`, Happy Eyeballs) и одноадресную.
 */
export function pinnedLookup(addrs: { address: string; family: 4 | 6 }[]): net.LookupFunction {
  return (_hostname, options, callback) => {
    const wantsAll = typeof options === "object" && options !== null && "all" in options && options.all === true;
    if (wantsAll) {
      callback(null, addrs.map((a) => ({ address: a.address, family: a.family })));
    } else {
      callback(null, addrs[0].address, addrs[0].family);
    }
  };
}

// ───────────────────────── Собственно запрос ────────────────────────────────

export type SafeFetchImpl = typeof undiciFetch;

export interface SafeFetchDeps {
  /** Подменяемый транспорт (тесты; по умолчанию — undici's fetch). */
  fetchImpl?: SafeFetchImpl;
  allowedHostSuffixes?: readonly string[];
  /** Подменяемый резолвер имён (тесты). */
  lookup?: LookupFn;
  /** Сколько перенаправлений разрешено пройти (каждое — с полной проверкой). */
  maxRedirects?: number;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * fetch, которому разрешено ходить только на Google и только на публичные
 * адреса, с прибитым к проверенному адресу соединением. Перенаправления не
 * выполняются автоматически: каждый `Location` проверяется заново, и
 * перенаправление на закрытый адрес превращается в ошибку, а не в запрос.
 */
export async function safeGoogleFetch(
  rawUrl: string,
  init: Record<string, unknown> = {},
  deps: SafeFetchDeps = {},
): Promise<Response> {
  const fetchImpl = deps.fetchImpl ?? undiciFetch;
  const allowed = deps.allowedHostSuffixes ?? ALLOWED_GOOGLE_HOST_SUFFIXES;
  const lookup = deps.lookup ?? defaultLookup;
  const maxRedirects = deps.maxRedirects ?? 3;

  let url = assertAllowedGoogleUrl(rawUrl, allowed);
  for (let hop = 0; ; hop++) {
    const addrs = await resolveVettedAddresses(url.hostname.replace(/^\[|\]$/g, ""), lookup);
    // Таймауты на ВСЕ фазы, не только на установление соединения: иначе
    // «соединились и молчим» держало бы вызов минутами (undici по умолчанию
    // ждёт заголовки/тело по 5 минут). Гейт подтверждения от этого не зависит,
    // но подвисший инструмент — это тоже отказ в обслуживании.
    const dispatcher = new UndiciAgent({
      connect: { lookup: pinnedLookup(addrs), timeout: FETCH_TIMEOUT_MS },
      headersTimeout: FETCH_TIMEOUT_MS,
      bodyTimeout: FETCH_TIMEOUT_MS,
    });
    let res: Awaited<ReturnType<SafeFetchImpl>>;
    try {
      res = await fetchImpl(url.toString() as never, {
        ...init,
        redirect: "manual",
        dispatcher,
      } as never);
    } finally {
      void dispatcher.close().catch(() => {});
    }

    const location = REDIRECT_STATUSES.has(res.status) ? res.headers.get("location") : null;
    if (!location) return res as unknown as Response; // в том числе 308 от Google без Location — это статус, а не редирект
    if (hop >= maxRedirects) {
      throw new BlockedUrlError(`🛑 слишком много перенаправлений (> ${maxRedirects}) — прерываю`);
    }
    let next: string;
    try {
      next = new URL(location, url).toString();
    } catch {
      throw new BlockedUrlError(`🛑 перенаправление на неразбираемый адрес: ${location.slice(0, 120)}`);
    }
    // Ключевое: адрес перенаправления проходит ТЕ ЖЕ проверки. Иначе
    // разрешённый хост одним 302 увёл бы сервер на 169.254.169.254.
    url = assertAllowedGoogleUrl(next, allowed);
  }
}
