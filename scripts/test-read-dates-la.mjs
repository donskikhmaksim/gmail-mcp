#!/usr/bin/env node
/**
 * Даты читающих инструментов — ВСЕГДА America/Los_Angeles, и все инструменты
 * согласны между собой на ОДНОМ письме.
 *
 * Что здесь проверяется и почему (приёмка 2026-08-07):
 * `summarise()` клал в `date` сырой заголовок письма, то есть время в поясе
 * ОТПРАВИТЕЛЯ. На 100 письмах это дало 9 разных смещений, а у 12 писем —
 * чужой календарный день. Самопротиворечие внутри одного инструмента:
 * письмо попадало в выборку `after:2026/08/07 before:2026/08/08`, а
 * `gmail_search` печатал у него «8 Aug»; запрос за 8 августа давал ноль.
 *
 * Фикстуры здесь — ФИКСИРОВАННЫЕ моменты времени, и это НЕ «календарная мина»:
 * код под тестом не выводит окно из текущих часов (нет `now() - N дней`), он
 * переводит конкретный epoch в конкретный пояс. Летний и зимний моменты взяты
 * по разные стороны перехода на летнее время намеренно: смещение LA не
 * константа (−07:00 летом, −08:00 зимой).
 *
 * Сеть не используется: Google-клиент — заглушка.
 *
 * Usage: node scripts/test-read-dates-la.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";
import { laIso, laDateStamp } from "../dist/util.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

// --- фикстуры --------------------------------------------------------------

// Тот самый случай из приёмки: отправитель в +0300 пишет «8 Aug», в LA это
// ещё 7 августа, 16:16.
const SUMMER_HEADER = "Sat, 8 Aug 2026 02:16:37 +0300";
const SUMMER_MS = Date.parse(SUMMER_HEADER); // 2026-08-07T23:16:37Z
// Зима: у отправителя 1 января 09:00 в +0300, в LA это ещё 31 декабря.
const WINTER_HEADER = "Fri, 1 Jan 2027 09:00:00 +0300";
const WINTER_MS = Date.parse(WINTER_HEADER);

const msg = (id, threadId, dateHeader, ms) => ({
  id,
  threadId,
  internalDate: ms === null ? undefined : String(ms),
  snippet: "snippet",
  labelIds: ["INBOX"],
  payload: {
    mimeType: "text/plain",
    headers: [
      { name: "From", value: "Sender <sender@example.com>" },
      { name: "To", value: "me@personal.test" },
      { name: "Subject", value: "Тема" },
      ...(dateHeader ? [{ name: "Date", value: dateHeader }] : []),
    ],
    body: { data: Buffer.from("тело", "utf8").toString("base64url") },
  },
});

const MESSAGES = {
  SUMMER: msg("SUMMER", "T1", SUMMER_HEADER, SUMMER_MS),
  WINTER: msg("WINTER", "T2", WINTER_HEADER, WINTER_MS),
  // internalDate нет — сервер обязан разобрать заголовок отправителя сам.
  NOINTERNAL: msg("NOINTERNAL", "T3", SUMMER_HEADER, null),
  // Времени нет вообще — приводить нечего, выдавать за LA нельзя.
  NODATE: msg("NODATE", "T4", "", null),
};

const fakeClients = {
  names: ["personal"],
  defaultName: "personal",
  multi: false,
  canonicalName: (n) => (n && n.trim() ? n.trim() : "personal"),
  emailFor: () => "me@personal.test",
  resolve: () => ({
    gmail: {
      users: {
        messages: {
          list: async () => ({ data: { messages: Object.keys(MESSAGES).map((id) => ({ id })), resultSizeEstimate: 4 } }),
          get: async ({ id }) => {
            if (!MESSAGES[id]) throw new Error(`Message not found: ${id}`);
            return { data: MESSAGES[id] };
          },
        },
        threads: {
          get: async ({ id }) => {
            const found = Object.values(MESSAGES).filter((m) => m.threadId === id);
            if (!found.length) throw new Error(`Thread not found: ${id}`);
            return { data: { id, messages: found } };
          },
        },
      },
    },
    drive: {},
    docs: {},
    accessToken: async () => "ya29.FAKE",
  }),
  baseGmailQuery: () => "",
};

const server = new McpServer({ name: "test", version: "0" });
registerGmailTools(server, fakeClients, { store: null, userToken: null });
const client = new Client({ name: "test-client", version: "0" });
const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
const call = async (name, args) => {
  const r = await client.callTool({ name, arguments: args });
  return r.structuredContent ?? JSON.parse(r.content[0].text);
};

// --- 1. laIso: перевод в LA, с учётом перехода на летнее время --------------

console.log("\n[1] laIso — пояс LA, а не UTC и не пояс отправителя");
check("лето: +0300 «8 Aug 02:16» → 2026-08-07T16:16:37-07:00", laIso(SUMMER_MS) === "2026-08-07T16:16:37-07:00", laIso(SUMMER_MS));
check("зима: смещение -08:00", laIso(WINTER_MS) === "2026-12-31T22:00:00-08:00", laIso(WINTER_MS));
check("тот же момент времени (Date.parse обратим)", Date.parse(laIso(SUMMER_MS)) === SUMMER_MS, laIso(SUMMER_MS));
check("календарный день — 07, а не 08", laDateStamp(SUMMER_MS) === "2026-08-07", laDateStamp(SUMMER_MS));

// --- 2. gmail_search --------------------------------------------------------

console.log("\n[2] gmail_search отдаёт date в LA");
const search = await call("gmail_search", { query: "in:inbox", maxResults: 4 });
const sSummer = search.messages.find((m) => m.id === "SUMMER");
check("date в LA", sSummer.date === "2026-08-07T16:16:37-07:00", sSummer.date);
check("сырой заголовок сохранён отдельно", sSummer.dateHeader === SUMMER_HEADER, sSummer.dateHeader);
check("internalDate — абсолютное время числом", sSummer.internalDate === SUMMER_MS, sSummer.internalDate);
check("в date нет пояса отправителя (+0300)", !String(sSummer.date).includes("+03"), sSummer.date);

// --- 3. сверка инструментов на ОДНОМ письме --------------------------------

console.log("\n[3] один и тот же объект тремя инструментами — даты сходятся");
const byGet = (await call("gmail_get_message", { messageIds: ["SUMMER"] })).results[0];
const byThread = (await call("gmail_get_thread", { threadIds: ["T1"] })).results[0].messages[0];
check("gmail_get_message == gmail_search", byGet.date === sSummer.date, `${byGet.date} vs ${sSummer.date}`);
check("gmail_get_thread == gmail_search", byThread.date === sSummer.date, `${byThread.date} vs ${sSummer.date}`);
check("все три дают именно LA-значение", [sSummer.date, byGet.date, byThread.date].every((d) => d === "2026-08-07T16:16:37-07:00"), [sSummer.date, byGet.date, byThread.date]);
check("dateHeader тоже совпадает во всех трёх", byGet.dateHeader === SUMMER_HEADER && byThread.dateHeader === SUMMER_HEADER, [byGet.dateHeader, byThread.dateHeader]);

// --- 4. календарный день не «уезжает» --------------------------------------

console.log("\n[4] календарный день = день по Лос-Анджелесу");
check("лето: date начинается с 2026-08-07", byGet.date.startsWith("2026-08-07"), byGet.date);
const winter = (await call("gmail_get_message", { messageIds: ["WINTER"] })).results[0];
check("зима: 1 января у отправителя → 31 декабря в LA", winter.date.startsWith("2026-12-31"), winter.date);
check("зимнее смещение -08:00", winter.date.endsWith("-08:00"), winter.date);

// --- 5. запасные пути -------------------------------------------------------

console.log("\n[5] нет internalDate → парсится заголовок; нет времени вовсе → пусто");
const noInternal = (await call("gmail_get_message", { messageIds: ["NOINTERNAL"] })).results[0];
check("без internalDate date всё равно в LA", noInternal.date === "2026-08-07T16:16:37-07:00", noInternal.date);
const noDate = (await call("gmail_get_message", { messageIds: ["NODATE"] })).results[0];
check("без даты — пустая строка, а не выдумка", noDate.date === "", noDate.date);
check("internalDate = null", noDate.internalDate === null, noDate.internalDate);

// --- 6. очередь отложенной отправки — тоже LA, а не UTC --------------------

console.log("\n[6] gmail_list_scheduled_sends: sendAt в LA");
// Инструмент, вся суть которого — «когда именно уйдёт письмо», печатал
// `sendAt` в UTC, пока превью плана и журнал согласий печатали то же событие
// в PT: летом расхождение семь часов, то есть вечерняя отправка по LA
// показывалась в очереди уже завтрашним днём.
const queueStore = {
  async listScheduledSends() {
    return [{ id: "S1", toPreview: "друг@example.com", subjectPreview: "Тема", sendAt: new Date(SUMMER_MS), status: "pending" }];
  },
  async countScheduledSends() { return 0; },
};
const server2 = new McpServer({ name: "test-queue", version: "0" });
registerGmailTools(server2, fakeClients, { store: queueStore, userToken: null });
const client2 = new Client({ name: "test-client-2", version: "0" });
const [c2, s2] = InMemoryTransport.createLinkedPair();
await Promise.all([server2.connect(s2), client2.connect(c2)]);
const queue = await client2.callTool({ name: "gmail_list_scheduled_sends", arguments: {} });
const row = (queue.structuredContent ?? JSON.parse(queue.content[0].text)).results[0];
check("sendAt в LA, а не в UTC", row.sendAt === "2026-08-07T16:16:37-07:00", row.sendAt);
check("не заканчивается на Z", !String(row.sendAt).endsWith("Z"), row.sendAt);
check("тот же момент времени", Date.parse(row.sendAt) === SUMMER_MS, row.sendAt);
check("совпадает с датой письма того же момента", row.sendAt === sSummer.date, [row.sendAt, sSummer.date]);

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
