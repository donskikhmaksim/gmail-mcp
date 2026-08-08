#!/usr/bin/env node
/**
 * Язык вывода выбран, а не «сложился»: сводка (`summary`) любого инструмента —
 * по-русски (mcp-development-standard/references/output-format.md §7.4).
 *
 * Зачем детектор, а не просто перевод восьми строк: приёмка 2026-08-07
 * показала, что остаток считался закрытым «тремя строками», а по факту
 * английский `summary` отдавали ВОСЕМЬ читающих инструментов из девяти —
 * и при этом тексты ОШИБОК у тех же инструментов были русские. То есть
 * перевод без детектора чинит сегодняшний список и молча пропускает
 * следующий добавленный инструмент. Поэтому здесь две части:
 *
 *  [A] статическая — сканирует ИСХОДНИКИ и ловит английскую сводку у ЛЮБОГО
 *      инструмента, включая ещё не написанные;
 *  [B] динамическая — реально зовёт читающие инструменты и смотрит на текст,
 *      который получит пользователь.
 *
 * Usage: node scripts/test-ru-summary.mjs
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";
import { registerAccountTools } from "../dist/accounts.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

/**
 * Латиница, допустимая в русском тексте: имена собственные и технические
 * идентификаторы, которые по-русски не пишутся. Всё остальное — английский
 * текст, и это дефект. Список намеренно короткий: расширять его — осознанное
 * решение, а не способ протащить английскую фразу.
 */
const ALLOWED = new Set([
  "gmail", "google", "drive", "docs", "mcp", "pt", "utc", "iso", "url",
  "database_url", "id", "ids", "base64", "eml", "mbox", "ocr", "pdf", "csv",
  "json", "xml", "html", "png", "api",
]);

/** Все латинские слова длиной ≥2, кроме разрешённых. */
function englishWords(text) {
  return (text.match(/[A-Za-z_]{2,}/g) ?? []).filter((w) => !ALLOWED.has(w.toLowerCase()));
}

/** Вырезает `${…}` (с учётом вложенных скобок) — внутри живёт код, не текст. */
function stripInterpolations(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "$" && s[i + 1] === "{") {
      let depth = 1;
      i += 2;
      while (i < s.length && depth > 0) {
        if (s[i] === "{") depth++;
        else if (s[i] === "}") depth--;
        i++;
      }
      i--;
      continue;
    }
    out += s[i];
  }
  return out;
}

/** Все литералы, стоящие после `summary:` в исходниках. */
function summaryLiterals(src, file) {
  const out = [];
  const re = /summary:\s*(`(?:[^`\\]|\\.)*`|"(?:[^"\\]|\\.)*")/g;
  let m;
  while ((m = re.exec(src))) {
    const literal = m[1].slice(1, -1);
    out.push({ file, literal, line: src.slice(0, m.index).split("\n").length });
  }
  return out;
}

function tsFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...tsFiles(p));
    else if (name.endsWith(".ts")) out.push(p);
  }
  return out;
}

// --- [A] статическая часть: сводка любого инструмента ----------------------

console.log("\n[A] исходники: ни одной английской сводки");
const literals = tsFiles(join(ROOT, "src")).flatMap((f) => summaryLiterals(readFileSync(f, "utf8"), f.slice(ROOT.length + 1)));
check("сводки вообще найдены (скан не пустой)", literals.length >= 8, literals.length);
const offenders = literals
  .map((l) => ({ ...l, bad: englishWords(stripInterpolations(l.literal)) }))
  .filter((l) => l.bad.length > 0);
for (const o of offenders) console.log(`       ${o.file}:${o.line} → ${o.bad.join(", ")}  |  ${o.literal.slice(0, 90)}`);
check("английских слов в сводках нет", offenders.length === 0, offenders.map((o) => `${o.file}:${o.line}`));

// Детектор обязан РАБОТАТЬ, а не просто молчать: проверяем его на образцах.
console.log("\n[A2] сам детектор ловит английский и не ругается на русский");
check("ловит «Fetched 2/3 message(s)»", englishWords("📧 Fetched 2/3 message(s)").length > 0);
check("ловит «has next page»", englishWords("🔍 Поиск — 5 писем (has next page)").length > 0);
check("пропускает чистый русский", englishWords("📧 Получено 2/3 письма (ошибок: 1)").length === 0);
check("пропускает имя продукта Gmail", englishWords("🔍 Поиск Gmail — 5 писем").length === 0);
check("вырезает подстановки", stripInterpolations('${plural(n, "one", "few", "many")} писем') === " писем", stripInterpolations('${plural(n, "one", "few", "many")} писем'));

// --- [B] динамическая часть: что реально увидит пользователь ---------------

console.log("\n[B] живые вызовы читающих инструментов");

const MESSAGE = {
  id: "M1",
  threadId: "T1",
  internalDate: "1754600197000",
  snippet: "фрагмент",
  labelIds: ["INBOX"],
  payload: {
    mimeType: "multipart/mixed",
    headers: [
      { name: "From", value: "Отправитель <sender@example.com>" },
      { name: "To", value: "me@personal.test" },
      { name: "Subject", value: "Тема письма" },
      { name: "Date", value: "Fri, 7 Aug 2026 16:16:37 -0700" },
    ],
    parts: [
      { filename: "файл.txt", mimeType: "text/plain", body: { attachmentId: "A1", size: 6 } },
    ],
  },
};

const scheduled = [
  { id: "S1", toPreview: "друг@example.com", subjectPreview: "Тема", sendAt: new Date(1_754_600_197_000), status: "pending" },
];
const fakeStore = {
  async listScheduledSends() { return scheduled; },
  async countScheduledSends() { return 0; },
};

const fakeClients = {
  names: ["personal", "work"],
  defaultName: "personal",
  multi: true,
  canonicalName: (n) => (n && n.trim() ? n.trim() : "personal"),
  emailFor: () => "me@personal.test",
  resolve: () => ({
    gmail: {
      users: {
        messages: {
          list: async () => ({ data: { messages: [{ id: "M1" }], resultSizeEstimate: 1 } }),
          get: async () => ({ data: MESSAGE }),
          attachments: { get: async () => ({ data: { data: Buffer.from("привет", "utf8").toString("base64url") } }) },
        },
        threads: { get: async () => ({ data: { id: "T1", messages: [MESSAGE] } }) },
        labels: { list: async () => ({ data: { labels: [{ id: "INBOX", name: "Входящие", type: "system" }, { id: "L1", name: "Счета", type: "user" }] } }) },
      },
    },
    drive: {},
    docs: {},
    accessToken: async () => "ya29.FAKE",
  }),
  baseGmailQuery: () => "",
};

const server = new McpServer({ name: "test", version: "0" });
registerAccountTools(server, fakeClients);
registerGmailTools(server, fakeClients, { store: fakeStore, userToken: null });
const client = new Client({ name: "test-client", version: "0" });
const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(serverSide), client.connect(clientSide)]);

const cases = [
  ["list_accounts", {}],
  ["gmail_search", { query: "", maxResults: 1 }],
  ["gmail_count", { query: "" }],
  ["gmail_get_message", { messageIds: ["M1"] }],
  ["gmail_get_thread", { threadIds: ["T1"] }],
  ["gmail_get_attachment", { items: [{ messageId: "M1", attachmentId: "A1" }] }],
  ["gmail_list_labels", {}],
  ["gmail_list_scheduled_sends", {}],
];

/**
 * Оставляет только СОБСТВЕННЫЙ текст сервера: выкидывает подставленные данные
 * и технические идентификаторы. Иначе тест ругался бы на латиницу, которую
 * сервер не писал, а получил, — метку аккаунта («personal»), значение
 * enum-статуса («pending»), поисковый запрос («is:unread»), имя параметра в
 * бэктиках (`account`).
 */
const serverPhrases = (s) =>
  String(s)
    .replace(/`[^`]*`/g, " ")   // `account` — имя параметра
    .replace(/«[^»]*»/g, " ")   // «pending», «is:unread» — данные вызова
    .replace(/"[^"]*"/g, " ")
    .replace(/^-\s.*$/gm, " "); // список меток аккаунтов в list_accounts

for (const [name, args] of cases) {
  const r = await client.callTool({ name, arguments: args });
  const text = r.content[0].text;
  let summary;
  try {
    summary = (r.structuredContent ?? JSON.parse(text)).summary ?? text;
  } catch {
    summary = text; // list_accounts отдаёт готовый текст, не JSON
  }
  const bad = englishWords(serverPhrases(summary));
  check(`${name}: сводка по-русски`, bad.length === 0, { summary, bad });
  check(`${name}: сводка непустая`, String(summary).trim().length > 0, summary);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
