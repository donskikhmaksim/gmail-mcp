#!/usr/bin/env node
/**
 * gmail_get_attachment — лимит, настоящие свойства файла, identity-guard.
 *
 * Три дефекта из приёмки 2026-08-07, все три покрыты здесь:
 *  Н-3 `maxBytes` игнорировался на текстовом пути: PNG в 102 993 байта,
 *      запрошенный с `mimeType:"text/plain"` и `maxBytes:1`, приходил целиком
 *      и с отчётом «1/1 успешно». Ветка `isTextual` стояла ДО проверки лимита,
 *      а сама «текстовость» бралась из аргумента вызова.
 *  Н-4 `filename`/`mimeType` в ответе были эхом аргументов: «ВЫДУМАННОЕ-ИМЯ.zip»
 *      возвращалось как есть, а без аргументов — `null`, хотя настоящие имя и
 *      тип сервер знает (он же отдаёт их в `gmail_get_message.attachments`).
 *  Н-5 `messageId` не сверялся с `attachmentId`: токен вложения из письма А,
 *      поданный с письмом Б (без вложений вовсе), возвращал содержимое и
 *      «1/1 успешно» — эхо подтверждало привязку, которой не было.
 *
 * Сеть не используется: Google-клиент — заглушка, которая считает вызовы.
 *
 * Usage: node scripts/test-attachment-identity.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

// --- фикстуры --------------------------------------------------------------

const PNG_BYTES = Buffer.alloc(102_993, 0x89); // «большая» картинка, как в приёмке
const LOG_BYTES = Buffer.from("строка лога\n".repeat(400), "utf8"); // настоящий text/*
const SMALL_PNG = Buffer.alloc(64, 0x89);

const ATTACHMENTS = {
  ATT_PNG: { data: PNG_BYTES, filename: "снимок.png", mimeType: "image/png" },
  ATT_LOG: { data: LOG_BYTES, filename: "server.log", mimeType: "text/plain" },
  ATT_SMALL: { data: SMALL_PNG, filename: "icon.png", mimeType: "image/png" },
};

const part = (attId) => ({
  filename: ATTACHMENTS[attId].filename,
  mimeType: ATTACHMENTS[attId].mimeType,
  body: { attachmentId: attId, size: ATTACHMENTS[attId].data.length },
});

const MESSAGES = {
  // Письмо с тремя вложениями.
  MSG_WITH: {
    id: "MSG_WITH",
    threadId: "T1",
    internalDate: "1754000000000",
    payload: { mimeType: "multipart/mixed", headers: [], parts: [part("ATT_PNG"), part("ATT_LOG"), part("ATT_SMALL")] },
  },
  // Письмо БЕЗ вложений вообще — цель подмены из Н-5.
  MSG_EMPTY: {
    id: "MSG_EMPTY",
    threadId: "T2",
    internalDate: "1754000000000",
    payload: { mimeType: "text/plain", headers: [], body: { data: "" } },
  },
};

let messageGetCalls = 0;
let attachmentGetCalls = 0;
let messageGetFails = false;

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
          get: async ({ id }) => {
            messageGetCalls++;
            if (messageGetFails) throw new Error("Backend error");
            if (!MESSAGES[id]) throw new Error(`Message not found: ${id}`);
            return { data: MESSAGES[id] };
          },
          attachments: {
            get: async ({ id }) => {
              attachmentGetCalls++;
              const a = ATTACHMENTS[id];
              if (!a) throw new Error(`Attachment not found: ${id}`);
              return { data: { data: a.data.toString("base64url"), size: a.data.length } };
            },
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
const reset = () => { messageGetCalls = 0; attachmentGetCalls = 0; };

// --- 1. Н-3: maxBytes держит и текстовый путь ------------------------------

console.log("\n[1] maxBytes работает НЕЗАВИСИМО от типа файла");
reset();
// Ровно сценарий приёмки: PNG выдаётся за text/plain и просится с maxBytes: 1.
const faked = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_WITH", attachmentId: "ATT_PNG", mimeType: "text/plain", filename: "ложь.txt", maxBytes: 1 }],
})).results[0];
check("отказ, а не тихая выдача", typeof faked.error === "string" && faked.error.length > 0, faked.error ?? null);
check("содержимое НЕ отдано текстом", faked.text === undefined, faked.text?.length);
check("содержимое НЕ отдано base64", faked.content === undefined, faked.content?.length);
check("в отказе назван реальный размер", String(faked.error).includes("102993"), faked.error);
check("байты даже не скачивались", attachmentGetCalls === 0, attachmentGetCalls);

reset();
// Честный текстовый файл — тоже под лимитом (раньше он вливался целиком).
const bigLog = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_WITH", attachmentId: "ATT_LOG", maxBytes: 100 }],
})).results[0];
check("настоящий text/plain сверх лимита — отказ", typeof bigLog.error === "string", bigLog.error ?? null);
check("текст не отдан", bigLog.text === undefined, bigLog.text?.length);

// --- 2. текстовый путь работает, когда влезает -----------------------------

console.log("\n[2] в пределах лимита содержимое отдаётся, кодировка — по РЕАЛЬНОМУ типу");
reset();
const okLog = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_WITH", attachmentId: "ATT_LOG", maxBytes: 1_000_000 }],
})).results[0];
check("text/plain → encoding text", okLog.encoding === "text", okLog.encoding);
check("текст пришёл целиком", okLog.text === LOG_BYTES.toString("utf8"), okLog.text?.length);
check("ошибки нет", okLog.error === undefined, okLog.error);
const okPng = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_WITH", attachmentId: "ATT_SMALL" }],
})).results[0];
check("image/png → encoding base64", okPng.encoding === "base64", okPng.encoding);
check("base64 совпадает с байтами", okPng.content === SMALL_PNG.toString("base64"), okPng.content?.length);

// --- 3. Н-4: имя и тип — из письма, а не из аргументов ---------------------

console.log("\n[3] filename/mimeType берутся из письма");
reset();
const named = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_WITH", attachmentId: "ATT_SMALL", filename: "ВЫДУМАННОЕ-ИМЯ.zip", mimeType: "application/octet-stream" }],
})).results[0];
check("выдуманное имя НЕ возвращается", named.filename !== "ВЫДУМАННОЕ-ИМЯ.zip", named.filename);
check("возвращается настоящее имя", named.filename === "icon.png", named.filename);
check("возвращается настоящий MIME", named.mimeType === "image/png", named.mimeType);
const unnamed = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_WITH", attachmentId: "ATT_LOG", maxBytes: 1_000_000 }],
})).results[0];
check("без аргументов имя не null, а настоящее", unnamed.filename === "server.log", unnamed.filename);
check("без аргументов тип не null, а настоящий", unnamed.mimeType === "text/plain", unnamed.mimeType);

// --- 4. Н-5: identity-guard ------------------------------------------------

console.log("\n[4] identity-guard: attachmentId обязан принадлежать messageId");
reset();
const stolen = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_EMPTY", attachmentId: "ATT_PNG", maxBytes: 8_000_000 }],
})).results[0];
check("жёсткий отказ (🛑)", String(stolen.error ?? "").includes("🛑"), stolen.error ?? null);
check("в отказе названы оба id", String(stolen.error).includes("ATT_PNG") && String(stolen.error).includes("MSG_EMPTY"), stolen.error);
check("содержимое НЕ отдано", stolen.text === undefined && stolen.content === undefined, [stolen.text?.length, stolen.content?.length]);
check("скачивания не было вовсе", attachmentGetCalls === 0, attachmentGetCalls);
check("эхо-подтверждения привязки нет (filename null)", stolen.filename === null, stolen.filename);

// --- 5. fail-closed: письмо не читается ------------------------------------

console.log("\n[5] fail-closed — не сверили с письмом, значит не скачиваем");
reset();
messageGetFails = true;
const blind = (await call("gmail_get_attachment", {
  items: [{ messageId: "MSG_WITH", attachmentId: "ATT_SMALL" }],
})).results[0];
messageGetFails = false;
check("отказ 🛑", String(blind.error ?? "").includes("🛑"), blind.error ?? null);
check("байты не скачаны", attachmentGetCalls === 0, attachmentGetCalls);

// --- 6. один запрос на письмо, не на вложение ------------------------------

console.log("\n[6] метаданные письма читаются один раз на батч");
reset();
const batch = await call("gmail_get_attachment", {
  items: [
    { messageId: "MSG_WITH", attachmentId: "ATT_SMALL" },
    { messageId: "MSG_WITH", attachmentId: "ATT_LOG", maxBytes: 1_000_000 },
  ],
});
check("оба элемента успешны", batch.results.every((r) => r.error === undefined), batch.results.map((r) => r.error ?? "ok"));
check("messages.get вызван 1 раз на 2 вложения", messageGetCalls === 1, messageGetCalls);
check("attachments.get вызван 2 раза", attachmentGetCalls === 2, attachmentGetCalls);
check("сводка считает успехи честно", batch.summary.includes("2/2"), batch.summary);

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
