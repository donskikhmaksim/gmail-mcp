#!/usr/bin/env node
/**
 * Happy-path coverage for the T1 auto-execute package (Максим, 2026-08-05:
 * «нажал кнопку — должно сразу исполниться на бэке») — extends
 * `test-auto-execute.mjs` (which only covers `tryAutoExecute`'s own
 * binding/one-shot/TTL guards against a hand-picked `gmail_send`-shaped
 * fake) with ONE check per newly-registered tool: `getAutoExecutor(tool)`
 * exists and its `execute()` actually calls the right Gmail/Drive API and
 * returns a non-empty human-readable report — the same text the model would
 * have seen from the normal (non-auto) tool call.
 *
 * `gmail_send` itself is NOT re-tested here — it's the already-shipped
 * reference implementation, unchanged by this package.
 *
 * Fully offline: fake Google clients (call-recording stubs) + a fake
 * Postgres-shaped store for snooze/schedule_send (injected via `ctx.store`,
 * same shape `AutoExecutorCtx.store` carries in production — see
 * `autoExecute.ts`'s `AutoExecutorPgStore`). No real network, no real DB.
 *
 * Usage: node scripts/test-auto-execute-t1.mjs (needs `npm run build` first
 * — imports the COMPILED dist/, same convention as test-gate-coverage.mjs).
 */
import { getAutoExecutor } from "../dist/autoExecute.js";
import { initDownloads } from "../dist/downloads.js";
// Side-effect import: registers every gmail_* auto-executor at module load.
import "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const HEADERS = [
  { name: "From", value: "sender@example.com" },
  { name: "To", value: "recipient@example.com" },
  { name: "Subject", value: "Test Subject" },
  { name: "Date", value: "Mon, 01 Jan 2024 00:00:00 +0000" },
  { name: "Message-ID", value: "<abc@example.com>" },
];
const RAW = Buffer.from(
  "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test Subject\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody text",
).toString("base64url");

/** Fresh fake GoogleClients (`g`) + call recorder, one per test so calls
 * from one tool never leak into another tool's assertions. Broad enough to
 * cover every mutation + post-verify read the 14 tools below touch. */
function makeFakeG() {
  const calls = {
    modify: [], trash: [], send: [], draftsCreate: [], draftsSend: [],
    labelsCreate: [], labelsPatch: [], labelsDelete: [], attachmentsGet: [],
    driveFilesCreate: [], threadsGet: [],
  };
  const g = {
    gmail: {
      users: {
        messages: {
          get: async ({ id }) => ({
            data: { id, threadId: "thread-1", labelIds: ["SENT"], payload: { headers: HEADERS }, raw: RAW },
          }),
          modify: async (args) => { calls.modify.push(args); return { data: {} }; },
          trash: async (args) => { calls.trash.push(args); return { data: {} }; },
          send: async (args) => { calls.send.push(args); return { data: { id: "msg-sent-1", threadId: "thread-1" } }; },
          attachments: {
            get: async (args) => {
              calls.attachmentsGet.push(args);
              return { data: { data: Buffer.from("hello attachment").toString("base64url") } };
            },
          },
        },
        drafts: {
          create: async (args) => { calls.draftsCreate.push(args); return { data: { id: "draft-1" } }; },
          send: async (args) => { calls.draftsSend.push(args); return { data: { id: "msg-sent-1" } }; },
          get: async () => ({ data: { message: { payload: { headers: HEADERS } } } }),
        },
        labels: {
          create: async (args) => { calls.labelsCreate.push(args); return { data: { id: "Label_1", name: args.requestBody.name } }; },
          patch: async (args) => { calls.labelsPatch.push(args); return { data: { id: args.id, name: args.requestBody.name ?? "Existing" } }; },
          delete: async (args) => { calls.labelsDelete.push(args); return { data: {} }; },
          get: async ({ id }) => ({ data: { id, name: "ExistingLabel" } }),
          list: async () => ({ data: { labels: [] } }),
        },
        threads: {
          get: async (args) => {
            calls.threadsGet.push(args);
            if (args.format === "minimal") return { data: { messages: [{ id: "m1" }] } };
            return { data: { messages: [{ payload: { headers: [{ name: "Subject", value: "Thread subject" }] } }] } };
          },
        },
      },
    },
    drive: {
      files: {
        create: async (args) => {
          calls.driveFilesCreate.push(args);
          return { data: { id: "file-1", name: args.requestBody?.name ?? "file", webViewLink: "https://drive.example/x" } };
        },
        get: async ({ fileId }) => ({ data: { id: fileId, name: "file", trashed: false } }),
        // ensureUploadFolder (gmail_create_upload_session) probes for an
        // existing staging folder first — no matches, so it falls through
        // to files.create above.
        list: async () => ({ data: { files: [] } }),
      },
    },
    accessToken: async () => "fake-access-token",
  };
  return { g, calls };
}

function makeConsentStore() {
  const outcomes = [];
  return {
    outcomes,
    createManifest: async () => {},
    getManifest: async () => null,
    consumeManifest: async () => null,
    invalidateManifest: async () => {},
    appendConsentAudit: async () => {},
    updateConsentAuditOutcome: async (auditId, outcome) => { outcomes.push({ auditId, ...outcome }); },
  };
}

function makeFakePgStore() {
  const snoozeCalls = [];
  const scheduledCalls = [];
  return {
    snoozeCalls,
    scheduledCalls,
    addSnooze: async (args) => { snoozeCalls.push(args); },
    addScheduledSend: async (args) => { scheduledCalls.push(args); return 42; },
  };
}

function makeCtx(g, extra = {}) {
  return {
    clients: { resolve: () => g, canonicalName: (a) => a ?? "work" },
    consentStore: makeConsentStore(),
    userToken: null,
    store: null,
    ...extra,
  };
}

async function runHappyPath(tool, payload, ctxOverrides, assertFn) {
  console.log(`\n[${tool}] happy path`);
  const executor = getAutoExecutor(tool);
  check("зарегистрирован в реестре (getAutoExecutor не undefined)", !!executor, `getAutoExecutor("${tool}") вернул undefined`);
  if (!executor) return;
  const { g, calls } = makeFakeG();
  const ctx = makeCtx(g, ctxOverrides);
  let text;
  let threw = null;
  try {
    text = await executor.execute(payload, "audit-" + tool, ctx);
  } catch (e) {
    threw = e;
  }
  check("execute() не упал", !threw, threw ? String(threw) : "");
  if (threw) return;
  check("вернул непустую строку (текст отчёта)", typeof text === "string" && text.length > 0, JSON.stringify(text));
  assertFn(calls, text, ctx);
}

// ---- gmail_reply ------------------------------------------------------------
await runHappyPath(
  "gmail_reply",
  {
    account: "work",
    replies: [{
      messageId: "orig-1", body: "reply body", replyAll: false,
      fromAddr: "recipient@example.com", resolvedTo: "recipient@example.com",
      subject: "Re: Test", messageIdHeader: "<abc@example.com>", references: "<abc@example.com>",
      threadId: "thread-1",
    }],
  },
  {},
  (calls, text) => {
    check("создан черновик (drafts.create)", calls.draftsCreate.length === 1);
    check("черновик отправлен (drafts.send)", calls.draftsSend.length === 1);
    check("текст упоминает 'Ответов отправлено'", text.includes("Ответов отправлено"), text);
  },
);

// ---- gmail_forward ----------------------------------------------------------
await runHappyPath(
  "gmail_forward",
  {
    account: "work",
    items: [{ messageId: "orig-1", to: "recipient@example.com", subject: "Fwd: Test", origFrom: "sender@example.com", origSubject: "Test" }],
  },
  {},
  (calls, text) => {
    check("письмо отправлено (messages.send)", calls.send.length === 1);
    check("текст упоминает 'Переслано'", text.includes("Переслано"), text);
  },
);

// ---- gmail_create_draft -------------------------------------------------------
await runHappyPath(
  "gmail_create_draft",
  { account: "work", drafts: [{ to: "recipient@example.com", subject: "Draft subj", body: "draft body" }] },
  {},
  (calls, text) => {
    check("черновик создан (drafts.create)", calls.draftsCreate.length === 1);
    check("текст упоминает 'Created'", text.includes("Created"), text);
  },
);

// ---- gmail_archive ------------------------------------------------------------
await runHappyPath(
  "gmail_archive",
  { account: "work", items: [{ id: "m1", subject: "Subj", from: "sender@example.com", labelIds: ["INBOX"] }] },
  {},
  (calls, text) => {
    check("messages.modify вызван с removeLabelIds INBOX", calls.modify.length === 1 && calls.modify[0].requestBody.removeLabelIds.includes("INBOX"));
    check("текст упоминает 'Archived'", text.includes("Archived"), text);
  },
);

// ---- gmail_trash --------------------------------------------------------------
await runHappyPath(
  "gmail_trash",
  { account: "work", items: [{ id: "m1", subject: "Subj", from: "sender@example.com", labelIds: ["INBOX"] }] },
  {},
  (calls, text) => {
    check("messages.trash вызван", calls.trash.length === 1);
    check("текст упоминает 'Trashed'", text.includes("Trashed"), text);
  },
);

// ---- gmail_modify_labels --------------------------------------------------------
await runHappyPath(
  "gmail_modify_labels",
  { account: "work", items: [{ messageId: "m1", subject: "Subj", from: "sender@example.com", addLabelIds: ["STARRED"], removeLabelIds: ["UNREAD"] }] },
  {},
  (calls, text) => {
    check("messages.modify вызван с addLabelIds/removeLabelIds", calls.modify.length === 1 && calls.modify[0].requestBody.addLabelIds.includes("STARRED"));
    check("текст упоминает 'Modified'", text.includes("Modified"), text);
  },
);

// ---- gmail_snooze (needs a fake PgStore + userToken threading) ----------------
{
  const fakeStore = makeFakePgStore();
  await runHappyPath(
    "gmail_snooze",
    { account: "work", items: [{ id: "m1", subject: "Subj", from: "sender@example.com", labelIds: ["INBOX"], unsnoozeAt: new Date(Date.now() + 3_600_000).toISOString() }] },
    { store: fakeStore, userToken: "user-token-123" },
    (calls, text) => {
      check("messages.modify (снятие INBOX) вызван", calls.modify.length === 1);
      check("addSnooze вызван РОВНО один раз (персистентность через ctx.store)", fakeStore.snoozeCalls.length === 1);
      check("userToken из ctx дошёл до addSnooze (не потерян)", fakeStore.snoozeCalls[0]?.userToken === "user-token-123");
      check("accountName корректен", fakeStore.snoozeCalls[0]?.accountName === "work");
      check("текст упоминает 'Snoozed'", text.includes("Snoozed"), text);
    },
  );
}

// ---- gmail_schedule_send (needs a fake PgStore + userToken threading) --------
{
  const fakeStore = makeFakePgStore();
  await runHappyPath(
    "gmail_schedule_send",
    { account: "work", messages: [{ to: "recipient@example.com", subject: "Sched", body: "body", sendAt: new Date(Date.now() + 3_600_000).toISOString() }] },
    { store: fakeStore, userToken: "user-token-456" },
    (calls, text) => {
      check("addScheduledSend вызван ровно один раз", fakeStore.scheduledCalls.length === 1);
      check("userToken из ctx дошёл до addScheduledSend", fakeStore.scheduledCalls[0]?.userToken === "user-token-456");
      check("текст упоминает 'Scheduled'", text.includes("Scheduled"), text);
    },
  );
  console.log("\n[gmail_schedule_send] ctx.store === null → честный отказ, не тихая потеря очереди");
  const executor = getAutoExecutor("gmail_schedule_send");
  const { g } = makeFakeG();
  let threw = null;
  try {
    await executor.execute(
      { account: "work", messages: [{ to: "x@example.com", subject: "s", body: "b", sendAt: new Date(Date.now() + 3_600_000).toISOString() }] },
      "audit-x",
      makeCtx(g, { store: null }),
    );
  } catch (e) {
    threw = e;
  }
  check("бросает (не молча теряет очередь) когда store недоступен", threw !== null, "execute() не бросил при store=null");
}

// ---- gmail_save_attachment_to_drive -------------------------------------------
await runHappyPath(
  "gmail_save_attachment_to_drive",
  { account: "work", items: [{ messageId: "m1", attachmentId: "att1", filename: "file.pdf", size: 123 }] },
  {},
  (calls, text) => {
    check("attachments.get вызван", calls.attachmentsGet.length === 1);
    check("drive.files.create вызван", calls.driveFilesCreate.length === 1);
    check("текст упоминает 'Saved'", text.includes("Saved"), text);
  },
);

// ---- gmail_create_label -----------------------------------------------------
await runHappyPath(
  "gmail_create_label",
  { account: "work", labels: [{ name: "NewLabel" }] },
  {},
  (calls, text) => {
    check("labels.create вызван с правильным именем", calls.labelsCreate.length === 1 && calls.labelsCreate[0].requestBody.name === "NewLabel");
    check("текст упоминает 'Created'", text.includes("Created"), text);
  },
);

// ---- gmail_update_label -------------------------------------------------------
await runHappyPath(
  "gmail_update_label",
  { account: "work", items: [{ labelId: "Label_1", currentName: "Old", name: "New" }] },
  {},
  (calls, text) => {
    check("labels.patch вызван", calls.labelsPatch.length === 1 && calls.labelsPatch[0].requestBody.name === "New");
    check("текст упоминает 'Updated'", text.includes("Updated"), text);
  },
);

// ---- gmail_delete_label -------------------------------------------------------
await runHappyPath(
  "gmail_delete_label",
  { account: "work", labels: [{ id: "Label_1", name: "ToDelete", messageCount: 0 }] },
  {},
  (calls, text) => {
    check("labels.delete вызван", calls.labelsDelete.length === 1 && calls.labelsDelete[0].id === "Label_1");
    check("текст упоминает 'Deleted'", text.includes("Deleted"), text);
  },
);

// ---- gmail_export_thread_eml --------------------------------------------------
await runHappyPath(
  "gmail_export_thread_eml",
  { account: "work", threadId: "thread-1", subject: "Thread subject", messageCount: 1, format: "eml_files", scope: "all" },
  {},
  (calls, text) => {
    check("threads.get вызван (минимум format=minimal)", calls.threadsGet.some((c) => c.format === "minimal"));
    check("файл экспорта создан в Drive", calls.driveFilesCreate.length === 1);
    check("текст упоминает 'Exported'", text.includes("Exported"), text);
  },
);

// ---- gmail_create_upload_session (needs a fetch stub) -------------------------
//
// Транспорт ИНЖЕКТИРУЕТСЯ через `ctx.safeFetch`, а не подменой
// `globalThis.fetch`: исходящие запросы к Google идут через
// `safeGoogleFetch` (undici's own fetch + Agent, см. src/safeFetch.ts), и
// подмена глобала их бы не перехватила. Заодно это проверяет, что адрес
// сессии, пришедший от Google, проходит проверку и запоминается сервером —
// наружу уходит непрозрачный sessionId, а не адрес.
{
  const fetchCalls = [];
  const safeFetch = {
    lookup: async () => [{ address: "142.250.72.14" }],
    fetchImpl: async (url, opts) => {
      fetchCalls.push({ url, opts });
      return {
        ok: true,
        status: 200,
        headers: {
          get: (name) =>
            name.toLowerCase() === "location"
              ? "https://www.googleapis.com/upload/drive/v3/files/FILE1?upload_id=session-1"
              : null,
        },
        text: async () => "",
      };
    },
  };
  {
    await runHappyPath(
      "gmail_create_upload_session",
      { account: "work", files: [{ name: "file.pdf" }] },
      { safeFetch },
      (calls, text) => {
        // ensureUploadFolder's own files.create (staging folder, since
        // files.list found none) PLUS the placeholder file's files.create —
        // two calls total, not one.
        check(
          "drive.files.create вызван для папки и для плейсхолдера (2 раза)",
          calls.driveFilesCreate.length === 2,
          `calls=${calls.driveFilesCreate.length}`,
        );
        check(
          "плейсхолдер отмечен appProperties.gmailMcpUpload",
          calls.driveFilesCreate.some((c) => c.requestBody?.appProperties?.gmailMcpUpload === "1"),
        );
        check("resumable-сессия запрошена у Google (fetch)", fetchCalls.length === 1);
        check(
          "запрос ушёл на googleapis.com, а не куда попало",
          /^https:\/\/www\.googleapis\.com\//.test(String(fetchCalls[0]?.url)),
          String(fetchCalls[0]?.url),
        );
        check("текст упоминает 'Opened'", text.includes("Opened"), text);
        check(
          "наружу отдан непрозрачный sessionId, а не адрес",
          /"sessionId":\s*"[A-Za-z0-9_-]{20,}"/.test(text) && !/"sessionId":\s*"[^"]*:\/\//.test(text),
          text.slice(0, 300),
        );
      },
    );
  }
}

// ---- gmail_get_download_url --------------------------------------------------
//
// Тул гейтован (ссылка САМА является доступом), поэтому у него обязан быть
// исполнитель: человек жмёт «✅ Подтвердить» в Telegram — поллер исполняет
// именно этот код, и ссылка должна реально появиться.
{
  initDownloads("https://mail.example.test");
  await runHappyPath(
    "gmail_get_download_url",
    {
      account: "work",
      ttlMinutes: 30,
      items: [{ messageId: "msg-1", attachmentId: "att-1", filename: "f.pdf", mimeType: "application/pdf" }],
    },
    {},
    (calls, text) => {
      const m = text.match(/https:\/\/mail\.example\.test\/dl\/([A-Za-z0-9_-]{20,})/);
      check("ссылка выдана", !!m, text.slice(0, 300));
      check("текст упоминает выдачу ссылок", text.includes("Выдано ссылок:"), text.slice(0, 120));
      check(
        "в отчёте прямо сказано, что отозвать ссылку нельзя",
        /отозвать её нельзя|Отозвать её нельзя/.test(text),
        text.slice(0, 400),
      );
    },
  );
  // Независимо от текста отчёта: токен реально лежит в хранилище ссылок и
  // ведёт к тому же вложению (то же, что проверяет post-verify инструмента).
}

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
