/**
 * Gmail tools: read / analyse / send / reply / archive / trash / labels.
 * Array-first: every item-based tool accepts arrays; batch_ duplicates removed.
 */
import { z } from "zod";
import { Readable } from "node:stream";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { gmail_v1 } from "googleapis";
import { ok, fail, guard, isTextual } from "../util.js";
import { accountField, type UserClients } from "../accounts.js";
import type { GoogleClients } from "../google.js";
import { documentToPlainText } from "./docs.js";
import type { PgStore } from "../store.js";

const GOOGLE_DOC_MIME = "application/vnd.google-apps.document";

/** Lists attachment parts (filename + id + size) in a message payload. */
function collectAttachments(
  payload?: gmail_v1.Schema$MessagePart,
): { filename: string; mimeType: string; size: number; attachmentId: string }[] {
  const out: { filename: string; mimeType: string; size: number; attachmentId: string }[] = [];
  const walk = (part?: gmail_v1.Schema$MessagePart) => {
    if (!part) return;
    if (part.filename && part.body?.attachmentId) {
      out.push({
        filename: part.filename,
        mimeType: part.mimeType ?? "application/octet-stream",
        size: part.body.size ?? 0,
        attachmentId: part.body.attachmentId,
      });
    }
    for (const sub of part.parts ?? []) walk(sub);
  };
  walk(payload);
  return out;
}

// ---- helpers ---------------------------------------------------------------

function header(headers: gmail_v1.Schema$MessagePartHeader[] | undefined, name: string): string {
  const h = (headers ?? []).find((x) => (x.name ?? "").toLowerCase() === name.toLowerCase());
  return h?.value ?? "";
}

function decodeB64(data?: string | null): string {
  if (!data) return "";
  return Buffer.from(data, "base64url").toString("utf8");
}

/** Walks the MIME tree and returns the best-effort plain-text body. */
function extractBody(payload?: gmail_v1.Schema$MessagePart): string {
  if (!payload) return "";
  const walk = (part: gmail_v1.Schema$MessagePart, preferHtml: boolean): string | null => {
    const mime = part.mimeType ?? "";
    if (mime === "text/plain" && !preferHtml && part.body?.data) return decodeB64(part.body.data);
    if (mime === "text/html" && preferHtml && part.body?.data) {
      return decodeB64(part.body.data)
        .replace(/<style[\s\S]*?<\/style>/gi, "")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/g, " ")
        .replace(/\s+\n/g, "\n")
        .trim();
    }
    for (const sub of part.parts ?? []) {
      const r = walk(sub, preferHtml);
      if (r) return r;
    }
    return null;
  };
  return (
    walk(payload, false) ??
    walk(payload, true) ??
    decodeB64(payload.body?.data) ??
    ""
  );
}

function summarise(msg: gmail_v1.Schema$Message) {
  const h = msg.payload?.headers;
  return {
    id: msg.id,
    threadId: msg.threadId,
    from: header(h, "From"),
    to: header(h, "To"),
    subject: header(h, "Subject"),
    date: header(h, "Date"),
    snippet: msg.snippet ?? "",
    labelIds: msg.labelIds ?? [],
  };
}

/** RFC 2822 + base64url encoding for sending. Exported for testing. */
export interface MailAttachment {
  filename: string;
  mimeType: string;
  /** base64 (standard, not url-safe) of the file bytes. */
  base64: string;
}

export function buildRawEmail(opts: {
  to: string;
  subject: string;
  body: string;
  cc?: string;
  bcc?: string;
  from?: string;
  inReplyTo?: string;
  references?: string;
  attachments?: MailAttachment[];
}): string {
  const encodeHeader = (v: string) =>
    // eslint-disable-next-line no-control-regex
    /[^\x00-\x7F]/.test(v) ? `=?UTF-8?B?${Buffer.from(v, "utf8").toString("base64")}?=` : v;

  const headerLines = [
    opts.from ? `From: ${opts.from}` : null,
    `To: ${opts.to}`,
    opts.cc ? `Cc: ${opts.cc}` : null,
    opts.bcc ? `Bcc: ${opts.bcc}` : null,
    `Date: ${new Date().toUTCString()}`,
    `Subject: ${encodeHeader(opts.subject)}`,
    opts.inReplyTo ? `In-Reply-To: ${opts.inReplyTo}` : null,
    opts.references ? `References: ${opts.references}` : null,
    "MIME-Version: 1.0",
  ].filter(Boolean) as string[];

  const bodyB64 = Buffer.from(opts.body, "utf8").toString("base64");

  let mime: string;
  if (opts.attachments && opts.attachments.length) {
    const boundary = "=_gmcp_" + Buffer.from(opts.subject + opts.attachments.length).toString("hex").slice(0, 16);
    const parts: string[] = [];
    parts.push(
      `--${boundary}`,
      'Content-Type: text/plain; charset="UTF-8"',
      "Content-Transfer-Encoding: base64",
      "",
      bodyB64,
    );
    for (const att of opts.attachments) {
      const wrapped = att.base64.replace(/(.{76})/g, "$1\r\n");
      parts.push(
        `--${boundary}`,
        `Content-Type: ${att.mimeType}; name="${att.filename}"`,
        "Content-Transfer-Encoding: base64",
        `Content-Disposition: attachment; filename="${att.filename}"`,
        "",
        wrapped,
      );
    }
    parts.push(`--${boundary}--`);
    mime =
      headerLines.join("\r\n") +
      "\r\n" +
      `Content-Type: multipart/mixed; boundary="${boundary}"` +
      "\r\n\r\n" +
      parts.join("\r\n");
  } else {
    mime =
      headerLines.join("\r\n") +
      "\r\n" +
      'Content-Type: text/plain; charset="UTF-8"' +
      "\r\n" +
      "Content-Transfer-Encoding: base64" +
      "\r\n\r\n" +
      bodyB64;
  }
  return Buffer.from(mime, "utf8").toString("base64url");
}

export interface AttachmentInput {
  driveFileId?: string;
  contentBase64?: string;
  filename?: string;
  mimeType?: string;
}

/** Resolves attachment inputs (Drive file ids or inline base64) into mail attachments. */
async function resolveAttachments(
  g: GoogleClients,
  items: AttachmentInput[],
): Promise<MailAttachment[]> {
  const out: MailAttachment[] = [];
  for (const item of items) {
    if (item.driveFileId) {
      const meta = await g.drive.files.get({ fileId: item.driveFileId, fields: "name,mimeType" });
      const srcMime = meta.data.mimeType ?? "application/octet-stream";
      let filename = item.filename ?? meta.data.name ?? "attachment";
      let mimeType = item.mimeType ?? srcMime;
      let buf: Buffer;
      if (srcMime.startsWith("application/vnd.google-apps.")) {
        mimeType = item.mimeType ?? "application/pdf";
        const r = await g.drive.files.export(
          { fileId: item.driveFileId, mimeType },
          { responseType: "arraybuffer" },
        );
        buf = Buffer.from(r.data as ArrayBuffer);
        if (!item.filename && !/\.[a-z0-9]+$/i.test(filename)) filename += ".pdf";
      } else {
        const r = await g.drive.files.get(
          { fileId: item.driveFileId, alt: "media" },
          { responseType: "arraybuffer" },
        );
        buf = Buffer.from(r.data as ArrayBuffer);
      }
      out.push({ filename, mimeType, base64: buf.toString("base64") });
    } else if (item.contentBase64) {
      out.push({
        filename: item.filename ?? "attachment",
        mimeType: item.mimeType ?? "application/octet-stream",
        base64: item.contentBase64,
      });
    } else {
      throw new Error("Each attachment needs either driveFileId or contentBase64.");
    }
  }
  return out;
}

// ---- tools -----------------------------------------------------------------

export interface GmailSnoozeContext {
  store: PgStore | null;
  userToken: string | null;
}

export function registerGmailTools(
  server: McpServer,
  clients: UserClients,
  snoozeCtx: GmailSnoozeContext = { store: null, userToken: null },
) {
  const account = accountField(clients);

  const attachmentsField = z
    .array(
      z.object({
        driveFileId: z.string().optional().describe("Attach this Google Drive file."),
        contentBase64: z.string().optional().describe("Inline file bytes as base64."),
        filename: z.string().optional(),
        mimeType: z.string().optional(),
      }),
    )
    .optional()
    .describe(
      "Files to attach. Each item is either {driveFileId} (a Drive file, Google Docs/Sheets export to PDF) " +
        "or {filename, contentBase64, mimeType} (inline).",
    );

  // ---- gmail_search (unchanged) --------------------------------------------

  server.registerTool(
    "gmail_search",
    {
      title: "Search emails",
      description:
        "Search the mailbox with Gmail query syntax (e.g. \"from:bob@x.com is:unread newer_than:7d has:attachment\"). " +
        "Returns matching messages with sender, subject, date and snippet (no full body). " +
        "Supports pagination: pass back the returned `nextPageToken` to get the next page.",
      inputSchema: {
        account,
        query: z
          .string()
          .default("")
          .describe('Gmail search query. Empty = most recent. e.g. "is:unread", "from:..."'),
        maxResults: z.number().int().min(1).max(100).default(10).optional(),
        pageToken: z
          .string()
          .optional()
          .describe("Page token from a previous call's `nextPageToken` to fetch the next page."),
      },
    },
    guard(async ({ account, query, maxResults, pageToken }) => {
      const g = clients.resolve(account);
      const base = clients.baseGmailQuery(account);
      const q = [base, query].map((s) => (s ?? "").trim()).filter(Boolean).join(" ");
      const list = await g.gmail.users.messages.list({
        userId: "me",
        q: q || undefined,
        maxResults: maxResults ?? 10,
        pageToken,
      });
      const ids = (list.data.messages ?? []).map((m) => m.id!).filter(Boolean);
      const messages = await Promise.all(
        ids.map((id) =>
          g.gmail.users.messages.get({
            userId: "me",
            id,
            format: "metadata",
            metadataHeaders: ["From", "To", "Subject", "Date"],
          }),
        ),
      );
      const msgs = messages.map((r) => summarise(r.data));
      return ok({
        summary: `🔍 Gmail search "${q || "(all)"}" — ${msgs.length} message(s)${list.data.nextPageToken ? " (has next page)" : ""}`,
        resultSizeEstimate: list.data.resultSizeEstimate ?? ids.length,
        nextPageToken: list.data.nextPageToken ?? null,
        messages: msgs,
      });
    }),
  );

  // ---- gmail_count (unchanged) ---------------------------------------------

  server.registerTool(
    "gmail_count",
    {
      title: "Count messages or threads",
      description:
        "Exact count of MESSAGES or THREADS matching a Gmail query, by paginating through ids " +
        '(no per-message fetch). Examples: query "is:starred", "is:unread", "label:Требует ответа". ' +
        "Use unit=threads to count conversations rather than individual messages.",
      inputSchema: {
        account,
        query: z.string().default("").describe('Gmail query, e.g. "is:starred", "is:unread".'),
        unit: z.enum(["messages", "threads"]).default("messages").optional(),
      },
    },
    guard(async ({ account, query, unit }) => {
      const g = clients.resolve(account);
      const base = clients.baseGmailQuery(account);
      const q = [base, query].map((s) => (s ?? "").trim()).filter(Boolean).join(" ");
      const countThreads = unit === "threads";
      const MAX_PAGES = 200;
      let count = 0;
      let pageToken: string | undefined;
      let pages = 0;
      do {
        if (countThreads) {
          const r = await g.gmail.users.threads.list({
            userId: "me",
            q: q || undefined,
            maxResults: 500,
            pageToken,
          });
          count += (r.data.threads ?? []).length;
          pageToken = r.data.nextPageToken ?? undefined;
        } else {
          const r = await g.gmail.users.messages.list({
            userId: "me",
            q: q || undefined,
            maxResults: 500,
            pageToken,
          });
          count += (r.data.messages ?? []).length;
          pageToken = r.data.nextPageToken ?? undefined;
        }
        pages++;
      } while (pageToken && pages < MAX_PAGES);
      return ok({
        summary: `📊 ${count}${!!pageToken ? "+" : ""} ${countThreads ? "thread(s)" : "message(s)"} for query "${q || "(all mail)"}"`,
        unit: countThreads ? "threads" : "messages",
        query: q || "(all mail)",
        count,
        capped: !!pageToken,
      });
    }),
  );

  // ---- gmail_get_message (array) -------------------------------------------

  server.registerTool(
    "gmail_get_message",
    {
      title: "Read emails",
      description: "Get one or more emails fully: headers plus the decoded plain-text body.",
      inputSchema: {
        account,
        messageIds: z.array(z.string()).min(1).describe("Message id(s) to fetch."),
      },
    },
    guard(async ({ account, messageIds }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        messageIds.map(async (id) => {
          try {
            const res = await g.gmail.users.messages.get({ userId: "me", id, format: "full" });
            const s = summarise(res.data);
            const body = extractBody(res.data.payload);
            const attachments = collectAttachments(res.data.payload);
            return { ...s, body, attachments };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      const err_ = results.filter((r) => "error" in r);
      return ok({
        summary: `📧 Fetched ${ok_.length}/${messageIds.length} message(s)${err_.length ? ` (${err_.length} error(s))` : ""}`,
        results,
      });
    }),
  );

  // ---- gmail_get_thread (array) --------------------------------------------

  server.registerTool(
    "gmail_get_thread",
    {
      title: "Read threads",
      description: "Get every message in one or more conversation threads (decoded).",
      inputSchema: {
        account,
        threadIds: z.array(z.string()).min(1).describe("Thread id(s) to fetch."),
      },
    },
    guard(async ({ account, threadIds }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        threadIds.map(async (threadId) => {
          try {
            const res = await g.gmail.users.threads.get({ userId: "me", id: threadId, format: "full" });
            const messages = (res.data.messages ?? []).map((m) => ({
              ...summarise(m),
              body: extractBody(m.payload),
              attachments: collectAttachments(m.payload),
            }));
            return { id: threadId, messages };
          } catch (e) {
            return { id: threadId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📧 Fetched ${ok_.length}/${threadIds.length} thread(s)`,
        results,
      });
    }),
  );

  // ---- gmail_send (array) --------------------------------------------------

  server.registerTool(
    "gmail_send",
    {
      title: "Send emails",
      description: "Send one or more new emails (optionally with attachments). `to`/`cc`/`bcc` may be comma-separated lists.",
      inputSchema: {
        account,
        messages: z
          .array(
            z.object({
              to: z.string().describe("Recipient(s), comma-separated."),
              subject: z.string(),
              body: z.string(),
              cc: z.string().optional(),
              bcc: z.string().optional(),
              attachments: attachmentsField,
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, messages }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        messages.map(async (msg) => {
          try {
            const atts = msg.attachments?.length ? await resolveAttachments(g, msg.attachments) : undefined;
            const raw = buildRawEmail({ to: msg.to, subject: msg.subject, body: msg.body, cc: msg.cc, bcc: msg.bcc, attachments: atts });
            const res = await g.gmail.users.messages.send({ userId: "me", requestBody: { raw } });
            return { messageId: res.data.id, threadId: res.data.threadId };
          } catch (e) {
            return { error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `✉️ Sent ${ok_.length}/${messages.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_reply (array) -------------------------------------------------

  server.registerTool(
    "gmail_reply",
    {
      title: "Reply to emails",
      description: "Reply within the same thread of one or more existing messages.",
      inputSchema: {
        account,
        replies: z
          .array(
            z.object({
              messageId: z.string().describe("Id of the message being replied to."),
              body: z.string(),
              replyAll: z.boolean().default(false).optional().describe("Also reply to Cc recipients."),
              attachments: attachmentsField,
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, replies }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        replies.map(async (item) => {
          try {
            const orig = await g.gmail.users.messages.get({
              userId: "me",
              id: item.messageId,
              format: "metadata",
              metadataHeaders: ["From", "To", "Cc", "Subject", "Message-ID", "References"],
            });
            const h = orig.data.payload?.headers;
            const fromAddr = header(h, "From");
            const messageIdHeader = header(h, "Message-ID");
            const references = [header(h, "References"), messageIdHeader].filter(Boolean).join(" ");
            let subject = header(h, "Subject");
            if (!/^re:/i.test(subject)) subject = "Re: " + subject;
            const cc = item.replyAll ? header(h, "Cc") || undefined : undefined;
            const atts = item.attachments?.length ? await resolveAttachments(g, item.attachments) : undefined;
            const raw = buildRawEmail({
              to: fromAddr,
              cc,
              subject,
              body: item.body,
              inReplyTo: messageIdHeader || undefined,
              references: references || undefined,
              attachments: atts,
            });
            const threadId = orig.data.threadId ?? undefined;
            const draft = await g.gmail.users.drafts.create({
              userId: "me",
              requestBody: { message: { raw, threadId } },
            });
            const res = await g.gmail.users.drafts.send({
              userId: "me",
              requestBody: { id: draft.data.id! },
            });
            return { messageId: res.data.id };
          } catch (e) {
            return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `↩️ Replied to ${ok_.length}/${replies.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_forward (array) -----------------------------------------------

  server.registerTool(
    "gmail_forward",
    {
      title: "Forward emails",
      description: "Forward one or more existing messages (including their attachments) to new recipients.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string().describe("Id of the message to forward."),
              to: z.string().describe("Recipient(s), comma-separated."),
              body: z.string().optional().describe("Optional text to add above the forwarded content."),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        items.map(async (item) => {
          try {
            const orig = await g.gmail.users.messages.get({ userId: "me", id: item.messageId, format: "full" });
            const h = orig.data.payload?.headers;
            let subject = header(h, "Subject");
            if (!/^fwd:/i.test(subject)) subject = "Fwd: " + subject;
            const forwardedHeader =
              "---------- Forwarded message ----------\r\n" +
              `From: ${header(h, "From")}\r\n` +
              `Date: ${header(h, "Date")}\r\n` +
              `Subject: ${header(h, "Subject")}\r\n` +
              `To: ${header(h, "To")}\r\n\r\n`;
            const body = (item.body ? item.body + "\r\n\r\n" : "") + forwardedHeader + extractBody(orig.data.payload);
            const atts: MailAttachment[] = [];
            for (const a of collectAttachments(orig.data.payload)) {
              const att = await g.gmail.users.messages.attachments.get({
                userId: "me",
                messageId: item.messageId,
                id: a.attachmentId,
              });
              atts.push({
                filename: a.filename,
                mimeType: a.mimeType,
                base64: Buffer.from(att.data.data ?? "", "base64url").toString("base64"),
              });
            }
            const raw = buildRawEmail({ to: item.to, subject, body, attachments: atts.length ? atts : undefined });
            const res = await g.gmail.users.messages.send({ userId: "me", requestBody: { raw } });
            return { messageId: res.data.id };
          } catch (e) {
            return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `➡️ Forwarded ${ok_.length}/${items.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_create_draft (array) ------------------------------------------

  server.registerTool(
    "gmail_create_draft",
    {
      title: "Create drafts",
      description: "Create one or more draft emails (not sent) for the user to review/send later.",
      inputSchema: {
        account,
        drafts: z
          .array(
            z.object({
              to: z.string(),
              subject: z.string(),
              body: z.string(),
              cc: z.string().optional(),
              bcc: z.string().optional(),
              attachments: attachmentsField,
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, drafts }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        drafts.map(async (d) => {
          try {
            const atts = d.attachments?.length ? await resolveAttachments(g, d.attachments) : undefined;
            const raw = buildRawEmail({ to: d.to, subject: d.subject, body: d.body, cc: d.cc, bcc: d.bcc, attachments: atts });
            const res = await g.gmail.users.drafts.create({
              userId: "me",
              requestBody: { message: { raw } },
            });
            return { draftId: res.data.id };
          } catch (e) {
            return { error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📝 Created ${ok_.length}/${drafts.length} draft(s)`,
        results,
      });
    }),
  );

  // ---- gmail_archive (array, absorbs batch_archive) ------------------------

  server.registerTool(
    "gmail_archive",
    {
      title: "Archive emails",
      description:
        "Archive one or more messages by removing them from the Inbox (they stay searchable). " +
        "Pass an array of message ids.",
      inputSchema: {
        account,
        messageIds: z.array(z.string()).min(1).describe("Message id(s) to archive."),
      },
    },
    guard(async ({ account, messageIds }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        messageIds.map(async (id) => {
          try {
            await g.gmail.users.messages.modify({
              userId: "me",
              id,
              requestBody: { removeLabelIds: ["INBOX"] },
            });
            return { id };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📥 Archived ${ok_.length}/${messageIds.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_trash (array, absorbs batch_trash) ----------------------------

  server.registerTool(
    "gmail_trash",
    {
      title: "Delete emails (to Trash)",
      description:
        "Move one or more messages to Trash (reversible; auto-purges after ~30 days). " +
        "Pass an array of message ids.",
      inputSchema: {
        account,
        messageIds: z.array(z.string()).min(1).describe("Message id(s) to trash."),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, messageIds }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        messageIds.map(async (id) => {
          try {
            await g.gmail.users.messages.trash({ userId: "me", id });
            return { id };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🗑 Trashed ${ok_.length}/${messageIds.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_modify_labels (array, absorbs batch_modify_labels) ------------

  server.registerTool(
    "gmail_modify_labels",
    {
      title: "Modify labels (read/unread/star/...)",
      description:
        "Add and/or remove labels on one or more messages. System labels include UNREAD, STARRED, IMPORTANT, INBOX, SPAM. " +
        "Mark as read = remove UNREAD; star = add STARRED. Use gmail_list_labels for custom label ids. " +
        "Pass an array of {messageId, addLabelIds?, removeLabelIds?} items.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string(),
              addLabelIds: z.array(z.string()).optional(),
              removeLabelIds: z.array(z.string()).optional(),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        items.map(async (item) => {
          try {
            await g.gmail.users.messages.modify({
              userId: "me",
              id: item.messageId,
              requestBody: { addLabelIds: item.addLabelIds, removeLabelIds: item.removeLabelIds },
            });
            return { id: item.messageId };
          } catch (e) {
            return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🏷️ Modified labels on ${ok_.length}/${items.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_snooze (array) ------------------------------------------------

  server.registerTool(
    "gmail_snooze",
    {
      title: "Snooze emails",
      description:
        "Archive one or more messages now and automatically return them to the Inbox at a specified time " +
        "(requires DATABASE_URL — Railway Postgres). Without Postgres the messages are still archived " +
        "but auto-restore is unavailable. " +
        "Pass `unsnoozeAt` as an ISO 8601 datetime, e.g. '2024-01-15T09:00:00'.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string().describe("Message id to snooze."),
              unsnoozeAt: z
                .string()
                .describe("ISO 8601 datetime when to wake up. Must be in the future."),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        items.map(async (item) => {
          try {
            const unsnoozeAt = new Date(item.unsnoozeAt);
            if (isNaN(unsnoozeAt.getTime())) {
              return { id: item.messageId, error: `Cannot parse date "${item.unsnoozeAt}". Use ISO 8601.` };
            }
            if (unsnoozeAt <= new Date()) {
              return { id: item.messageId, error: `Snooze time "${item.unsnoozeAt}" is already in the past.` };
            }
            await g.gmail.users.messages.modify({
              userId: "me",
              id: item.messageId,
              requestBody: { removeLabelIds: ["INBOX"] },
            });
            const { store, userToken } = snoozeCtx;
            if (store && userToken) {
              const accountName = account ?? clients.defaultName;
              await store.addSnooze({
                userToken,
                accountName,
                messageId: item.messageId,
                unsnoozeAt,
              });
            }
            return { id: item.messageId, unsnoozeAt: unsnoozeAt.toISOString() };
          } catch (e) {
            return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `⏰ Snoozed ${ok_.length}/${items.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_get_attachment (array) ----------------------------------------

  server.registerTool(
    "gmail_get_attachment",
    {
      title: "Download email attachments",
      description:
        "Download one or more attachments' content. Get `attachmentId` from gmail_get_message's `attachments`. " +
        "Text attachments return as text; binaries as base64.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string(),
              attachmentId: z.string(),
              mimeType: z.string().optional().describe("Attachment MIME type (from gmail_get_message)."),
              filename: z.string().optional(),
              maxBytes: z.number().int().min(1).max(8_000_000).default(750_000).optional(),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        items.map(async (item) => {
          try {
            const res = await g.gmail.users.messages.attachments.get({
              userId: "me",
              messageId: item.messageId,
              id: item.attachmentId,
            });
            const buf = Buffer.from(res.data.data ?? "", "base64url");
            const base = { messageId: item.messageId, attachmentId: item.attachmentId, filename: item.filename ?? null, mimeType: item.mimeType ?? null, bytes: buf.length };
            if (item.mimeType && isTextual(item.mimeType)) {
              return { ...base, text: buf.toString("utf8"), encoding: "text" };
            }
            const limit = item.maxBytes ?? 750_000;
            if (buf.length > limit) {
              return { ...base, error: `Attachment is ${buf.length} bytes — too large to inline. Raise maxBytes (max 8MB) or use gmail_save_attachment_to_drive.` };
            }
            return { ...base, content: buf.toString("base64"), encoding: "base64" };
          } catch (e) {
            return { messageId: item.messageId, attachmentId: item.attachmentId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📎 Fetched ${ok_.length}/${items.length} attachment(s)`,
        results,
      });
    }),
  );

  // ---- gmail_get_attachment_text (array) -----------------------------------

  server.registerTool(
    "gmail_get_attachment_text",
    {
      title: "Read attachments as text (OCR)",
      description:
        "Extract the TEXT of one or more email attachments (PDF, scan, image) using Google Drive's built-in OCR. " +
        "Use this to actually READ invoices/receipt PDFs.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string(),
              attachmentId: z.string(),
              mimeType: z.string().optional().describe("Source MIME type, e.g. 'application/pdf'. Defaults to application/pdf."),
              ocrLanguage: z.string().optional().describe("Optional language hint, e.g. 'en', 'ru'."),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        items.map(async (item) => {
          try {
            const att = await g.gmail.users.messages.attachments.get({
              userId: "me",
              messageId: item.messageId,
              id: item.attachmentId,
            });
            const buffer = Buffer.from(att.data.data ?? "", "base64url");
            const created = await g.drive.files.create({
              requestBody: { name: "gmcp-ocr-tmp", mimeType: GOOGLE_DOC_MIME },
              media: { mimeType: item.mimeType ?? "application/pdf", body: Readable.from(buffer) },
              ocrLanguage: item.ocrLanguage,
              fields: "id",
            });
            const docId = created.data.id!;
            try {
              const doc = await g.docs.documents.get({ documentId: docId });
              const text = documentToPlainText(doc.data);
              return { messageId: item.messageId, attachmentId: item.attachmentId, text };
            } finally {
              await g.drive.files.delete({ fileId: docId }).catch(() => {});
            }
          } catch (e) {
            return { messageId: item.messageId, attachmentId: item.attachmentId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📄 Extracted text from ${ok_.length}/${items.length} attachment(s)`,
        results,
      });
    }),
  );

  // ---- gmail_save_attachment_to_drive (array) ------------------------------

  server.registerTool(
    "gmail_save_attachment_to_drive",
    {
      title: "Save email attachments to Drive",
      description:
        "Download one or more attachments and upload them straight to Google Drive (cloud-to-cloud, no size limit). " +
        "Get `attachmentId`/`filename` from gmail_get_message.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string(),
              attachmentId: z.string(),
              fileName: z.string().optional().describe("Name to save as in Drive."),
              folderId: z.string().optional().describe("Destination Drive folder id."),
              mimeType: z.string().optional(),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        items.map(async (item) => {
          try {
            const att = await g.gmail.users.messages.attachments.get({
              userId: "me",
              messageId: item.messageId,
              id: item.attachmentId,
            });
            const buffer = Buffer.from(att.data.data ?? "", "base64url");
            const filename = item.fileName ?? "attachment";
            const res = await g.drive.files.create({
              requestBody: { name: filename, parents: item.folderId ? [item.folderId] : undefined },
              media: { mimeType: item.mimeType ?? "application/octet-stream", body: Readable.from(buffer) },
              fields: "id,name,mimeType,size,webViewLink",
            });
            return { fileId: res.data.id, fileName: res.data.name };
          } catch (e) {
            return { messageId: item.messageId, attachmentId: item.attachmentId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `💾 Saved ${ok_.length}/${items.length} attachment(s) to Drive`,
        results,
      });
    }),
  );

  // ---- gmail_list_labels (unchanged) ---------------------------------------

  server.registerTool(
    "gmail_list_labels",
    {
      title: "List labels",
      description: "List all Gmail labels (system + custom) with their ids.",
      inputSchema: { account },
    },
    guard(async ({ account }) => {
      const g = clients.resolve(account);
      const res = await g.gmail.users.labels.list({ userId: "me" });
      const labels = (res.data.labels ?? []).map((l) => ({ id: l.id, name: l.name, type: l.type }));
      const userLabels = labels.filter((l) => l.type === "user");
      const systemLabels = labels.filter((l) => l.type === "system");
      return ok({
        summary: `🏷️ ${labels.length} label(s) — ${systemLabels.length} system, ${userLabels.length} user-defined`,
        labels,
      });
    }),
  );

  // ---- gmail_create_label (array) ------------------------------------------

  server.registerTool(
    "gmail_create_label",
    {
      title: "Create labels",
      description:
        "Create one or more new Gmail labels. Returns each created label's id. " +
        "Tip: call gmail_list_labels first to check if a label with the same name already exists.",
      inputSchema: {
        account,
        labels: z
          .array(
            z.object({
              name: z.string().describe("Label name, e.g. 'Work/Projects'. Use / for nesting."),
              labelListVisibility: z
                .enum(["labelShow", "labelShowIfUnread", "labelHide"])
                .default("labelShow")
                .optional(),
              messageListVisibility: z.enum(["show", "hide"]).default("show").optional(),
              backgroundColor: z.string().optional(),
              textColor: z.string().optional(),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, labels }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        labels.map(async (l) => {
          try {
            const res = await g.gmail.users.labels.create({
              userId: "me",
              requestBody: {
                name: l.name,
                labelListVisibility: l.labelListVisibility ?? "labelShow",
                messageListVisibility: l.messageListVisibility ?? "show",
                color: l.backgroundColor || l.textColor
                  ? { backgroundColor: l.backgroundColor, textColor: l.textColor }
                  : undefined,
              },
            });
            return { id: res.data.id, name: res.data.name };
          } catch (e) {
            return { error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🏷️ Created ${ok_.length}/${labels.length} label(s)`,
        results,
      });
    }),
  );

  // ---- gmail_update_label (array) ------------------------------------------

  server.registerTool(
    "gmail_update_label",
    {
      title: "Update labels",
      description: "Rename one or more labels or change their visibility/color.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              labelId: z.string().describe("Label ID (from gmail_list_labels or gmail_create_label)."),
              name: z.string().optional(),
              labelListVisibility: z.enum(["labelShow", "labelShowIfUnread", "labelHide"]).optional(),
              messageListVisibility: z.enum(["show", "hide"]).optional(),
              backgroundColor: z.string().optional(),
              textColor: z.string().optional(),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        items.map(async (item) => {
          try {
            const patch: Record<string, unknown> = {};
            if (item.name) patch.name = item.name;
            if (item.labelListVisibility) patch.labelListVisibility = item.labelListVisibility;
            if (item.messageListVisibility) patch.messageListVisibility = item.messageListVisibility;
            if (item.backgroundColor || item.textColor) patch.color = { backgroundColor: item.backgroundColor, textColor: item.textColor };
            const res = await g.gmail.users.labels.patch({
              userId: "me",
              id: item.labelId,
              requestBody: patch,
            });
            return { id: res.data.id, name: res.data.name };
          } catch (e) {
            return { id: item.labelId, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `✏️ Updated ${ok_.length}/${items.length} label(s)`,
        results,
      });
    }),
  );

  // ---- gmail_delete_label (array) ------------------------------------------

  server.registerTool(
    "gmail_delete_label",
    {
      title: "Delete labels",
      description:
        "Permanently delete one or more user-created Gmail labels. " +
        "The labels are removed from all messages (messages themselves are NOT deleted). " +
        "System labels (INBOX, SENT, etc.) cannot be deleted.",
      inputSchema: {
        account,
        labelIds: z.array(z.string()).min(1).describe("Label ID(s) to delete."),
      },
    },
    guard(async ({ account, labelIds }) => {
      const g = clients.resolve(account);
      const results = await Promise.all(
        labelIds.map(async (id) => {
          try {
            await g.gmail.users.labels.delete({ userId: "me", id });
            return { id };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        }),
      );
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🗑️ Deleted ${ok_.length}/${labelIds.length} label(s)`,
        results,
      });
    }),
  );
}
