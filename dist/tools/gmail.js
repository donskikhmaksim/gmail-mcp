/**
 * Gmail tools: read / analyse / send / reply / archive / trash / labels.
 */
import { z } from "zod";
import { Readable } from "node:stream";
import { ok, fail, guard, isTextual } from "../util.js";
import { accountField } from "../accounts.js";
import { documentToPlainText } from "./docs.js";
const GOOGLE_DOC_MIME = "application/vnd.google-apps.document";
/** Lists attachment parts (filename + id + size) in a message payload. */
function collectAttachments(payload) {
    const out = [];
    const walk = (part) => {
        if (!part)
            return;
        if (part.filename && part.body?.attachmentId) {
            out.push({
                filename: part.filename,
                mimeType: part.mimeType ?? "application/octet-stream",
                size: part.body.size ?? 0,
                attachmentId: part.body.attachmentId,
            });
        }
        for (const sub of part.parts ?? [])
            walk(sub);
    };
    walk(payload);
    return out;
}
// ---- helpers ---------------------------------------------------------------
function header(headers, name) {
    const h = (headers ?? []).find((x) => (x.name ?? "").toLowerCase() === name.toLowerCase());
    return h?.value ?? "";
}
function decodeB64(data) {
    if (!data)
        return "";
    return Buffer.from(data, "base64url").toString("utf8");
}
/** Walks the MIME tree and returns the best-effort plain-text body. */
function extractBody(payload) {
    if (!payload)
        return "";
    const walk = (part, preferHtml) => {
        const mime = part.mimeType ?? "";
        if (mime === "text/plain" && !preferHtml && part.body?.data)
            return decodeB64(part.body.data);
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
            if (r)
                return r;
        }
        return null;
    };
    // Prefer text/plain; fall back to flattened HTML; finally the raw body.
    return (walk(payload, false) ??
        walk(payload, true) ??
        decodeB64(payload.body?.data) ??
        "");
}
function summarise(msg) {
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
export function buildRawEmail(opts) {
    const encodeHeader = (v) => 
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
    ].filter(Boolean);
    const bodyB64 = Buffer.from(opts.body, "utf8").toString("base64");
    let mime;
    if (opts.attachments && opts.attachments.length) {
        const boundary = "=_gmcp_" + Buffer.from(opts.subject + opts.attachments.length).toString("hex").slice(0, 16);
        const parts = [];
        parts.push(`--${boundary}`, 'Content-Type: text/plain; charset="UTF-8"', "Content-Transfer-Encoding: base64", "", bodyB64);
        for (const att of opts.attachments) {
            const wrapped = att.base64.replace(/(.{76})/g, "$1\r\n"); // RFC line length
            parts.push(`--${boundary}`, `Content-Type: ${att.mimeType}; name="${att.filename}"`, "Content-Transfer-Encoding: base64", `Content-Disposition: attachment; filename="${att.filename}"`, "", wrapped);
        }
        parts.push(`--${boundary}--`);
        mime =
            headerLines.join("\r\n") +
                "\r\n" +
                `Content-Type: multipart/mixed; boundary="${boundary}"` +
                "\r\n\r\n" +
                parts.join("\r\n");
    }
    else {
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
/** Resolves attachment inputs (Drive file ids or inline base64) into mail attachments. */
async function resolveAttachments(g, items) {
    const out = [];
    for (const item of items) {
        if (item.driveFileId) {
            const meta = await g.drive.files.get({ fileId: item.driveFileId, fields: "name,mimeType" });
            const srcMime = meta.data.mimeType ?? "application/octet-stream";
            let filename = item.filename ?? meta.data.name ?? "attachment";
            let mimeType = item.mimeType ?? srcMime;
            let buf;
            if (srcMime.startsWith("application/vnd.google-apps.")) {
                mimeType = item.mimeType ?? "application/pdf";
                const r = await g.drive.files.export({ fileId: item.driveFileId, mimeType }, { responseType: "arraybuffer" });
                buf = Buffer.from(r.data);
                if (!item.filename && !/\.[a-z0-9]+$/i.test(filename))
                    filename += ".pdf";
            }
            else {
                const r = await g.drive.files.get({ fileId: item.driveFileId, alt: "media" }, { responseType: "arraybuffer" });
                buf = Buffer.from(r.data);
            }
            out.push({ filename, mimeType, base64: buf.toString("base64") });
        }
        else if (item.contentBase64) {
            out.push({
                filename: item.filename ?? "attachment",
                mimeType: item.mimeType ?? "application/octet-stream",
                base64: item.contentBase64,
            });
        }
        else {
            throw new Error("Each attachment needs either driveFileId or contentBase64.");
        }
    }
    return out;
}
export function registerGmailTools(server, clients, snoozeCtx = { store: null, userToken: null }) {
    const account = accountField(clients);
    const attachmentsField = z
        .array(z.object({
        driveFileId: z.string().optional().describe("Attach this Google Drive file."),
        contentBase64: z.string().optional().describe("Inline file bytes as base64."),
        filename: z.string().optional(),
        mimeType: z.string().optional(),
    }))
        .optional()
        .describe("Files to attach. Each item is either {driveFileId} (a Drive file, Google Docs/Sheets export to PDF) " +
        "or {filename, contentBase64, mimeType} (inline).");
    server.registerTool("gmail_search", {
        title: "Search emails",
        description: "Search the mailbox with Gmail query syntax (e.g. \"from:bob@x.com is:unread newer_than:7d has:attachment\"). " +
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
    }, guard(async ({ account, query, maxResults, pageToken }) => {
        const g = clients.resolve(account);
        // AND the account's configured base filter (e.g. a specific mailbox/alias)
        // into the query, so a named account can be scoped to one address.
        const base = clients.baseGmailQuery(account);
        const q = [base, query].map((s) => (s ?? "").trim()).filter(Boolean).join(" ");
        const list = await g.gmail.users.messages.list({
            userId: "me",
            q: q || undefined,
            maxResults: maxResults ?? 10,
            pageToken,
        });
        const ids = (list.data.messages ?? []).map((m) => m.id).filter(Boolean);
        const messages = await Promise.all(ids.map((id) => g.gmail.users.messages.get({
            userId: "me",
            id,
            format: "metadata",
            metadataHeaders: ["From", "To", "Subject", "Date"],
        })));
        const msgs = messages.map((r) => summarise(r.data));
        return ok({
            summary: `🔍 Gmail search "${q || "(all)"}" — ${msgs.length} message(s)${list.data.nextPageToken ? " (has next page)" : ""}`,
            resultSizeEstimate: list.data.resultSizeEstimate ?? ids.length,
            nextPageToken: list.data.nextPageToken ?? null,
            messages: msgs,
        });
    }));
    server.registerTool("gmail_count", {
        title: "Count messages or threads",
        description: "Exact count of MESSAGES or THREADS matching a Gmail query, by paginating through ids " +
            '(no per-message fetch). Examples: query "is:starred", "is:unread", "label:Требует ответа". ' +
            "Use unit=threads to count conversations rather than individual messages.",
        inputSchema: {
            account,
            query: z.string().default("").describe('Gmail query, e.g. "is:starred", "is:unread".'),
            unit: z.enum(["messages", "threads"]).default("messages").optional(),
        },
    }, guard(async ({ account, query, unit }) => {
        const g = clients.resolve(account);
        const base = clients.baseGmailQuery(account);
        const q = [base, query].map((s) => (s ?? "").trim()).filter(Boolean).join(" ");
        const countThreads = unit === "threads";
        const MAX_PAGES = 200; // 200 * 500 = up to 100k items
        let count = 0;
        let pageToken;
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
            }
            else {
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
    }));
    server.registerTool("gmail_get_message", {
        title: "Read an email",
        description: "Get one email fully: headers plus the decoded plain-text body, for reading/analysis.",
        inputSchema: { account, id: z.string().describe("Message id.") },
    }, guard(async ({ account, id }) => {
        const g = clients.resolve(account);
        const res = await g.gmail.users.messages.get({ userId: "me", id, format: "full" });
        const s = summarise(res.data);
        const body = extractBody(res.data.payload);
        const attachments = collectAttachments(res.data.payload);
        return ok({
            summary: `📧 From ${s.from} · "${s.subject}" · ${s.date}${attachments.length ? ` · ${attachments.length} attachment(s)` : ""}`,
            ...s,
            body,
            attachments,
        });
    }));
    server.registerTool("gmail_get_thread", {
        title: "Read a thread",
        description: "Get every message in a conversation thread (decoded), for analysing the whole exchange.",
        inputSchema: { account, threadId: z.string() },
    }, guard(async ({ account, threadId }) => {
        const g = clients.resolve(account);
        const res = await g.gmail.users.threads.get({ userId: "me", id: threadId, format: "full" });
        const msgs = (res.data.messages ?? []).map((m) => ({
            ...summarise(m),
            body: extractBody(m.payload),
            attachments: collectAttachments(m.payload),
        }));
        const participants = [...new Set(msgs.map((m) => m.from).filter(Boolean))].join(", ");
        return ok({
            summary: `📧 Thread — ${msgs.length} message(s)${participants ? ` · participants: ${participants}` : ""}`,
            threadId,
            messages: msgs,
        });
    }));
    server.registerTool("gmail_send", {
        title: "Send an email",
        description: "Send a new email (optionally with attachments). `to`/`cc`/`bcc` may be comma-separated lists.",
        inputSchema: {
            account,
            to: z.string().describe("Recipient(s), comma-separated."),
            subject: z.string(),
            body: z.string(),
            cc: z.string().optional(),
            bcc: z.string().optional(),
            attachments: attachmentsField,
        },
    }, guard(async ({ account, to, subject, body, cc, bcc, attachments }) => {
        const g = clients.resolve(account);
        const atts = attachments?.length ? await resolveAttachments(g, attachments) : undefined;
        const raw = buildRawEmail({ to, subject, body, cc, bcc, attachments: atts });
        const res = await g.gmail.users.messages.send({ userId: "me", requestBody: { raw } });
        return ok({
            summary: `✉️ Sent to ${to}${cc ? ` (cc ${cc})` : ""} — "${subject}"${atts?.length ? ` · ${atts.length} attachment(s)` : ""}`,
            to,
            cc: cc ?? null,
            bcc: bcc ?? null,
            subject,
            attachments: atts?.length ?? 0,
            id: res.data.id,
            threadId: res.data.threadId,
            labelIds: res.data.labelIds,
        });
    }));
    server.registerTool("gmail_reply", {
        title: "Reply to an email",
        description: "Reply within the same thread of an existing message. Keeps subject (adds 'Re:') and threading headers.",
        inputSchema: {
            account,
            messageId: z.string().describe("Id of the message being replied to."),
            body: z.string(),
            replyAll: z.boolean().default(false).optional().describe("Also reply to Cc recipients."),
            attachments: attachmentsField,
        },
    }, guard(async ({ account, messageId, body, replyAll, attachments }) => {
        const g = clients.resolve(account);
        const orig = await g.gmail.users.messages.get({
            userId: "me",
            id: messageId,
            format: "metadata",
            metadataHeaders: ["From", "To", "Cc", "Subject", "Message-ID", "References"],
        });
        const h = orig.data.payload?.headers;
        const fromAddr = header(h, "From");
        const messageIdHeader = header(h, "Message-ID");
        const references = [header(h, "References"), messageIdHeader].filter(Boolean).join(" ");
        let subject = header(h, "Subject");
        if (!/^re:/i.test(subject))
            subject = "Re: " + subject;
        const cc = replyAll ? header(h, "Cc") || undefined : undefined;
        const atts = attachments?.length ? await resolveAttachments(g, attachments) : undefined;
        const raw = buildRawEmail({
            to: fromAddr,
            cc,
            subject,
            body,
            inReplyTo: messageIdHeader || undefined,
            references: references || undefined,
            attachments: atts,
        });
        const threadId = orig.data.threadId ?? undefined;
        // drafts.create + drafts.send guarantees threadId is respected by Gmail.
        // messages.send ignores threadId in requestBody in some cases, creating a new thread.
        const draft = await g.gmail.users.drafts.create({
            userId: "me",
            requestBody: { message: { raw, threadId } },
        });
        const res = await g.gmail.users.drafts.send({
            userId: "me",
            requestBody: { id: draft.data.id },
        });
        return ok({
            summary: `↩️ Replied to ${fromAddr} — "${subject}"${atts?.length ? ` · ${atts.length} attachment(s)` : ""}`,
            to: fromAddr,
            cc: cc ?? null,
            subject,
            attachments: atts?.length ?? 0,
            id: res.data.id,
            threadId: res.data.threadId,
        });
    }));
    server.registerTool("gmail_forward", {
        title: "Forward an email",
        description: "Forward an existing message (including its attachments) to new recipients, with an optional note.",
        inputSchema: {
            account,
            messageId: z.string().describe("Id of the message to forward."),
            to: z.string().describe("Recipient(s), comma-separated."),
            cc: z.string().optional(),
            bcc: z.string().optional(),
            note: z.string().optional().describe("Optional text to add above the forwarded content."),
            attachments: attachmentsField,
        },
    }, guard(async ({ account, messageId, to, cc, bcc, note, attachments }) => {
        const g = clients.resolve(account);
        const orig = await g.gmail.users.messages.get({ userId: "me", id: messageId, format: "full" });
        const h = orig.data.payload?.headers;
        let subject = header(h, "Subject");
        if (!/^fwd:/i.test(subject))
            subject = "Fwd: " + subject;
        const forwardedHeader = "---------- Forwarded message ----------\r\n" +
            `From: ${header(h, "From")}\r\n` +
            `Date: ${header(h, "Date")}\r\n` +
            `Subject: ${header(h, "Subject")}\r\n` +
            `To: ${header(h, "To")}\r\n\r\n`;
        const body = (note ? note + "\r\n\r\n" : "") + forwardedHeader + extractBody(orig.data.payload);
        // Re-download the original attachments.
        const atts = [];
        for (const a of collectAttachments(orig.data.payload)) {
            const att = await g.gmail.users.messages.attachments.get({
                userId: "me",
                messageId,
                id: a.attachmentId,
            });
            atts.push({
                filename: a.filename,
                mimeType: a.mimeType,
                base64: Buffer.from(att.data.data ?? "", "base64url").toString("base64"),
            });
        }
        // Add extra attachments supplied by the caller.
        if (attachments?.length) {
            const extra = await resolveAttachments(g, attachments);
            atts.push(...extra);
        }
        const raw = buildRawEmail({ to, cc, bcc, subject, body, attachments: atts.length ? atts : undefined });
        const res = await g.gmail.users.messages.send({ userId: "me", requestBody: { raw } });
        return ok({
            summary: `➡️ Forwarded to ${to}${cc ? ` (cc ${cc})` : ""} — "${subject}"${atts.length ? ` · ${atts.length} attachment(s)` : ""}`,
            to,
            cc: cc ?? null,
            bcc: bcc ?? null,
            subject,
            forwardedAttachments: atts.length,
            id: res.data.id,
            threadId: res.data.threadId,
        });
    }));
    server.registerTool("gmail_create_draft", {
        title: "Create a draft",
        description: "Create a draft email (not sent) for the user to review/send later.",
        inputSchema: {
            account,
            to: z.string(),
            subject: z.string(),
            body: z.string(),
            cc: z.string().optional(),
            bcc: z.string().optional(),
            attachments: attachmentsField,
        },
    }, guard(async ({ account, to, subject, body, cc, bcc, attachments }) => {
        const g = clients.resolve(account);
        const atts = attachments?.length ? await resolveAttachments(g, attachments) : undefined;
        const raw = buildRawEmail({ to, subject, body, cc, bcc, attachments: atts });
        const res = await g.gmail.users.drafts.create({
            userId: "me",
            requestBody: { message: { raw } },
        });
        return ok({
            summary: `📝 Draft saved — to ${to}${cc ? ` (cc ${cc})` : ""} · "${subject}"${atts?.length ? ` · ${atts.length} attachment(s)` : ""}`,
            draftId: res.data.id,
            message: res.data.message,
        });
    }));
    server.registerTool("gmail_archive", {
        title: "Archive an email",
        description: "Archive a message by removing it from the Inbox (it stays searchable). " +
            "Returns the message's from/subject/date and a text preview so it's clear what was archived. " +
            "Pass `_from` and `_subject` if already known — they appear in the approval dialog.",
        inputSchema: {
            account,
            id: z.string(),
            _from: z.string().optional().describe("Sender address (for the approval dialog — fill from context if known)."),
            _subject: z.string().optional().describe("Email subject (for the approval dialog — fill from context if known)."),
        },
    }, guard(async ({ account, id, _from, _subject }) => {
        const g = clients.resolve(account);
        let msgSummary = null;
        let preview = "";
        try {
            const msg = await g.gmail.users.messages.get({ userId: "me", id, format: "full" });
            msgSummary = summarise(msg.data);
            preview = extractBody(msg.data.payload).replace(/\s+/g, " ").trim().slice(0, 400);
        }
        catch {
            // Use hint fields as fallback if the read fails.
            if (_from || _subject)
                msgSummary = { id, threadId: null, from: _from ?? "", to: "", subject: _subject ?? "", date: "", snippet: "", labelIds: [] };
        }
        const res = await g.gmail.users.messages.modify({
            userId: "me",
            id,
            requestBody: { removeLabelIds: ["INBOX"] },
        });
        return ok({
            summary: msgSummary
                ? `📥 Archived — from ${msgSummary.from} · "${msgSummary.subject}" · ${msgSummary.date}`
                : `📥 Archived message ${id}`,
            from: msgSummary?.from ?? null,
            subject: msgSummary?.subject ?? null,
            date: msgSummary?.date ?? null,
            preview,
            id: res.data.id,
            labelIds: res.data.labelIds,
            archived: true,
        });
    }));
    server.registerTool("gmail_trash", {
        title: "Delete an email (to Trash)",
        description: "Move a message to Trash (reversible; auto-purges after ~30 days). This is the standard 'delete'. " +
            "Returns the deleted message's from/subject/date and a text preview so it's clear what was removed. " +
            "Pass `_from` and `_subject` if already known — they appear in the approval dialog.",
        inputSchema: {
            account,
            id: z.string(),
            _from: z.string().optional().describe("Sender address (for the approval dialog — fill from context if known)."),
            _subject: z.string().optional().describe("Email subject (for the approval dialog — fill from context if known)."),
        },
    }, guard(async ({ account, id, _from, _subject }) => {
        const g = clients.resolve(account);
        let deleted = null;
        let preview = "";
        try {
            const msg = await g.gmail.users.messages.get({ userId: "me", id, format: "full" });
            deleted = summarise(msg.data);
            preview = extractBody(msg.data.payload).replace(/\s+/g, " ").trim().slice(0, 400);
        }
        catch {
            // Use hint fields as fallback if the read fails.
            if (_from || _subject)
                deleted = { id, threadId: null, from: _from ?? "", to: "", subject: _subject ?? "", date: "", snippet: "", labelIds: [] };
        }
        const res = await g.gmail.users.messages.trash({ userId: "me", id });
        return ok({
            summary: deleted
                ? `🗑 Trashed — from ${deleted.from} · "${deleted.subject}" · ${deleted.date}`
                : `🗑 Trashed message ${id}`,
            from: deleted?.from ?? null,
            subject: deleted?.subject ?? null,
            date: deleted?.date ?? null,
            preview,
            id: res.data.id,
            labelIds: res.data.labelIds,
            trashed: true,
        });
    }));
    server.registerTool("gmail_modify_labels", {
        title: "Modify labels (read/unread/star/...)",
        description: "Add and/or remove labels on a message. System labels include UNREAD, STARRED, IMPORTANT, INBOX, SPAM. " +
            "Mark as read = remove UNREAD; star = add STARRED. Use gmail_list_labels for custom label ids.",
        inputSchema: {
            account,
            id: z.string(),
            addLabelIds: z.array(z.string()).optional(),
            removeLabelIds: z.array(z.string()).optional(),
            _subject: z.string().optional().describe("Email subject (for the approval dialog — fill from context if known)."),
        },
    }, guard(async ({ account, id, addLabelIds, removeLabelIds, _subject }) => {
        const g = clients.resolve(account);
        let msgMeta = _subject ? { from: "", subject: _subject } : null;
        try {
            const msg = await g.gmail.users.messages.get({
                userId: "me",
                id,
                format: "metadata",
                metadataHeaders: ["From", "Subject"],
            });
            const h = msg.data.payload?.headers;
            msgMeta = { from: header(h, "From"), subject: header(h, "Subject") };
        }
        catch { }
        const res = await g.gmail.users.messages.modify({
            userId: "me",
            id,
            requestBody: { addLabelIds, removeLabelIds },
        });
        const addStr = addLabelIds?.length ? `+[${addLabelIds.join(", ")}]` : "";
        const rmStr = removeLabelIds?.length ? `-[${removeLabelIds.join(", ")}]` : "";
        return ok({
            summary: msgMeta
                ? `🏷️ Labels ${[addStr, rmStr].filter(Boolean).join(" ")} on "${msgMeta.subject}" from ${msgMeta.from}`
                : `🏷️ Labels ${[addStr, rmStr].filter(Boolean).join(" ")} on message ${id}`,
            id: res.data.id,
            labelIds: res.data.labelIds,
        });
    }));
    server.registerTool("gmail_batch_archive", {
        title: "Archive multiple emails",
        description: "Archive up to 1000 messages at once by removing INBOX label. " +
            "Pass an array of message ids (from gmail_search). " +
            "This uses the native Gmail batchModify API — one round-trip for all messages.",
        inputSchema: {
            account,
            ids: z.array(z.string()).min(1).max(1000).describe("Array of message ids to archive."),
        },
        annotations: { destructiveHint: false },
    }, guard(async ({ account, ids }) => {
        const g = clients.resolve(account);
        await g.gmail.users.messages.batchModify({
            userId: "me",
            requestBody: { ids, removeLabelIds: ["INBOX"] },
        });
        return ok({
            summary: `📥 Archived ${ids.length} message(s)`,
            count: ids.length,
            ids,
        });
    }));
    server.registerTool("gmail_batch_trash", {
        title: "Trash multiple emails",
        description: "Move up to 1000 messages to Trash at once (reversible; auto-purges after ~30 days). " +
            "Pass an array of message ids (from gmail_search). " +
            "Uses batchModify to add TRASH + remove INBOX in one API call.",
        inputSchema: {
            account,
            ids: z.array(z.string()).min(1).max(1000).describe("Array of message ids to trash."),
        },
        annotations: { destructiveHint: true },
    }, guard(async ({ account, ids }) => {
        const g = clients.resolve(account);
        await g.gmail.users.messages.batchModify({
            userId: "me",
            requestBody: { ids, addLabelIds: ["TRASH"], removeLabelIds: ["INBOX"] },
        });
        return ok({
            summary: `🗑 Trashed ${ids.length} message(s)`,
            count: ids.length,
            ids,
        });
    }));
    server.registerTool("gmail_batch_modify_labels", {
        title: "Modify labels on multiple emails",
        description: "Add and/or remove labels on up to 1000 messages at once. " +
            "Common uses: mark as read (removeLabelIds: [UNREAD]), star (addLabelIds: [STARRED]), " +
            "mark as spam (addLabelIds: [SPAM]), move to a custom label. " +
            "Uses the native Gmail batchModify API — one round-trip for all messages.",
        inputSchema: {
            account,
            ids: z.array(z.string()).min(1).max(1000).describe("Array of message ids."),
            addLabelIds: z.array(z.string()).optional().describe("Labels to add, e.g. [STARRED], [UNREAD], or custom label ids."),
            removeLabelIds: z.array(z.string()).optional().describe("Labels to remove, e.g. [UNREAD] to mark as read."),
        },
        annotations: { destructiveHint: false },
    }, guard(async ({ account, ids, addLabelIds, removeLabelIds }) => {
        if (!addLabelIds?.length && !removeLabelIds?.length) {
            return fail("Provide at least one of addLabelIds or removeLabelIds.");
        }
        const g = clients.resolve(account);
        await g.gmail.users.messages.batchModify({
            userId: "me",
            requestBody: { ids, addLabelIds, removeLabelIds },
        });
        const addStr = addLabelIds?.length ? `+[${addLabelIds.join(", ")}]` : "";
        const rmStr = removeLabelIds?.length ? `-[${removeLabelIds.join(", ")}]` : "";
        return ok({
            summary: `🏷️ Labels ${[addStr, rmStr].filter(Boolean).join(" ")} on ${ids.length} message(s)`,
            count: ids.length,
            ids,
        });
    }));
    server.registerTool("gmail_list_labels", {
        title: "List labels",
        description: "List all Gmail labels (system + custom) with their ids.",
        inputSchema: { account },
    }, guard(async ({ account }) => {
        const g = clients.resolve(account);
        const res = await g.gmail.users.labels.list({ userId: "me" });
        const labels = (res.data.labels ?? []).map((l) => ({ id: l.id, name: l.name, type: l.type }));
        const userLabels = labels.filter((l) => l.type === "user");
        const systemLabels = labels.filter((l) => l.type === "system");
        return ok({
            summary: `🏷️ ${labels.length} label(s) — ${systemLabels.length} system, ${userLabels.length} user-defined`,
            labels,
        });
    }));
    server.registerTool("gmail_get_attachment", {
        title: "Download an email attachment",
        description: "Download an attachment's content. Get `attachmentId` from gmail_get_message's `attachments`. " +
            "Text attachments return as text; binaries as base64 (size-limited — for big files use gmail_save_attachment_to_drive).",
        inputSchema: {
            account,
            messageId: z.string(),
            attachmentId: z.string(),
            mimeType: z.string().optional().describe("Attachment MIME type (from gmail_get_message), used to decide text vs base64."),
            filename: z.string().optional(),
            maxBytes: z.number().int().min(1).max(8_000_000).default(750_000).optional(),
        },
    }, guard(async ({ account, messageId, attachmentId, mimeType, filename, maxBytes }) => {
        const g = clients.resolve(account);
        const res = await g.gmail.users.messages.attachments.get({
            userId: "me",
            messageId,
            id: attachmentId,
        });
        const buf = Buffer.from(res.data.data ?? "", "base64url");
        const base = { filename: filename ?? null, mimeType: mimeType ?? null, bytes: buf.length };
        if (mimeType && isTextual(mimeType)) {
            return ok({
                summary: `📎 Attachment "${filename ?? "?"}" (${mimeType}, ${buf.length} bytes) — text content`,
                ...base,
                text: buf.toString("utf8"),
            });
        }
        const limit = maxBytes ?? 750_000;
        if (buf.length > limit) {
            return fail(`Attachment is ${buf.length} bytes — too large to inline. Raise maxBytes (max 8MB) ` +
                `or use gmail_save_attachment_to_drive.`);
        }
        return ok({
            summary: `📎 Attachment "${filename ?? "?"}" (${mimeType ?? "binary"}, ${buf.length} bytes) — base64`,
            ...base,
            base64: buf.toString("base64"),
        });
    }));
    server.registerTool("gmail_save_attachment_to_drive", {
        title: "Save an email attachment to Drive",
        description: "Download an attachment and upload it straight to Google Drive (cloud-to-cloud, no size limit). " +
            "Get `attachmentId`/`filename` from gmail_get_message.",
        inputSchema: {
            account,
            messageId: z.string(),
            attachmentId: z.string(),
            filename: z.string().describe("Name to save as in Drive."),
            mimeType: z.string().optional(),
            parentId: z.string().optional().describe("Destination Drive folder id."),
        },
    }, guard(async ({ account, messageId, attachmentId, filename, mimeType, parentId }) => {
        const g = clients.resolve(account);
        const att = await g.gmail.users.messages.attachments.get({
            userId: "me",
            messageId,
            id: attachmentId,
        });
        const buffer = Buffer.from(att.data.data ?? "", "base64url");
        const res = await g.drive.files.create({
            requestBody: { name: filename, parents: parentId ? [parentId] : undefined },
            media: { mimeType: mimeType ?? "application/octet-stream", body: Readable.from(buffer) },
            fields: "id,name,mimeType,size,webViewLink",
        });
        return ok({
            summary: `💾 Saved "${filename}" (${buffer.length} bytes) to Drive`,
            savedToDrive: res.data,
            sourceBytes: buffer.length,
        });
    }));
    server.registerTool("gmail_get_attachment_text", {
        title: "Read an attachment as text (OCR)",
        description: "Extract the TEXT of an email attachment (PDF, scan, image) using Google Drive's built-in OCR. " +
            "Downloads the attachment, OCR-converts it via Drive, returns plain text, and cleans up the temp file. " +
            "Use this to actually READ an invoice/receipt PDF (base64 is not readable by the model).",
        inputSchema: {
            account,
            messageId: z.string(),
            attachmentId: z.string(),
            mimeType: z
                .string()
                .optional()
                .describe("Source MIME type, e.g. 'application/pdf', 'image/png'. Defaults to application/pdf."),
            ocrLanguage: z.string().optional().describe("Optional language hint, e.g. 'en', 'ru'."),
        },
    }, guard(async ({ account, messageId, attachmentId, mimeType, ocrLanguage }) => {
        const g = clients.resolve(account);
        const att = await g.gmail.users.messages.attachments.get({
            userId: "me",
            messageId,
            id: attachmentId,
        });
        const buffer = Buffer.from(att.data.data ?? "", "base64url");
        // Upload + OCR-convert to a temporary Google Doc, read text, then delete it.
        const created = await g.drive.files.create({
            requestBody: { name: "gmcp-ocr-tmp", mimeType: GOOGLE_DOC_MIME },
            media: { mimeType: mimeType ?? "application/pdf", body: Readable.from(buffer) },
            ocrLanguage,
            fields: "id",
        });
        const docId = created.data.id;
        try {
            const doc = await g.docs.documents.get({ documentId: docId });
            const text = documentToPlainText(doc.data);
            return ok({
                summary: `📄 Extracted text from attachment via OCR (${buffer.length} bytes) — ${text.length} char(s)`,
                bytes: buffer.length,
                text,
            });
        }
        finally {
            await g.drive.files.delete({ fileId: docId }).catch(() => { });
        }
    }));
    server.registerTool("gmail_snooze", {
        title: "Snooze an email",
        description: "Archive a message now and automatically return it to the Inbox at a specified time " +
            "(requires DATABASE_URL — Railway Postgres). Without Postgres the message is still archived " +
            "but auto-restore is unavailable. " +
            "Pass `until` as an ISO 8601 datetime, e.g. '2024-01-15T09:00:00'. " +
            "Compute the target time from relative expressions: 'in 2 hours', 'tomorrow 9am', 'Monday morning'.",
        inputSchema: {
            account,
            id: z.string().describe("Message id to snooze."),
            until: z
                .string()
                .describe("ISO 8601 datetime when to wake up, e.g. '2025-01-15T09:00:00'. " +
                "Must be in the future."),
            _from: z.string().optional().describe("Sender address (for the approval dialog — fill from context if known)."),
            _subject: z.string().optional().describe("Email subject (for the approval dialog — fill from context if known)."),
        },
    }, guard(async ({ account, id, until, _from, _subject }) => {
        const g = clients.resolve(account);
        const unsnoozeAt = new Date(until);
        if (isNaN(unsnoozeAt.getTime())) {
            return fail(`Cannot parse date "${until}". Use ISO 8601, e.g. "2025-01-15T09:00:00".`);
        }
        if (unsnoozeAt <= new Date()) {
            return fail(`Snooze time "${until}" is already in the past.`);
        }
        // Read message context before archiving.
        let msgInfo = _from || _subject ? { from: _from ?? "", subject: _subject ?? "", date: "" } : null;
        try {
            const msg = await g.gmail.users.messages.get({
                userId: "me",
                id,
                format: "metadata",
                metadataHeaders: ["From", "Subject", "Date"],
            });
            const h = msg.data.payload?.headers;
            msgInfo = {
                from: header(h, "From"),
                subject: header(h, "Subject"),
                date: header(h, "Date"),
            };
        }
        catch { }
        // Archive: remove INBOX label.
        await g.gmail.users.messages.modify({
            userId: "me",
            id,
            requestBody: { removeLabelIds: ["INBOX"] },
        });
        // Persist snooze for auto-restore.
        const { store, userToken } = snoozeCtx;
        let autoRestore = false;
        if (store && userToken) {
            const accountName = account ?? clients.defaultName;
            await store.addSnooze({
                userToken,
                accountName,
                messageId: id,
                subject: msgInfo?.subject,
                unsnoozeAt,
            });
            autoRestore = true;
        }
        return ok({
            summary: msgInfo
                ? `⏰ Snoozed — from ${msgInfo.from} · "${msgInfo.subject}" · returns at ${unsnoozeAt.toISOString()}`
                : `⏰ Snoozed message ${id} — returns at ${unsnoozeAt.toISOString()}`,
            id,
            from: msgInfo?.from ?? null,
            subject: msgInfo?.subject ?? null,
            originalDate: msgInfo?.date ?? null,
            unsnoozeAt: unsnoozeAt.toISOString(),
            autoRestore,
            note: autoRestore
                ? "Message will automatically return to Inbox at the specified time."
                : "No DATABASE_URL configured — message archived but will NOT auto-restore. Add it to Gmail manually.",
        });
    }));
}
