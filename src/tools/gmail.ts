/**
 * Gmail tools: read / analyse / send / reply / archive / trash / labels.
 * Array-first: every item-based tool accepts arrays; batch_ duplicates removed.
 */
import { z } from "zod";
import { Readable } from "node:stream";
import dns from "node:dns/promises";
import net from "node:net";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { gmail_v1 } from "googleapis";
import { ok, fail, guard, isTextual, mapWithLimit } from "../util.js";
import { accountField, type UserClients } from "../accounts.js";
import type { GoogleClients } from "../google.js";
import { documentToPlainText } from "./docs.js";
import {
  issueDownloadLink,
  downloadsAvailable,
  DEFAULT_TTL_MINUTES,
  MAX_TTL_MINUTES,
} from "../downloads.js";
interface PgStore {
  addSnooze(args: {
    userToken: string | null;
    accountName: string;
    messageId: string;
    subject?: string;
    unsnoozeAt: Date;
  }): Promise<void>;
  addScheduledSend(args: {
    userToken: string | null;
    accountName: string;
    rawMessage: string;
    toPreview: string;
    subjectPreview: string;
    sendAt: Date;
  }): Promise<number>;
  listScheduledSends(
    accountName: string,
    status?: string,
  ): Promise<
    {
      id: number;
      toPreview: string;
      subjectPreview: string;
      sendAt: Date;
      status?: string;
      error?: string | null;
      sentMessageId?: string | null;
    }[]
  >;
  countScheduledSends(accountName: string, status: string): Promise<number>;
  cancelScheduledSend(id: number, accountName: string): Promise<boolean>;
}

const GOOGLE_DOC_MIME = "application/vnd.google-apps.document";

/** Drive's upload host — a big attachment is staged there before it is mailed. */
const DRIVE_UPLOAD_ENDPOINT = "https://www.googleapis.com/upload/drive/v3/files";

/** Where client-uploaded attachments are staged, so they are easy to find and clean up. */
const UPLOAD_FOLDER_NAME = "Gmail uploads (staged)";

/** Finds (or creates) the staging folder for client-side attachment uploads. */
async function ensureUploadFolder(g: GoogleClients): Promise<string> {
  const found = await g.drive.files.list({
    q: `name='${UPLOAD_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
    fields: "files(id)",
    pageSize: 1,
  });
  const existing = found.data.files?.[0]?.id;
  if (existing) return existing;
  const created = await g.drive.files.create({
    requestBody: { name: UPLOAD_FOLDER_NAME, mimeType: "application/vnd.google-apps.folder" },
    fields: "id",
  });
  if (!created.data.id) throw new Error(`Could not create the "${UPLOAD_FOLDER_NAME}" folder in Drive.`);
  return created.data.id;
}

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

interface MsgMeta {
  subject?: string;
  from?: string;
  snippet?: string;
}

/**
 * Best-effort subject/from/snippet for a batch of message ids, so mutating
 * tools can report "what" was touched, not just bare ids. Metadata failures
 * are swallowed — a missing subject must never fail the mutation itself.
 */
async function fetchMeta(
  g: GoogleClients,
  messageIds: string[],
): Promise<Map<string, MsgMeta>> {
  const meta = new Map<string, MsgMeta>();
  await mapWithLimit(messageIds, async (id) => {
    try {
      const r = await g.gmail.users.messages.get({
        userId: "me",
        id,
        format: "metadata",
        metadataHeaders: ["From", "Subject"],
      });
      const s = summarise(r.data);
      meta.set(id, { subject: s.subject, from: s.from, snippet: s.snippet });
    } catch {
      /* best-effort */
    }
  });
  return meta;
}

/** One human line per result: «Subject» — From: snippet (or the error). */
function describeLines(
  results: Array<{ id?: string | null; error?: string } & MsgMeta>,
  icon: string,
): string[] {
  return results.map((r) =>
    r.error
      ? `⚠️ ${r.id}: ${r.error}`
      : `${icon} «${r.subject || "(без темы)"}» — ${r.from || "?"}${r.snippet ? `: ${r.snippet.slice(0, 140)}` : ""}`,
  );
}

/**
 * Pulls the bare address out of an RFC 822 mailbox like `Name <a@b.com>` (or a
 * plain `a@b.com`), lower-cased and trimmed. "" when nothing address-like is
 * found. Exported for testing. Used to compute the real reply recipient and to
 * compare it against the account's own address (self-reply detection).
 */
export function extractEmail(raw: string): string {
  if (!raw) return "";
  const angle = raw.match(/<([^>]+)>/);
  const candidate = (angle ? angle[1] : raw).trim().toLowerCase();
  // If several addresses are comma-separated (To: a, b), take the first.
  const first = candidate.split(",")[0].trim();
  return /@/.test(first) ? first : "";
}

/** Per-process cache of account-label → real email, filled from users.getProfile. */
const profileEmailCache = new Map<string, string>();

/**
 * The real email address behind an account label, via Gmail's users.getProfile
 * (cached per label). Best-effort: returns undefined on any error rather than
 * failing the caller — the label alone is still shown (fail-soft). Exported for
 * testing.
 */
export async function accountEmail(
  g: GoogleClients,
  label: string,
  cache: Map<string, string> = profileEmailCache,
): Promise<string | undefined> {
  if (cache.has(label)) return cache.get(label);
  try {
    const r = await g.gmail.users.getProfile({ userId: "me" });
    const email = r.data.emailAddress ?? undefined;
    if (email) cache.set(label, email);
    return email;
  } catch {
    return undefined;
  }
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
  url?: string;
  contentBase64?: string;
  filename?: string;
  mimeType?: string;
}

/** Gmail caps a whole message (body + attachments) at 25 MB. */
const ATTACHMENT_MAX_BYTES = 25 * 1024 * 1024;

// ---- SSRF / OOM guard for url-based attachments -----------------------------
//
// A tool that downloads a URL server-side turns this MCP into a proxy into the
// hosting network. On Railway that means cloud-metadata (169.254.169.254),
// localhost ports and private ranges. `references/security-checklist.md` §2:
// https-only, resolve every IP and reject private/link-local/loopback,
// manual redirects (a public host can redirect to 169.254.169.254), a timeout,
// and a STREAMING size cap enforced BEFORE buffering (a URL that streams
// gigabytes is otherwise a guaranteed container OOM). Written portable — the
// same url-attach path lives in drive-mcp, so this block is copied verbatim.

const FETCH_TIMEOUT_MS = 20_000;
const MAX_ATTACHMENT_REDIRECTS = 3;

/** Optional DNS resolver override (tests inject a fake so no real lookup happens). */
export type LookupFn = (host: string) => Promise<{ address: string }[]>;
const defaultLookup: LookupFn = (host) => dns.lookup(host, { all: true });

/**
 * True when an IP literal is loopback / private / link-local / reserved /
 * multicast — i.e. NOT a public destination. Covers both IPv4 and IPv6
 * (including IPv4-mapped IPv6 like ::ffff:169.254.169.254). Exported for tests.
 */
export function isBlockedIp(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 4) return isBlockedIpv4(ip);
  if (kind === 6) return isBlockedIpv6(ip);
  return true; // not a parseable IP → treat as unsafe
}

function isBlockedIpv4(ip: string): boolean {
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = o;
  if (a === 0) return true; // 0.0.0.0/8 "this host"
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local (cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + 255.*
  return false;
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  // IPv4-mapped / IPv4-compatible — validate the embedded v4 address.
  const mapped = lower.match(/(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/);
  if (mapped) return isBlockedIpv4(mapped[1]);
  if (lower === "::1" || lower === "::") return true; // loopback / unspecified
  const head = lower.split(":")[0] ?? "";
  const n = parseInt(head || "0", 16);
  if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb"))
    return true; // fe80::/10 link-local
  if (n >= 0xfc00 && n <= 0xfdff) return true; // fc00::/7 unique-local
  if (lower.startsWith("ff")) return true; // ff00::/8 multicast
  return false;
}

/**
 * Validates a URL for a server-side fetch: https-only, and every resolved IP
 * must be public. Throws a 🛑-style refusal on anything unsafe. Returns the
 * parsed URL when clean. `lookup` is injectable for offline tests.
 */
export async function assertPublicUrl(rawUrl: string, lookup: LookupFn = defaultLookup): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("🛑 Ссылка на вложение неразборчива — вложение не скачано.");
  }
  if (url.protocol !== "https:") {
    throw new Error(`🛑 Разрешены только https-ссылки на вложения (получено «${url.protocol}»). Вложение не скачано.`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  // If the host is already an IP literal, check it directly (no DNS at all).
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new Error("🛑 Ссылка ведёт на внутренний/приватный адрес — вложение не скачано.");
    return url;
  }
  let addrs: { address: string }[];
  try {
    addrs = await lookup(host);
  } catch {
    throw new Error("🛑 Не удалось разрешить имя хоста ссылки — вложение не скачано.");
  }
  if (!addrs.length) throw new Error("🛑 Имя хоста ссылки не разрешается ни в один адрес — вложение не скачано.");
  for (const a of addrs) {
    if (isBlockedIp(a.address)) {
      throw new Error("🛑 Имя хоста ссылки разрешается во внутренний/приватный адрес — вложение не скачано.");
    }
  }
  return url;
}

/**
 * Fetches a URL into a Buffer with SSRF validation, manual redirects (each
 * Location re-validated), a per-request timeout and a streaming size cap
 * enforced WHILE downloading (never buffers past the cap). Returns the bytes
 * and the response content-type. Exported for tests.
 */
export async function fetchAttachmentSafely(
  rawUrl: string,
  maxBytes: number,
  lookup: LookupFn = defaultLookup,
): Promise<{ buf: Buffer; contentType: string | null }> {
  let current = rawUrl;
  for (let hop = 0; hop <= MAX_ATTACHMENT_REDIRECTS; hop++) {
    const url = await assertPublicUrl(current, lookup);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    let resp: Response;
    try {
      resp = await fetch(url, { redirect: "manual", signal: ctrl.signal, headers: { accept: "*/*" } });
    } catch (e) {
      clearTimeout(timer);
      if ((e as { name?: string })?.name === "AbortError") {
        throw new Error("🛑 Источник вложения не ответил вовремя (таймаут). Вложение не скачано.");
      }
      throw new Error("🛑 Не удалось соединиться с источником вложения. Вложение не скачано.");
    }
    // Manual redirect: re-validate the target through assertPublicUrl on next hop.
    if (resp.status >= 300 && resp.status < 400 && resp.headers.get("location")) {
      clearTimeout(timer);
      current = new URL(resp.headers.get("location")!, url).toString();
      continue;
    }
    if (!resp.ok) {
      clearTimeout(timer);
      throw new Error(`🛑 Источник вложения ответил ошибкой (HTTP ${resp.status}). Вложение не скачано.`);
    }
    // Fast pre-check: a declared Content-Length over the cap is refused up front.
    const declared = Number(resp.headers.get("content-length") ?? "");
    if (Number.isFinite(declared) && declared > maxBytes) {
      clearTimeout(timer);
      throw new Error(
        `🛑 Вложение по ссылке — ${Math.round(declared / (1024 * 1024))} МБ; Gmail ограничивает письмо 25 МБ. Не скачано.`,
      );
    }
    const contentType = resp.headers.get("content-type")?.split(";")[0]?.trim() ?? null;
    try {
      const buf = await readCappedStream(resp.body, maxBytes);
      clearTimeout(timer);
      return { buf, contentType };
    } catch (e) {
      clearTimeout(timer);
      throw e;
    }
  }
  throw new Error("🛑 Слишком много перенаправлений при скачивании вложения. Не скачано.");
}

/**
 * Reads a web stream into a Buffer, aborting the moment the accumulated size
 * would exceed `maxBytes` — so a URL that streams gigabytes never fills memory.
 * Exported for tests.
 */
export async function readCappedStream(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<Buffer> {
  if (!body) return Buffer.alloc(0);
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new Error(
            `🛑 Вложение по ссылке превышает лимит ${Math.round(maxBytes / (1024 * 1024))} МБ (Gmail-кап). Скачивание прервано.`,
          );
        }
        chunks.push(Buffer.from(value));
      }
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, total);
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
    } else if (item.url) {
      // SSRF/OOM-guarded: https-only, private IPs refused, manual redirects,
      // timeout, streaming size cap enforced before buffering. See §2 above.
      const { buf, contentType } = await fetchAttachmentSafely(item.url, ATTACHMENT_MAX_BYTES);
      const urlName = item.url.split("?")[0].replace(/\/+$/, "").split("/").pop() || "attachment";
      out.push({
        filename: item.filename ?? urlName,
        mimeType: item.mimeType ?? contentType ?? "application/octet-stream",
        base64: buf.toString("base64"),
      });
    } else if (item.contentBase64) {
      out.push({
        filename: item.filename ?? "attachment",
        mimeType: item.mimeType ?? "application/octet-stream",
        base64: item.contentBase64,
      });
    } else {
      throw new Error("Each attachment needs one of: driveFileId, url, or contentBase64.");
    }
  }
  return out;
}

// ---- tools -----------------------------------------------------------------

export interface GmailSnoozeContext {
  store: PgStore | null;
  userToken: string | null;
}

/** Reads a single header value out of a raw RFC 822 message (handles folding). */
function headerFromRaw(raw: string, name: string): string {
  const headerBlock = raw.split(/\r?\n\r?\n/, 1)[0] ?? raw;
  const re = new RegExp(`^${name}:[ \\t]*(.*(?:\\r?\\n[ \\t].*)*)`, "im");
  const m = headerBlock.match(re);
  if (!m) return "";
  return m[1].replace(/\r?\n[ \t]+/g, " ").trim();
}

/** Decodes RFC 2047 encoded-words (=?charset?B/Q?...?=) e.g. in Subject headers. */
function decodeMimeWords(s: string): string {
  if (!s) return s;
  return s.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]*)\?=(?:\s+(?==\?))?/g,
    (_m, charset: string, enc: string, text: string) => {
      try {
        const cs = charset.toLowerCase() === "windows-1251" ? "win1251" : charset;
        let buf: Buffer;
        if (enc.toUpperCase() === "B") {
          buf = Buffer.from(text, "base64");
        } else {
          // Q-encoding: '_' is a space, =XX is a hex-escaped byte.
          const q = text.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_x, h) => String.fromCharCode(parseInt(h, 16)));
          buf = Buffer.from(q, "latin1");
        }
        return new TextDecoder(cs as string).decode(buf);
      } catch {
        return text;
      }
    },
  );
}

/** Filesystem/Drive-safe file name fragment. */
function sanitizeName(s: string): string {
  return (s || "untitled")
    .replace(/[\/\\:*?"<>|\r\n\t]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120) || "untitled";
}

/** YYYY-MM-DD from an RFC 822 Date header, or "" if unparseable. */
function dateStamp(dateHeader: string): string {
  if (!dateHeader) return "";
  const d = new Date(dateHeader);
  return isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

/** mbox "From " separator line for one message (date is informational only). */
function mboxFromLine(raw: string): string {
  const d = new Date(headerFromRaw(raw, "Date"));
  const when = isNaN(d.getTime()) ? "Thu Jan  1 00:00:00 2000" : d.toUTCString();
  const from = headerFromRaw(raw, "From").replace(/[<>]/g, "").split(/\s+/).find((t) => t.includes("@")) || "unknown@localhost";
  return `From ${from} ${when}\n`;
}

/** mbox body escaping: lines beginning "From " must be quoted ">From ". */
function escapeMboxFrom(buf: Buffer): Buffer {
  return Buffer.from(buf.toString("latin1").replace(/\nFrom /g, "\n>From "), "latin1");
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
        url: z.string().optional().describe("Download the file from this public/direct URL and attach it."),
        contentBase64: z.string().optional().describe("Inline file bytes as base64."),
        filename: z.string().optional(),
        mimeType: z.string().optional(),
      }),
    )
    .optional()
    .describe(
      "Files to attach. Each item is one of: {driveFileId} (a Drive file, Google Docs/Sheets export to PDF), " +
        "{url} (the server downloads the file from the link), or {filename, contentBase64, mimeType} (inline).",
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
      const messages = await mapWithLimit(ids, (id) =>
          g.gmail.users.messages.get({
            userId: "me",
            id,
            format: "metadata",
            metadataHeaders: ["From", "To", "Subject", "Date"],
          }),);
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
      const results = await mapWithLimit(messageIds, async (id) => {
          try {
            const res = await g.gmail.users.messages.get({ userId: "me", id, format: "full" });
            const s = summarise(res.data);
            const body = extractBody(res.data.payload);
            const attachments = collectAttachments(res.data.payload);
            return { ...s, body, attachments };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        });
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
      const results = await mapWithLimit(threadIds, async (threadId) => {
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
        });
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
      const results = await mapWithLimit(messages, async (msg) => {
          try {
            const atts = msg.attachments?.length ? await resolveAttachments(g, msg.attachments) : undefined;
            const raw = buildRawEmail({ to: msg.to, subject: msg.subject, body: msg.body, cc: msg.cc, bcc: msg.bcc, attachments: atts });
            const res = await g.gmail.users.messages.send({ userId: "me", requestBody: { raw } });
            return { messageId: res.data.id, threadId: res.data.threadId };
          } catch (e) {
            return { error: String(e instanceof Error ? e.message : e) };
          }
        });
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
      const results = await mapWithLimit(replies, async (item) => {
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
        });
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
      const results = await mapWithLimit(items, async (item) => {
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
        });
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
      const results = await mapWithLimit(drafts, async (d) => {
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
        });
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
      const meta = await fetchMeta(g, messageIds);
      const results = await mapWithLimit(messageIds, async (id) => {
          try {
            await g.gmail.users.messages.modify({
              userId: "me",
              id,
              requestBody: { removeLabelIds: ["INBOX"] },
            });
            return { id, ...(meta.get(id) ?? {}) };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📥 Archived ${ok_.length}/${messageIds.length} message(s)`,
        archived: describeLines(results, "📥"),
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
      const meta = await fetchMeta(g, messageIds);
      const results = await mapWithLimit(messageIds, async (id) => {
          try {
            await g.gmail.users.messages.trash({ userId: "me", id });
            return { id, ...(meta.get(id) ?? {}) };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🗑 Trashed ${ok_.length}/${messageIds.length} message(s)`,
        deleted: describeLines(results, "🗑"),
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
      const meta = await fetchMeta(g, items.map((i) => i.messageId));
      const results = await mapWithLimit(items, async (item) => {
          try {
            await g.gmail.users.messages.modify({
              userId: "me",
              id: item.messageId,
              requestBody: { addLabelIds: item.addLabelIds, removeLabelIds: item.removeLabelIds },
            });
            return { id: item.messageId, ...(meta.get(item.messageId) ?? {}) };
          } catch (e) {
            return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
          }
        });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🏷️ Modified labels on ${ok_.length}/${items.length} message(s)`,
        modified: describeLines(results, "🏷️"),
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
        "(requires DATABASE_URL — Railway Postgres; a background check runs every minute). Without Postgres " +
        "the messages are still archived but auto-restore is unavailable — the result's `persisted` field " +
        "says which happened, so this is never silently false advertising. " +
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
      const results = await mapWithLimit(items, async (item) => {
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
            // userToken is null for onboarded (native-OAuth) deployments — that's
            // expected, not a reason to skip persisting; accountName alone is
            // enough for the scheduler to find the right Google account later.
            if (store) {
              const accountName = clients.canonicalName(account);
              await store.addSnooze({
                userToken,
                accountName,
                messageId: item.messageId,
                unsnoozeAt,
              });
            }
            return {
              id: item.messageId,
              unsnoozeAt: unsnoozeAt.toISOString(),
              persisted: !!store,
            };
          } catch (e) {
            return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
          }
        });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `⏰ Snoozed ${ok_.length}/${items.length} message(s)`,
        results,
      });
    }),
  );

  // ---- gmail_schedule_send / gmail_list_scheduled_sends / gmail_cancel_scheduled_send ----
  //
  // Gmail's own API has no "send later" parameter — verified against the
  // official users.messages.send reference, which takes no delay/schedule
  // field at all. This is this server holding the message itself and sending
  // it for real, on time, from its own always-on process; Gmail never knows it
  // was ever delayed.

  server.registerTool(
    "gmail_schedule_send",
    {
      title: "Schedule an email to send later",
      description:
        "Compose one or more emails now, but hold them and actually send each at its own `sendAt` time " +
        "(requires DATABASE_URL — Railway Postgres; a background check runs every minute, so delivery can be up " +
        "to ~1 minute late, never early). Gmail itself has no delayed-send API — this works because the message " +
        "is fully built and validated right now (attachments resolved, addresses checked) and stored ready to go, " +
        "so nothing can fail at send time except Gmail itself being briefly down. " +
        "Use gmail_list_scheduled_sends to check what's pending and gmail_cancel_scheduled_send to pull one back " +
        "before it fires. Without DATABASE_URL this tool cannot work at all — say so plainly rather than pretending.",
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
              sendAt: z.string().describe("ISO 8601 datetime to send at, e.g. '2026-07-28T08:00:00-07:00'. Must be in the future."),
            }),
          )
          .min(1),
      },
    },
    guard(async ({ account, messages }) => {
      const { store, userToken } = snoozeCtx;
      if (!store) {
        return fail(
          "Scheduled send requires DATABASE_URL (Railway Postgres) to be configured on this server — " +
            "without it there is nowhere to hold the message until sendAt. Use gmail_send for immediate delivery.",
        );
      }
      // Fail-fast on an unknown account label BEFORE anything is queued: both
      // resolve() and canonicalName() throw the same "❌ Неизвестный аккаунт …
      // Доступные: personal (email), …" error naming labels AND emails, so an
      // incident-1-style typo ("maksim.donskikh" instead of "work") is caught
      // here, at call time — not an hour later in the background scheduler.
      // canonicalName also stores the resolved canonical label (never a stray
      // "" from `account ?? default`), closing the :resolve/:accountName drift.
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);
      const results = await mapWithLimit(messages, async (msg) => {
        try {
          const sendAt = new Date(msg.sendAt);
          if (isNaN(sendAt.getTime())) {
            return { to: msg.to, subject: msg.subject, error: `Cannot parse date "${msg.sendAt}". Use ISO 8601.` };
          }
          if (sendAt <= new Date()) {
            return { to: msg.to, subject: msg.subject, error: `sendAt "${msg.sendAt}" is already in the past.` };
          }
          // Resolve attachments and build the raw MIME NOW, so a bad driveFileId
          // or an over-quota Drive fails this call instead of silently rotting
          // in the queue until sendAt.
          const atts = msg.attachments?.length ? await resolveAttachments(g, msg.attachments) : undefined;
          const raw = buildRawEmail({ to: msg.to, subject: msg.subject, body: msg.body, cc: msg.cc, bcc: msg.bcc, attachments: atts });
          const id = await store.addScheduledSend({
            userToken,
            accountName,
            rawMessage: raw,
            toPreview: msg.to,
            subjectPreview: msg.subject,
            sendAt,
          });
          return { id, to: msg.to, subject: msg.subject, sendAt: sendAt.toISOString() };
        } catch (e) {
          return { to: msg.to, subject: msg.subject, error: String(e instanceof Error ? e.message : e) };
        }
      });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🕗 Scheduled ${ok_.length}/${messages.length} message(s)`,
        results,
      });
    }),
  );

  server.registerTool(
    "gmail_list_scheduled_sends",
    {
      title: "List emails waiting to be sent",
      description:
        "List messages queued by gmail_schedule_send, soonest first. By default shows only `pending` (still waiting). " +
        "Pass `status` to inspect other states: `failed` (send failed — includes the full error; e.g. a bad account " +
        "label or a process that died mid-send), `sending` (currently being sent), `sent`, `canceled`, or `all`. " +
        "Even a default (`pending`) call warns you when failed sends exist, so a silently-failed send can't hide.",
      inputSchema: {
        account,
        status: z
          .enum(["pending", "failed", "sending", "sent", "canceled", "all"])
          .default("pending")
          .optional()
          .describe("Which sends to list. Default 'pending'. Use 'failed' to see sends that did not go out."),
      },
      annotations: { readOnlyHint: true },
    },
    guard(async ({ account, status }) => {
      const { store } = snoozeCtx;
      if (!store) {
        return ok({ summary: "No scheduled sends — DATABASE_URL is not configured, so nothing can be queued.", results: [] });
      }
      const accountName = clients.canonicalName(account);
      const wanted = status ?? "pending";
      const rows = await store.listScheduledSends(accountName, wanted);
      // Always surface the failed count, even on a default 'pending' call — a
      // failed send that no one looks at is exactly how incident 1 stayed hidden.
      const failedCount = await store.countScheduledSends(accountName, "failed");
      const note =
        failedCount > 0 && wanted !== "failed"
          ? `⚠️ есть ${failedCount} провалившаяся(ихся) отправка(ок) — посмотрите status='failed'.`
          : undefined;
      return ok({
        summary: `🕗 ${rows.length} message(s) with status='${wanted}'`,
        ...(note ? { note } : {}),
        results: rows.map((r) => ({
          id: r.id,
          to: r.toPreview,
          subject: r.subjectPreview,
          sendAt: r.sendAt.toISOString(),
          status: r.status ?? wanted,
          // Show the full error for anything that failed, so the reason is visible.
          ...(r.error ? { error: r.error } : {}),
          ...(r.sentMessageId ? { sentMessageId: r.sentMessageId } : {}),
        })),
      });
    }),
  );

  server.registerTool(
    "gmail_cancel_scheduled_send",
    {
      title: "Cancel a scheduled email",
      description: "Cancel one or more messages queued by gmail_schedule_send, as long as they have not already gone out.",
      inputSchema: {
        account,
        ids: z.array(z.number().int()).min(1).describe("Ids from gmail_list_scheduled_sends."),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, ids }) => {
      const { store } = snoozeCtx;
      if (!store) {
        return fail("DATABASE_URL is not configured, so there is nothing scheduled to cancel.");
      }
      const accountName = clients.canonicalName(account);
      const results = await mapWithLimit(ids, async (id) => {
        const canceled = await store.cancelScheduledSend(id, accountName);
        return canceled
          ? { id, canceled: true as const }
          : { id, canceled: false as const, error: "Already sent, already canceled, or unknown id." };
      });
      const ok_ = results.filter((r) => r.canceled);
      return ok({
        summary: `🚫 Canceled ${ok_.length}/${ids.length} scheduled send(s)`,
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
      const results = await mapWithLimit(items, async (item) => {
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
        });
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
      const results = await mapWithLimit(items, async (item) => {
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
        });
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
      const results = await mapWithLimit(items, async (item) => {
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
        });
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
      const results = await mapWithLimit(labels, async (l) => {
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
        });
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
      const results = await mapWithLimit(items, async (item) => {
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
        });
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
      const results = await mapWithLimit(labelIds, async (id) => {
          try {
            await g.gmail.users.labels.delete({ userId: "me", id });
            return { id };
          } catch (e) {
            return { id, error: String(e instanceof Error ? e.message : e) };
          }
        });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `🗑️ Deleted ${ok_.length}/${labelIds.length} label(s)`,
        results,
      });
    }),
  );

  // ---- gmail_export_thread_eml ---------------------------------------------

  server.registerTool(
    "gmail_export_thread_eml",
    {
      title: "Export a thread as .eml originals",
      description:
        "Export every message in a Gmail thread as a TRUE, unmodified RFC 822 .eml file " +
        "(via Gmail API format=raw) and save them to Google Drive — the legally-clean original " +
        "with all headers intact, not a reconstruction. Optionally combine the whole thread into " +
        "one .mbox archive. Get threadId from gmail_search or gmail_get_thread.",
      inputSchema: {
        account,
        threadId: z.string().describe("Gmail thread id to export (also accepts a single message's threadId)."),
        folderId: z.string().optional().describe("Destination Drive folder id (defaults to Drive root)."),
        folderName: z
          .string()
          .optional()
          .describe("If set, create a new Drive subfolder with this name and save the export into it."),
        format: z
          .enum(["eml_files", "mbox"])
          .default("eml_files")
          .optional()
          .describe(
            "'eml_files' = one standalone .eml per message (each a self-contained original); " +
              "'mbox' = one combined .mbox archive of the whole thread.",
          ),
        scope: z
          .enum(["all", "last", "first"])
          .default("all")
          .optional()
          .describe(
            "Which messages of the thread to export: 'all' = every message (default); " +
              "'last' = only the most recent message; 'first' = only the original message. " +
              "With 'last'/'first' a single .eml is written, named without the NN_ prefix.",
          ),
      },
    },
    guard(async ({ account, threadId, folderId, folderName, format, scope }) => {
      const g = clients.resolve(account);
      // threads.get does NOT support format=raw (only messages.get does), so do
      // it in two steps: list the thread's message ids, then pull each message
      // with format=raw. That raw field is the full RFC 822 source (base64url) —
      // the real bytes Google received, headers and all — which is what makes
      // the export a genuine original rather than a re-serialised reconstruction.
      const stub = await g.gmail.users.threads.get({ userId: "me", id: threadId, format: "minimal" });
      const ids = (stub.data.messages ?? []).map((m) => m.id).filter((x): x is string => !!x);
      if (!ids.length) return fail(`Thread ${threadId} has no messages (check the threadId).`);
      const allMessages = await mapWithLimit(ids, (id) =>
          g.gmail.users.messages.get({ userId: "me", id, format: "raw" }).then((r) => r.data),);
      // threads.get returns messages oldest-first, so [0] is the original and
      // the last element is the most recent.
      const messages =
        scope === "last"
          ? [allMessages[allMessages.length - 1]]
          : scope === "first"
            ? [allMessages[0]]
            : allMessages;

      // Optionally drop everything into a fresh Drive subfolder.
      let parentId = folderId;
      if (folderName) {
        const folder = await g.drive.files.create({
          requestBody: {
            name: folderName,
            mimeType: "application/vnd.google-apps.folder",
            parents: folderId ? [folderId] : undefined,
          },
          fields: "id",
        });
        parentId = folder.data.id ?? folderId;
      }

      const rawBuf = (m: gmail_v1.Schema$Message) => Buffer.from(m.raw ?? "", "base64url");

      if (format === "mbox") {
        const parts: Buffer[] = [];
        for (const m of messages) {
          const raw = rawBuf(m);
          parts.push(Buffer.from(mboxFromLine(raw.toString("latin1")), "latin1"));
          parts.push(escapeMboxFrom(raw));
          parts.push(Buffer.from("\n", "latin1"));
        }
        const mbox = Buffer.concat(parts);
        const subj = decodeMimeWords(headerFromRaw(rawBuf(messages[0]).toString("latin1"), "Subject")) || threadId;
        const res = await g.drive.files.create({
          requestBody: { name: `${sanitizeName(subj)}.mbox`, parents: parentId ? [parentId] : undefined },
          media: { mimeType: "application/mbox", body: Readable.from(mbox) },
          fields: "id,name,webViewLink,size",
        });
        return ok({
          summary: `📧 Exported thread ${threadId} (${messages.length} message(s)) as one .mbox to Drive`,
          folderId: parentId ?? null,
          file: { id: res.data.id, name: res.data.name, link: res.data.webViewLink, bytes: res.data.size },
        });
      }

      // eml_files: one standalone .eml per message.
      const files = await mapWithLimit(messages, async (m, i) => {
          try {
            const buf = rawBuf(m);
            const raw = buf.toString("latin1");
            const stamp = dateStamp(headerFromRaw(raw, "Date"));
            const subj = decodeMimeWords(headerFromRaw(raw, "Subject")) || "no-subject";
            // Single-message export (scope last/first, or a one-message thread):
            // no NN_ index prefix, so there's no lone "01_" on a single file.
            const prefix = messages.length > 1 ? `${String(i + 1).padStart(2, "0")}_` : "";
            const name = `${prefix}${stamp ? stamp + "_" : ""}${sanitizeName(subj)}.eml`;
            const res = await g.drive.files.create({
              requestBody: { name, parents: parentId ? [parentId] : undefined },
              media: { mimeType: "message/rfc822", body: Readable.from(buf) },
              fields: "id,name,webViewLink,size",
            });
            return { messageId: m.id, name: res.data.name, id: res.data.id, link: res.data.webViewLink, bytes: res.data.size };
          } catch (e) {
            return { messageId: m.id, error: String(e instanceof Error ? e.message : e) };
          }
        });
      const good = files.filter((f) => !("error" in f));
      return ok({
        summary: `📧 Exported ${good.length}/${messages.length} message(s) of thread ${threadId} as .eml originals to Drive`,
        folderId: parentId ?? null,
        files,
      });
    }),
  );

  // ---- gmail_get_download_url (array) --------------------------------------

  server.registerTool(
    "gmail_get_download_url",
    {
      title: "Get a temporary link to an attachment",
      description:
        "Return a temporary download link per attachment so the client (phone, browser, script) can fetch the " +
        "bytes directly, instead of gmail_get_attachment inlining them into this conversation. Use it for anything " +
        "large or binary, or whenever the user wants to keep the file rather than read its content here. " +
        "Get `attachmentId` from gmail_get_message; filename and type are looked up automatically when omitted. " +
        "The link IS the credential: anyone holding it can fetch that one attachment until it expires " +
        `(default ${DEFAULT_TTL_MINUTES} minutes, max ${MAX_TTL_MINUTES / 60} hours), so pass it only to the person who ` +
        "asked. It grants access to that single attachment — not to the message, and not to the mailbox.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string(),
              attachmentId: z.string(),
              filename: z.string().optional().describe("Overrides the name the file is saved under."),
              mimeType: z.string().optional(),
            }),
          )
          .min(1),
        ttlMinutes: z
          .number()
          .int()
          .min(1)
          .max(MAX_TTL_MINUTES)
          .optional()
          .describe(`How long each link stays valid. Default ${DEFAULT_TTL_MINUTES} minutes.`),
      },
      annotations: { readOnlyHint: true },
    },
    guard(async ({ account, items, ttlMinutes }) => {
      if (!downloadsAvailable()) {
        return fail(
          "Download links are unavailable: this server does not know its own public URL. " +
            "Set PUBLIC_BASE_URL (on Railway, turn on public networking). " +
            "gmail_get_attachment still works for small attachments.",
        );
      }
      const g = clients.resolve(account);
      const results = await mapWithLimit(items, async (item) => {
        try {
          let { filename, mimeType } = item;
          let size: number | undefined;
          // Fill in whatever the caller did not pass by looking at the message itself.
          if (!filename || !mimeType) {
            const msg = await g.gmail.users.messages.get({
              userId: "me",
              id: item.messageId,
              format: "full",
            });
            const found = collectAttachments(msg.data.payload).find(
              (a) => a.attachmentId === item.attachmentId,
            );
            filename = filename ?? found?.filename;
            mimeType = mimeType ?? found?.mimeType;
            size = found?.size;
          }
          const { url, expiresAt } = await issueDownloadLink(
            {
              account: clients.canonicalName(account),
              messageId: item.messageId,
              attachmentId: item.attachmentId,
              name: filename || "attachment",
              mimeType: mimeType ?? "application/octet-stream",
              size,
            },
            ttlMinutes ?? DEFAULT_TTL_MINUTES,
          );
          return {
            messageId: item.messageId,
            attachmentId: item.attachmentId,
            filename: filename || "attachment",
            mimeType: mimeType ?? "application/octet-stream",
            bytes: size ?? null,
            downloadUrl: url,
            expiresAt,
          };
        } catch (e) {
          return {
            messageId: item.messageId,
            attachmentId: item.attachmentId,
            error: String(e instanceof Error ? e.message : e),
          };
        }
      });
      const good = results.filter((r) => !("error" in r));
      return ok({
        summary: `🔗 Built ${good.length}/${items.length} download link(s)`,
        results,
        note: "Each link works without any further sign-in until it expires — treat it as a password for that one file.",
      });
    }),
  );

  // ---- gmail_create_upload_session / gmail_confirm_upload -------------------

  server.registerTool(
    "gmail_create_upload_session",
    {
      title: "Start a direct upload for a big attachment",
      description:
        "Open a resumable upload session so the client (phone, browser, script) can send a big file's bytes " +
        "straight to Google, then attach it to an email — instead of squeezing it through this conversation as " +
        "content_base64, which is only practical below ~1MB. " +
        "The bytes go to Drive, not to Gmail: Gmail's own upload endpoint only accepts a complete MIME message, " +
        "so it cannot take a bare file from a client. The file lands in a '" +
        UPLOAD_FOLDER_NAME +
        "' folder in your Drive and its id comes back immediately, so you can compose the mail before the upload " +
        "even finishes. " +
        "Flow: call this → client PUTs the bytes to uploadUrl → (optional) gmail_confirm_upload → " +
        "gmail_send/gmail_reply/gmail_create_draft with attachments: [{driveFileId}]. " +
        "The uploadUrl carries its own authorisation — treat it as a secret; it stays valid for about a week. " +
        "The staged file stays in Drive afterwards; delete it there if you do not want a copy.",
      inputSchema: {
        account,
        files: z
          .array(
            z.object({
              name: z.string().describe("File name as it should appear on the email, e.g. 'contract.pdf'."),
              mimeType: z
                .string()
                .optional()
                .describe("Content type the client will send. Default octet-stream."),
              sizeBytes: z
                .number()
                .int()
                .positive()
                .optional()
                .describe("Total size in bytes, if known — lets Google reject an oversized upload up front."),
            }),
          )
          .min(1)
          .describe("Array of files to open upload sessions for."),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, files }) => {
      const g = clients.resolve(account);
      const token = await g.accessToken();
      const folderId = await ensureUploadFolder(g);
      const results = await mapWithLimit(files, async ({ name, mimeType, sizeBytes }) => {
        try {
          const contentType = mimeType ?? "application/octet-stream";
          // Create the (empty) file first so its id is known up front — the model
          // can then write the email without waiting for the bytes to arrive.
          const placeholder = await g.drive.files.create({
            requestBody: {
              name,
              parents: [folderId],
              appProperties: { gmailMcpUpload: "1" },
            },
            fields: "id",
          });
          const fileId = placeholder.data.id;
          if (!fileId) throw new Error("Drive did not return a file id for the staged upload.");

          const res = await fetch(
            `${DRIVE_UPLOAD_ENDPOINT}/${encodeURIComponent(fileId)}?uploadType=resumable&fields=id,name,size`,
            {
              method: "PATCH",
              headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json; charset=UTF-8",
                "X-Upload-Content-Type": contentType,
                ...(sizeBytes ? { "X-Upload-Content-Length": String(sizeBytes) } : {}),
              },
              body: "{}",
            },
          );
          if (!res.ok) {
            return { name, error: `Google refused the session (HTTP ${res.status}): ${(await res.text()).slice(0, 500)}` };
          }
          const uploadUrl = res.headers.get("location");
          if (!uploadUrl) {
            return { name, error: "Google accepted the request but returned no Location header (no session URI)." };
          }
          return {
            name,
            driveFileId: fileId,
            uploadUrl,
            mimeType: contentType,
            sizeBytes: sizeBytes ?? null,
            howTo:
              `PUT ${uploadUrl} with header "Content-Type: ${contentType}"` +
              (sizeBytes ? ` and "Content-Length: ${sizeBytes}"` : "") +
              ", body = the raw file bytes.",
            thenSend: `Attach it with attachments: [{"driveFileId": "${fileId}"}].`,
          };
        } catch (e) {
          return { name, error: String(e instanceof Error ? e.message : e) };
        }
      });
      const good = results.filter((r) => !("error" in r));
      return ok({
        summary: `🚀 Opened ${good.length}/${files.length} upload session(s)`,
        results,
        note:
          "Gmail will only carry the attachment once the client has PUT the bytes — a message sent before that " +
          "would go out with an empty file. Check with gmail_confirm_upload when in doubt. " +
          "Gmail caps a whole message at 25 MB.",
      });
    }),
  );

  server.registerTool(
    "gmail_confirm_upload",
    {
      title: "Check a direct upload",
      description:
        "Ask Google how an upload started by gmail_create_upload_session is doing. Reports `complete` (the file is " +
        "ready to attach), `in_progress` (how many bytes arrived, so the client knows where to resume), or " +
        "`expired` (session gone — open a new one). Uploads nothing itself.",
      inputSchema: {
        uploads: z
          .array(
            z.object({
              uploadUrl: z.string().describe("Session URI returned by gmail_create_upload_session."),
              sizeBytes: z
                .number()
                .int()
                .positive()
                .optional()
                .describe("Total size, if known — makes the status query exact."),
            }),
          )
          .min(1),
      },
      annotations: { readOnlyHint: true },
    },
    guard(async ({ uploads }) => {
      const results = await mapWithLimit(uploads, async ({ uploadUrl, sizeBytes }) => {
        try {
          // An empty PUT with "bytes */total" asks for status instead of sending
          // content; the session URI carries its own authorisation.
          const res = await fetch(uploadUrl, {
            method: "PUT",
            headers: { "Content-Range": `bytes */${sizeBytes ?? "*"}` },
          });
          if (res.status === 200 || res.status === 201) {
            let file: { id?: string; name?: string; size?: string } = {};
            try {
              file = JSON.parse(await res.text());
            } catch {
              /* Google answered without a usable body — the id simply isn't there. */
            }
            return {
              uploadUrl,
              status: "complete" as const,
              driveFileId: file.id ?? null,
              name: file.name ?? null,
              size: file.size ?? null,
            };
          }
          if (res.status === 308) {
            // "Range: bytes=0-<last>" — absent when nothing has arrived yet.
            const range = res.headers.get("range");
            const last = range ? Number(range.split("-")[1]) : NaN;
            const bytesReceived = Number.isFinite(last) ? last + 1 : 0;
            return { uploadUrl, status: "in_progress" as const, bytesReceived, resumeFrom: bytesReceived };
          }
          if (res.status === 404 || res.status === 410) {
            return {
              uploadUrl,
              status: "expired" as const,
              error: "Google no longer knows this session (expired, cancelled, or finished long ago). Open a new one.",
            };
          }
          return { uploadUrl, error: `Unexpected status ${res.status}: ${(await res.text()).slice(0, 500)}` };
        } catch (e) {
          return { uploadUrl, error: String(e instanceof Error ? e.message : e) };
        }
      });
      return ok({
        summary: `📶 Checked ${uploads.length} upload session(s)`,
        results,
      });
    }),
  );
}
