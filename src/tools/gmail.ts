/**
 * Gmail tools: read / analyse / send / reply / archive / trash / labels.
 * Array-first: every item-based tool accepts arrays; batch_ duplicates removed.
 */
import { z } from "zod";
import { Readable } from "node:stream";
import dns from "node:dns/promises";
import net from "node:net";
import { Agent as UndiciAgent, fetch as pinnedFetch } from "undici";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { gmail_v1 } from "googleapis";
import {
  ok,
  okVerbatim,
  fail,
  guard,
  isTextual,
  mapWithLimit,
  safeText,
  safeBlock,
  laIso,
  laDateStamp,
  plural,
} from "../util.js";
import { accountField, type UserClients } from "../accounts.js";
import type { GoogleClients } from "../google.js";
import { documentToPlainText } from "./docs.js";
import {
  requireConsent,
  sha256,
  formatLaTime,
  USER_REPLY_DOC,
  type ConsentStore,
  type ConsentConfig,
  type ConsentPlan,
  type TgApprovalGate,
} from "../consent.js";
import {
  issueDownloadLink,
  resolveDownloadLink,
  downloadsAvailable,
  DEFAULT_TTL_MINUTES,
  MAX_TTL_MINUTES,
} from "../downloads.js";
import { rememberUploadSession, resolveUploadSession } from "../uploadSessions.js";
import {
  safeGoogleFetch,
  assertAllowedGoogleUrl,
  isBlockedIp,
  pinnedLookup,
  type SafeFetchDeps,
} from "../safeFetch.js";
import { registerAutoExecutor, type AutoExecutorCtx } from "../autoExecute.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
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

/** One row of the shared consent_audit log, as read by `gmail_consent_audit`
 * (package A4). Mirrors store.ts's `ConsentAuditRow` structurally — the same
 * "don't import store.ts directly, context provides adapters" convention as
 * `PgStore` above; `server.ts` wires the real implementation in. */
interface ConsentAuditRow {
  id: string;
  ts: number;
  tool: string;
  accountLabel: string;
  manifestId?: string | null;
  objectHash?: string | null;
  userReply: string;
  outcome: string;
  refusalReason?: string | null;
  actor: string;
  postVerifyResult: string | null;
  error: string | null;
  preSnapshot: unknown;
}

interface ConsentAuditFilters {
  server: string;
  since?: number;
  until?: number;
  accountLabel?: string;
  tool?: string;
  outcome?: string;
}

/** Read-only access to the consent-gate audit log (package A4, `[R:полнота-1]`
 * — "разбор инцидента без ssh"). Separate from `PgStore`/`ConsentStore` above:
 * this is neither the scheduled-send store nor the plan/execute gate, just a
 * read path over the same `consent_audit` table A1 already writes to. */
interface AuditStore {
  listConsentAudit(filters: ConsentAuditFilters, limit?: number, offset?: number): Promise<ConsentAuditRow[]>;
  countConsentAudit(filters: ConsentAuditFilters): Promise<number>;
}

const GOOGLE_DOC_MIME = "application/vnd.google-apps.document";

// ── OCR scratch file: identity guard + honest cleanup ──────────────────────
//
// Google's OCR has no "read the text" endpoint: the only way in is to create a
// Google Doc, i.e. a REAL file materialised in the owner's Drive (quota,
// activity feed, "Recent"). That makes gmail_get_attachment_text a write,
// however read-shaped it looks from outside — see its registration below for
// why it nonetheless stays ungated and what has to hold for that to be safe.

/** Name every OCR scratch doc carries — also the identity guard's marker. */
const OCR_TEMP_NAME = "gmcp-ocr-tmp";

/** A temp OCR file that is STILL IN THE USER'S DRIVE after the call. */
interface OcrCleanupFailure {
  tempFileId: string;
  /** Why it could not be cleaned up — verbatim, never swallowed. */
  error: string;
}

/**
 * Moves the temporary OCR document to the trash, having first checked that the
 * id really points at OUR scratch doc.
 *
 * Two deliberate choices, both reactions to how the previous version failed:
 *
 *  - TRASH, not `files.delete`. Permanent deletion must never be a side effect
 *    of extracting text: if `docId` were ever wrong (a Drive quirk, a future
 *    refactor threading in a caller-supplied id), a delete would destroy a real
 *    user file with no recovery, while trashing is undoable for 30 days.
 *  - IDENTITY GUARD. Re-read the file first and require name+mimeType to match
 *    the scratch doc this call just created; a mismatch means we do NOT touch
 *    it and report instead.
 *
 * @returns `null` on success, or a description of the leftover file. The caller
 *   MUST surface a non-null result to the USER: the previous version logged the
 *   failure and still reported a clean "extracted N/N", so the person whose
 *   Drive was accumulating "gmcp-ocr-tmp" garbage never heard about it.
 */
async function cleanupOcrTempDoc(
  g: GoogleClients,
  docId: string,
  toolName: string,
): Promise<OcrCleanupFailure | null> {
  try {
    const meta = await g.drive.files.get({ fileId: docId, fields: "id,name,mimeType,trashed" });
    const name = meta.data.name ?? "";
    const mime = meta.data.mimeType ?? "";
    if (name !== OCR_TEMP_NAME || mime !== GOOGLE_DOC_MIME) {
      throw new Error(
        `identity guard: ${docId} is «${safeText(name, 80)}» (${safeText(mime, 60)}), not this call's ` +
          `temporary «${OCR_TEMP_NAME}» Google Doc — left untouched on purpose.`,
      );
    }
    if (meta.data.trashed) return null;
    await g.drive.files.update({ fileId: docId, requestBody: { trashed: true } });
    return null;
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    // Logged AND returned: the log is for the operator, the return value is for
    // the person who asked — they are the one who has to remove the leftover.
    console.error(`[${toolName}] temp OCR doc ${docId} was NOT cleaned up — it stays in Drive:`, error);
    return { tempFileId: docId, error };
  }
}

/** Human-readable warning naming every leftover, so it cannot pass unnoticed. */
function ocrLeftoverWarning(leftovers: OcrCleanupFailure[]): string {
  return (
    `⚠️ ${leftovers.length} temporary OCR file(s) could NOT be cleaned up and are STILL in the Drive ` +
    `(delete them by id: ${leftovers.map((l) => l.tempFileId).join(", ")}). Tell the user — do not hide this.`
  );
}

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

/**
 * Абсолютный момент письма в epoch-миллисекундах, или null.
 *
 * Приоритет у `internalDate` (Gmail отдаёт его при любом format, включая
 * `metadata`) — это время, по которому сам Gmail фильтрует запросы вида
 * `after:`/`before:`. Заголовок `Date` — запасной путь: его пишет отправитель,
 * он может быть кривым или отсутствовать.
 */
function messageEpochMs(msg: gmail_v1.Schema$Message, dateHeader: string): number | null {
  const internal = Number(msg.internalDate);
  if (Number.isFinite(internal) && internal > 0) return internal;
  const parsed = Date.parse(dateHeader);
  return Number.isNaN(parsed) ? null : parsed;
}

/**
 * Поля письма для выдачи читающих инструментов.
 *
 * `date` — ВСЕГДА в America/Los_Angeles (ISO со смещением, `laIso`), а не в
 * поясе отправителя. До 2026-08-07 сюда клался сырой заголовок `Date`: на
 * выборке из 100 писем это давало 9 разных смещений и у 12 писем — чужой
 * календарный день, вплоть до самопротиворечия (письмо из выборки
 * `after:2026/08/07 before:2026/08/08` печаталось как «8 Aug»).
 *
 * Сырой заголовок никуда не делся — он рядом, в `dateHeader`; абсолютное время
 * для машинной сортировки — в `internalDate`. Если время не удалось установить
 * вообще, `date` пустой: выдавать за LA то, что к LA не приведено, нельзя.
 */
function summarise(msg: gmail_v1.Schema$Message) {
  const h = msg.payload?.headers;
  const dateHeader = header(h, "Date");
  const ms = messageEpochMs(msg, dateHeader);
  return {
    id: msg.id,
    threadId: msg.threadId,
    from: header(h, "From"),
    to: header(h, "To"),
    subject: header(h, "Subject"),
    date: ms === null ? "" : laIso(ms),
    dateHeader,
    internalDate: ms,
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
  // subject/from/snippet/error are all externally-controlled — neutralise each
  // through safeText so a crafted email can't forge status lines in this output.
  return results.map((r) =>
    r.error
      ? `⚠️ ${r.id}: ${safeText(r.error)}`
      : `${icon} «${safeText(r.subject) || "(без темы)"}» — ${safeText(r.from) || "?"}${r.snippet ? `: ${safeText(r.snippet, 140)}` : ""}`,
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

// ---- Post-verify for sends (references/identity-postverify.md §5) -----------
//
// A 200 OK from messages.send means "Gmail accepted it", NOT "it went to the
// right place". After every send the server makes a SEPARATE metadata read of
// the new message and checks it independently: the classic self-send tell is
// labelIds ⊇ {SENT, INBOX} (a reply to your own message comes back to you —
// incident 2). The report is built here, sanitised through safeText (S1), and
// glued onto the tool response by the server. Fail-closed: any ❌ keeps the
// summary off "sent".

export type PostVerifyOutcome = "ok" | "warn" | "mismatch";

export interface PostVerifyResult {
  outcome: PostVerifyOutcome;
  messageId: string;
  /** One ready-made §5.3 bullet line (external text already run through safeText). */
  line: string;
  /** Machine-readable detail for the per-item results array. */
  detail: string;
}

/** Resolves a promise or rejects after ms — so a hung messages.get can't hang the tool. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}

const POST_VERIFY_TIMEOUT_MS = 10_000;

/**
 * Independently verifies one just-sent message with a fresh metadata read.
 * `expectedTo` is the recipient the caller intended; `selfEmail` (when known)
 * is this account's own address. Never throws — a read failure/timeout yields
 * a ⚠️ "not verified", not a broken send. Exported for testing.
 */
export async function postVerifySend(
  g: GoogleClients,
  messageId: string,
  expectedTo: string,
  selfEmail?: string,
  timeoutMs: number = POST_VERIFY_TIMEOUT_MS,
): Promise<PostVerifyResult> {
  const expected = extractEmail(expectedTo);
  if (!messageId) {
    return {
      outcome: "warn",
      messageId: "",
      line: `- ⚠️ **«${safeText(expectedTo)}»** — Gmail не вернул id письма, отправку не удалось перепроверить`,
      detail: "no message id returned",
    };
  }
  let subject = "";
  let toHeader = "";
  let labelIds: string[] = [];
  try {
    const r = await withTimeout(
      g.gmail.users.messages.get({
        userId: "me",
        id: messageId,
        format: "metadata",
        metadataHeaders: ["To", "Cc", "Bcc", "Subject", "From"],
      }),
      timeoutMs,
      "post-verify messages.get",
    );
    const h = r.data.payload?.headers;
    subject = header(h, "Subject");
    toHeader = header(h, "To");
    labelIds = r.data.labelIds ?? [];
  } catch (e) {
    return {
      outcome: "warn",
      messageId,
      line: `- ⚠️ **«${safeText(subject) || safeText(expectedTo)}»** — не удалось перепроверить (${safeText(e instanceof Error ? e.message : String(e), 60)}); письмо могло уйти, пруфа нет`,
      detail: "read failed/timed out",
    };
  }
  const subjLabel = safeText(subject) || "(без темы)";
  const actualTo = safeText(toHeader) || "(?)";
  const inSent = labelIds.includes("SENT");
  const inInbox = labelIds.includes("INBOX");
  // Primary tell of incident 2: a message both SENT and in the INBOX went to
  // the account itself. Also flag it when the actual To resolves to selfEmail.
  const actualToAddr = extractEmail(toHeader);
  const selfSend = (inSent && inInbox) || (!!selfEmail && !!actualToAddr && actualToAddr === selfEmail.toLowerCase());
  if (selfSend) {
    return {
      outcome: "mismatch",
      messageId,
      line: `- ❌ **«${subjLabel}»** — ушло ВАМ ЖЕ (в отправленных И во входящих${selfEmail ? `, To=${safeText(selfEmail)}` : ""}); проверьте адресата — похоже на ответ самому себе`,
      detail: "self-send: labels SENT+INBOX",
    };
  }
  if (!inSent) {
    return {
      outcome: "warn",
      messageId,
      line: `- ⚠️ **«${subjLabel}»** — письма пока нет в «Отправленных» (метка SENT не проставилась); возможна задержка Gmail, перепроверьте`,
      detail: "no SENT label yet",
    };
  }
  // Recipient sanity: if the intended address is nowhere in the actual To, warn
  // (aliases/lists make a hard mismatch too noisy — self-send above is the hard ❌).
  if (expected && actualToAddr && !toHeader.toLowerCase().includes(expected)) {
    return {
      outcome: "warn",
      messageId,
      line: `- ⚠️ **«${subjLabel}»** — в отправленном To=${actualTo}, ожидался ${safeText(expectedTo)}; сверьте адресата`,
      detail: "recipient differs from expected",
    };
  }
  return {
    outcome: "ok",
    messageId,
    line: `- ✅ **«${subjLabel}»** — в «Отправленных», To: ${actualTo}`,
    detail: "confirmed in Sent",
  };
}

/**
 * Now, formatted for America/Los_Angeles.
 *
 * Суффикс — «PT», а НЕ «America/Los_Angeles»: подпись отчёта обрамляется
 * `_…_` (курсив), а конвертер markdown→Telegram-HTML намеренно не курсивит
 * подчёркивания внутри слова (иначе ломались бы имена файлов вида
 * `n8n_email_report.md`). Из-за `Los_Angeles` вся строка подписи уезжала в
 * Telegram как есть, с голыми подчёркиваниями. «PT» — тот же формат, что уже
 * используется в превью планов (`formatLaTime(...) PT`).
 */
function nowInLA(): string {
  return new Date().toLocaleString("sv-SE", { timeZone: "America/Los_Angeles" }) + " PT";
}

/**
 * One §5.3 renderer for the WHOLE file (output-format.md §7.1 p.5: "an
 * instrument hand-rolling its own status string is a defect"). `renderPostVerifyReport`
 * below (the 4 send tools) and every T1 mutation (trash/archive/labels/Drive
 * writes, package T1) go through this SAME function with their own
 * title/subtitle — the ✅/⚠️/❌ shape is defined once.
 * `results` only needs `{outcome, line}` — `PostVerifyResult` (extra
 * `messageId`/`detail` fields) satisfies this structurally, no cast needed.
 *
 * ЗДЕСЬ БОЛЬШЕ НЕТ хвоста «[агенту: перепечатай … ДОСЛОВНО]». Это была
 * инструкция модели, вшитая в данные; «не пересказывать» теперь выражено
 * `_meta`-флагом ответа (`okVerbatim(..., "execution-report")`), см.
 * `PRESENTATION_META_KEY` в util.ts. Внутри отчёта — только факты.
 */
interface VerifyLine {
  outcome: PostVerifyOutcome;
  line: string;
}

function renderVerifyReport(title: string, subtitle: string, results: VerifyLine[]): string {
  const okN = results.filter((r) => r.outcome === "ok").length;
  const warnN = results.filter((r) => r.outcome === "warn").length;
  const mmN = results.filter((r) => r.outcome === "mismatch").length;
  const body = results.map((r) => r.line).join("\n");
  return (
    `### 🧾 ${title}\n` +
    `_${nowInLA()} · ${subtitle}_\n\n` +
    `${body}\n\n` +
    `**Итог: ✅ ${okN} подтверждено, ⚠️ ${warnN} не проверено, ❌ ${mmN} расхождение.**`
  );
}

/**
 * Собирает ГОТОВЫЙ ЧЕЛОВЕКОЧИТАЕМЫЙ отчёт об исполнении мутации.
 *
 * Инцидент 2026-08-06: оба билдера ниже возвращали `ok({summary, results,
 * verification})`, а `ok()` не-строку сериализует в `JSON.stringify(…, null, 2)`.
 * В обычном чате модель это ещё пересказывала, но АВТО-путь (кнопка «✅
 * Подтвердить» в Telegram → `autoExecute` → `extractText` → `editMessageText`)
 * отдаёт `content[0].text` человеку КАК ЕСТЬ — и Максим получил в чат сырой
 * JSON с фигурными скобками, ключами и экранированными `\n` внутри
 * `verification`. Планы приходили нормально ровно потому, что там в `ok()`
 * шла СТРОКА (`ok(decision.preview)`), а не объект.
 *
 * Поэтому текстом теперь становится сам отчёт, а машинные поля (messageId/
 * threadId/labelId…) не выбрасываются, а печатаются компактной строкой
 * «Детали» — без JSON-скобок, но без потери данных.
 */
function renderResultDetails(results: unknown[]): string[] {
  const MAX_ITEMS = 10;
  const lines: string[] = [];
  for (const r of results.slice(0, MAX_ITEMS)) {
    if (!r || typeof r !== "object") continue;
    const pairs = Object.entries(r as Record<string, unknown>)
      .filter(([k, v]) => k !== "error" && v !== null && v !== undefined && typeof v !== "object")
      .map(([k, v]) => `${safeText(k, 40)}: ${safeText(String(v), 120)}`);
    if (pairs.length) lines.push(`- ${pairs.join(" · ")}`);
  }
  if (results.length > MAX_ITEMS) lines.push(`- …ещё ${results.length - MAX_ITEMS}`);
  return lines;
}

function renderExecutionReport(opts: {
  summary: string;
  errors: string[];
  verification?: string;
  results: unknown[];
  note?: string;
  extra?: Record<string, unknown>;
}): string {
  const parts: string[] = [opts.summary];
  if (opts.errors.length) {
    parts.push(["**Ошибки:**", ...opts.errors.map((e) => `- ❌ ${safeText(e, 300)}`)].join("\n"));
  }
  if (opts.verification) parts.push(opts.verification);
  const details = renderResultDetails(opts.results);
  const extraLines = opts.extra ? renderResultDetails([opts.extra]) : [];
  if (details.length || extraLines.length) {
    parts.push(["_Детали:_", ...details, ...extraLines].join("\n"));
  }
  if (opts.note) parts.push(`⚠️ ${safeText(opts.note, 500)}`);
  return parts.join("\n\n");
}

/** Builds the §5.3 proof block from per-message post-verify results (server-glued). */
export function renderPostVerifyReport(results: PostVerifyResult[]): string {
  return renderVerifyReport("Независимая проверка отправки", "запрошено ⇄ «Отправленные» Gmail", results);
}

/** Worst outcome across a batch, for choosing the summary status. Only needs
 * `{outcome}` — accepts `PostVerifyResult[]`/`VerifyLine[]`/T1 verify results alike. */
export function worstOutcome(results: Array<{ outcome: PostVerifyOutcome }>): PostVerifyOutcome {
  if (results.some((r) => r.outcome === "mismatch")) return "mismatch";
  if (results.some((r) => r.outcome === "warn")) return "warn";
  return "ok";
}

// ---- Package T1: consent gate on priority-2 write tools --------------------
//
// Same requireConsent/plan→execute machinery as A3's 4 send tools, applied to
// gmail_archive/trash/modify_labels/create_label/update_label/delete_label/
// save_attachment_to_drive/export_thread_eml/create_upload_session/
// create_draft/snooze (Maksim's decision 2026-08-04: ALL write tools go
// behind the gate, no "it's reversible" exemptions). Two shared building
// blocks below cover the common "batch of existing message ids" shape
// (archive/trash/modify_labels/snooze); create_label/update_label/
// delete_label/save_attachment_to_drive/export_thread_eml/create_upload_session/
// create_draft each get their own plan()/rehash() (different live objects to
// re-read), but all funnel through the same `buildMutationResult` for the
// §5.3 report + phase-2 audit write.

/** subject/from/labelIds for a message, read fresh via a SEPARATE metadata
 * call (never trusts the caller to supply a title — same convention
 * `describeLines`/`fetchMeta` already use elsewhere in this file). `null` =
 * unreadable (deleted/no access) — callers turn that into a rehash MISMATCH
 * rather than silently trusting a stale plan (same pattern as gmail_reply/
 * gmail_forward's rehash above). labelIds costs nothing extra: Gmail always
 * returns it on the Message resource regardless of requested headers. */
interface MsgIdentity {
  subject: string;
  from: string;
  labelIds: string[];
}

async function fetchMsgIdentity(g: GoogleClients, ids: string[]): Promise<Map<string, MsgIdentity | null>> {
  const out = new Map<string, MsgIdentity | null>();
  await mapWithLimit(ids, async (id) => {
    try {
      const r = await g.gmail.users.messages.get({
        userId: "me",
        id,
        format: "metadata",
        metadataHeaders: ["From", "Subject"],
      });
      const s = summarise(r.data);
      out.set(id, { subject: s.subject, from: s.from, labelIds: s.labelIds });
    } catch {
      out.set(id, null);
    }
  });
  return out;
}

/** Live labelIds only (cheapest read) — used by the post-verify helpers below,
 * which run AFTER the mutation and only care about label state, not identity. */
async function fetchLabelIds(g: GoogleClients, id: string): Promise<string[] | null> {
  try {
    const r = await g.gmail.users.messages.get({ userId: "me", id, format: "minimal" });
    return r.data.labelIds ?? [];
  } catch {
    return null;
  }
}

interface IdBatchItem {
  id: string;
  subject: string;
  from: string;
  labelIds: string[];
}
interface IdBatchPayload {
  account: string;
  items: IdBatchItem[];
}

/** Projects an IdBatchPayload down to exactly {account, items:[{id,subject,from}]}
 * — the binding surface (plan §T1 item 4). `labelIds` rides along in the
 * payload for tools that need a pre-mutation snapshot (trash) but is
 * deliberately NOT part of the hash: it is expected to legitimately change
 * between plan and execute (that's the whole point of e.g. modify_labels). */
function idBatchHashPayload(p: IdBatchPayload) {
  return { account: p.account, items: p.items.map(({ id, subject, from }) => ({ id, subject, from })) };
}

/**
 * Builds a plan for the common "batch of existing message ids" gated
 * mutation (archive/trash/snooze; modify_labels/save_attachment_to_drive
 * build their own richer item shape but reuse `fetchMsgIdentity`/the same
 * hash convention). Refuses up front (throws — caught by `guard()`) if any id
 * is unreadable, so a typo'd/inaccessible id never silently drops out of the
 * batch between plan and preview.
 */
async function buildIdBatchPlan(
  g: GoogleClients,
  accountName: string,
  messageIds: string[] | undefined,
  verb: string,
  errorNoun: string,
): Promise<ConsentPlan> {
  if (!messageIds || !messageIds.length) {
    throw new Error(`Нужен непустой \`messageIds\`, чтобы построить план (${errorNoun}).`);
  }
  const idn = await fetchMsgIdentity(g, messageIds);
  const unreadable = messageIds.filter((id) => idn.get(id) == null);
  if (unreadable.length) {
    throw new Error(
      `Не удалось прочитать письмо(а) ${unreadable.join(", ")} — проверьте id или доступ. Ничего не изменено.`,
    );
  }
  const items: IdBatchItem[] = messageIds.map((id) => {
    const m = idn.get(id)!;
    return { id, subject: m.subject, from: m.from, labelIds: m.labelIds };
  });
  const payload: IdBatchPayload = { account: accountName, items };
  const lines = items.map(
    (it) => `- «${safeText(it.subject) || "(без темы)"}» (${it.id}) — ${safeText(it.from) || "?"}`,
  );
  const preview = `### 📤 План: ${verb} — ${items.length}\n\n${lines.join("\n")}`;
  return { payload, objectHash: sha256(idBatchHashPayload(payload)), preview, batchSize: items.length };
}

/** Rehash for `buildIdBatchPlan`'s payload: re-reads subject/from LIVE for
 * every item (real binding, not `sha256(addressing)` in disguise — see
 * consent.ts's contract comment on `rehash`). An id that vanished between
 * plan and execute becomes "__UNREADABLE__", which can never equal what was
 * read at plan time — forcing a mismatch rather than trusting the stale plan. */
async function rehashIdBatch(g: GoogleClients, addressing: IdBatchPayload): Promise<string> {
  const idn = await fetchMsgIdentity(g, addressing.items.map((it) => it.id));
  const fresh = addressing.items.map((it) => {
    const m = idn.get(it.id);
    return m
      ? { id: it.id, subject: m.subject, from: m.from }
      : { id: it.id, subject: "__UNREADABLE__", from: "__UNREADABLE__" };
  });
  return sha256({ account: addressing.account, items: fresh });
}

// ---- T1 post-verify helpers (identity-postverify.md §5) --------------------
// Each does a SEPARATE fresh read after the mutation — never reuses the
// mutation call's own response as proof (§5.1 p.1). Never throws: a read
// failure/timeout is ⚠️ "not verified", matching postVerifySend's contract.

/** Post-verify: message no longer carries INBOX (archive/snooze's target state). */
async function postVerifyNotInInbox(g: GoogleClients, id: string, subjectHint: string): Promise<VerifyLine & { detail: string }> {
  const subj = safeText(subjectHint) || "(без темы)";
  const labels = await fetchLabelIds(g, id);
  if (labels === null) {
    return { outcome: "warn", line: `- ⚠️ **«${subj}»** (${id}) — не удалось перепроверить состояние письма`, detail: "read failed" };
  }
  if (labels.includes("INBOX")) {
    return { outcome: "mismatch", line: `- ❌ **«${subj}»** (${id}) — всё ещё во «Входящих» (INBOX)`, detail: "still in INBOX" };
  }
  return { outcome: "ok", line: `- ✅ **«${subj}»** (${id}) — вне «Входящих»`, detail: "not in INBOX" };
}

/** Post-verify: message carries TRASH. */
async function postVerifyInTrash(g: GoogleClients, id: string, subjectHint: string): Promise<VerifyLine & { detail: string }> {
  const subj = safeText(subjectHint) || "(без темы)";
  const labels = await fetchLabelIds(g, id);
  if (labels === null) {
    return { outcome: "warn", line: `- ⚠️ **«${subj}»** (${id}) — не удалось перепроверить`, detail: "read failed" };
  }
  if (!labels.includes("TRASH")) {
    return { outcome: "mismatch", line: `- ❌ **«${subj}»** (${id}) — метки TRASH нет, письмо не в Корзине`, detail: "no TRASH label" };
  }
  return { outcome: "ok", line: `- ✅ **«${subj}»** (${id}) — в Корзине`, detail: "in Trash" };
}

/** Post-verify: `addLabelIds` are all present AND `removeLabelIds` are all
 * absent from the live labelIds. */
async function postVerifyLabelsApplied(
  g: GoogleClients,
  id: string,
  subjectHint: string,
  addLabelIds: string[] = [],
  removeLabelIds: string[] = [],
): Promise<VerifyLine & { detail: string }> {
  const subj = safeText(subjectHint) || "(без темы)";
  const labels = await fetchLabelIds(g, id);
  if (labels === null) {
    return { outcome: "warn", line: `- ⚠️ **«${subj}»** (${id}) — не удалось перепроверить метки`, detail: "read failed" };
  }
  const missingAdd = addLabelIds.filter((l) => !labels.includes(l));
  const stillThere = removeLabelIds.filter((l) => labels.includes(l));
  if (missingAdd.length || stillThere.length) {
    const parts = [
      missingAdd.length ? `не добавились: ${missingAdd.join(", ")}` : "",
      stillThere.length ? `не удалились: ${stillThere.join(", ")}` : "",
    ]
      .filter(Boolean)
      .join("; ");
    return { outcome: "mismatch", line: `- ❌ **«${subj}»** (${id}) — ${parts}`, detail: parts };
  }
  return { outcome: "ok", line: `- ✅ **«${subj}»** (${id}) — метки применены`, detail: "labels applied" };
}

async function fetchLabel(g: GoogleClients, id: string): Promise<{ id: string; name: string } | null> {
  try {
    const r = await g.gmail.users.labels.get({ userId: "me", id });
    return { id: r.data.id ?? id, name: r.data.name ?? "" };
  } catch {
    return null;
  }
}

/** Post-verify: a label with this id exists and its live name matches. */
async function postVerifyLabelExists(
  g: GoogleClients,
  id: string,
  expectedName: string,
): Promise<VerifyLine & { detail: string }> {
  const label = safeText(expectedName) || "(без имени)";
  const live = await fetchLabel(g, id);
  if (!live) {
    return { outcome: "warn", line: `- ⚠️ **«${label}»** (${id}) — не удалось перепроверить метку`, detail: "read failed" };
  }
  if (live.name !== expectedName) {
    return {
      outcome: "mismatch",
      line: `- ❌ **«${label}»** (${id}) — живое имя «${safeText(live.name)}» не совпадает с ожидаемым`,
      detail: "name mismatch",
    };
  }
  return { outcome: "ok", line: `- ✅ **«${label}»** (${id}) — метка существует`, detail: "exists" };
}

/** Post-verify: the label id no longer appears in labels.list — a SEPARATE
 * read, never the delete call's own 200 OK (§5.1 p.3). */
async function postVerifyLabelGone(g: GoogleClients, id: string, nameHint: string): Promise<VerifyLine & { detail: string }> {
  const label = safeText(nameHint) || "(без имени)";
  let live: gmail_v1.Schema$Label[] | undefined;
  try {
    const r = await g.gmail.users.labels.list({ userId: "me" });
    live = r.data.labels ?? [];
  } catch (e) {
    return {
      outcome: "warn",
      line: `- ⚠️ **«${label}»** (${id}) — не удалось перепроверить (${safeText(e instanceof Error ? e.message : String(e), 60)})`,
      detail: "read failed",
    };
  }
  if (live.some((l) => l.id === id)) {
    return { outcome: "mismatch", line: `- ❌ **«${label}»** (${id}) — метка всё ещё существует`, detail: "still exists" };
  }
  return { outcome: "ok", line: `- ✅ **«${label}»** (${id}) — метка удалена`, detail: "deleted" };
}

/** Post-verify: a Drive file exists (by id) and is not trashed. Used by
 * save_attachment_to_drive/export_thread_eml/create_upload_session. */
async function postVerifyDriveFileExists(
  g: GoogleClients,
  fileId: string | null | undefined,
  nameHint: string | null | undefined,
): Promise<VerifyLine & { detail: string }> {
  const label = safeText(nameHint) || "(без имени)";
  if (!fileId) {
    return { outcome: "warn", line: `- ⚠️ **«${label}»** — id файла в Drive неизвестен, перепроверить нечем`, detail: "no file id" };
  }
  try {
    const r = await g.drive.files.get({ fileId, fields: "id,name,trashed" });
    if (r.data.trashed) {
      return { outcome: "mismatch", line: `- ❌ **«${label}»** — файл в Drive оказался в корзине`, detail: "trashed" };
    }
    return {
      outcome: "ok",
      line: `- ✅ **«${safeText(r.data.name) || label}»** — файл существует в Drive (id ${fileId})`,
      detail: "exists",
    };
  } catch (e) {
    return {
      outcome: "warn",
      line: `- ⚠️ **«${label}»** — не удалось перепроверить файл в Drive (${safeText(e instanceof Error ? e.message : String(e), 60)})`,
      detail: "read failed",
    };
  }
}

/** Post-verify: a draft exists (by id), with a SEPARATE drafts.get read. */
async function postVerifyDraftExists(
  g: GoogleClients,
  draftId: string | null | undefined,
  subjectHint: string,
): Promise<VerifyLine & { detail: string }> {
  const label = safeText(subjectHint) || "(без темы)";
  if (!draftId) {
    return { outcome: "warn", line: `- ⚠️ **«${label}»** — id черновика неизвестен, перепроверить нечем`, detail: "no draft id" };
  }
  try {
    const r = await g.gmail.users.drafts.get({ userId: "me", id: draftId, format: "metadata" });
    const h = r.data.message?.payload?.headers;
    const to = header(h, "To");
    const subj = header(h, "Subject");
    return {
      outcome: "ok",
      line: `- ✅ **«${safeText(subj) || label}»** — черновик существует, Кому: ${safeText(to) || "(?)"}`,
      detail: "exists",
    };
  } catch (e) {
    return {
      outcome: "warn",
      line: `- ⚠️ **«${label}»** — не удалось перепроверить черновик (${safeText(e instanceof Error ? e.message : String(e), 60)})`,
      detail: "read failed",
    };
  }
}

/**
 * Aggregates a T1 batch mutation's per-item results with REAL independent
 * post-verify reads (mirrors `buildSendResult`'s approach for the 4 send
 * tools): every item without an execute-time `error` gets a fresh `verify`
 * read, the response header reflects the WORST outcome (never smoothed to ✅
 * on a ❌ — §5.3), and the audit row's phase-2 outcome is filled in via
 * `updateConsentAuditOutcome` so `gmail_consent_audit` shows what actually
 * happened, not just that the human said yes (the exact gap that kept
 * incident 1 invisible).
 */
async function buildMutationResult<T extends { error?: string }>(opts: {
  results: T[];
  total: number;
  verb: string;
  summaryIcon: string;
  verify: (item: T) => Promise<VerifyLine & { detail: string }>;
  reportTitle: string;
  reportSubtitle: string;
  consentStore?: ConsentStore;
  auditId?: string;
  preSnapshot?: unknown;
  /** Предупреждение вызывающему/человеку отдельным абзацем отчёта (например
   * «ссылка работает без входа — обращайтесь как с паролем»). Раньше три
   * инструмента дописывали его, РАСПАРСИВ обратно JSON из уже собранного
   * результата — теперь параметр, а не разбор собственного вывода. */
  note?: string;
  /** Доп. поля результата, не выводимые из `results` (например `folderId`). */
  extra?: Record<string, unknown>;
}): Promise<ReturnType<typeof ok>> {
  const { results, total, verb, summaryIcon, verify, reportTitle, reportSubtitle, consentStore, auditId, preSnapshot } = opts;
  const succeeded = results.filter((r) => !r.error);
  const pv = await mapWithLimit(succeeded, (r) => verify(r));
  const okN = succeeded.length;
  const failN = total - okN;
  const worst = worstOutcome(pv);
  let icon = summaryIcon;
  let tail = "";
  if (worst === "mismatch") {
    icon = "❌";
    tail = " — РАСХОЖДЕНИЕ при проверке, см. отчёт";
  } else if (worst === "warn" || failN > 0) {
    icon = "⚠️";
    if (failN > 0) tail = ` (${failN} с ошибкой)`;
  }
  if (consentStore && auditId) {
    const errs = results
      .filter((r): r is T & { error: string } => !!r.error)
      .map((r) => r.error)
      .join("; ");
    await consentStore
      .updateConsentAuditOutcome(auditId, {
        outcome: okN > 0 ? "confirmed" : "failed",
        postVerify:
          `${icon} ${verb} ${okN}/${total}${tail}` + (pv.length ? ` · post-verify: ${pv.map((p) => p.detail).join("; ")}` : ""),
        error: errs || null,
        ...(preSnapshot !== undefined ? { preSnapshot } : {}),
      })
      .catch((e) => {
        console.error(
          "[consent audit] updateConsentAuditOutcome failed:",
          e instanceof Error ? e.message : String(e),
        );
      });
  }
  const summary = `${icon} ${verb} ${okN}/${total}${tail}`;
  const verification = pv.length ? renderVerifyReport(reportTitle, reportSubtitle, pv) : undefined;
  const note = opts.note;
  return okVerbatim(
    renderExecutionReport({
      summary,
      errors: results.map((r) => r.error).filter((e): e is string => !!e),
      verification,
      results,
      note,
      extra: opts.extra,
    }),
    "execution-report",
    { summary, results, ...(verification ? { verification } : {}), ...(note ? { note } : {}), ...(opts.extra ?? {}) },
  );
}

/**
 * Phase-2 audit context (package A3): when a send tool ran through the
 * consent gate, `buildSendResult` also files the mutation's real outcome back
 * onto the phase-1 audit row via `updateConsentAuditOutcome` — otherwise the
 * audit log would show "confirmed by the human" and nothing about what
 * actually happened, repeating incident 1's invisibility. Awaited (not
 * fire-and-forget) so a caller reading the audit log right after the tool
 * call sees phase 2 already filled in; a DB hiccup here is logged and
 * swallowed — it must never turn an otherwise-successful/failed send into a
 * broken tool response.
 */
interface SendAuditContext {
  consentStore: ConsentStore;
  auditId: string;
  /** Outbound snapshot captured BEFORE the mutation (§5.2) — no full bodies. */
  preSnapshot: unknown;
}

/**
 * Post-verifies every successfully-sent message in a batch and assembles the
 * tool response: an honest header (✅ / ⚠️ / ❌) reflecting BOTH per-item send
 * failures and the post-verify outcome, plus the §5.3 proof block glued on by
 * the server. Fail-closed: any ❌ (self-send) keeps the header off "sent".
 */
async function buildSendResult(
  g: GoogleClients,
  results: Array<{ messageId?: string | null; error?: string; expectedTo?: string }>,
  total: number,
  selfEmail: string | undefined,
  verb: string,
  auditCtx?: SendAuditContext,
): Promise<ReturnType<typeof ok>> {
  const sent = results.filter((r) => r.messageId && !("error" in r && r.error));
  const pv = await mapWithLimit(sent, (r) => postVerifySend(g, r.messageId!, r.expectedTo ?? "", selfEmail));
  const okN = sent.length;
  const failN = total - okN;
  const worst = worstOutcome(pv);
  let icon = "✉️";
  let tail = "";
  if (worst === "mismatch") {
    icon = "❌";
    tail = " — РАСХОЖДЕНИЕ при проверке, см. отчёт";
  } else if (worst === "warn" || failN > 0) {
    icon = "⚠️";
    if (failN > 0) tail = ` (${failN} с ошибкой)`;
  }
  if (auditCtx) {
    const errs = results
      .filter((r): r is { error: string } => "error" in r && !!r.error)
      .map((r) => r.error)
      .join("; ");
    await auditCtx.consentStore
      .updateConsentAuditOutcome(auditCtx.auditId, {
        outcome: okN > 0 ? "confirmed" : "failed",
        postVerify:
          `${icon} ${verb} ${okN}/${total}${tail}` +
          (pv.length ? ` · post-verify: ${pv.map((p) => p.detail).join("; ")}` : ""),
        error: errs || null,
        preSnapshot: auditCtx.preSnapshot,
      })
      .catch((e) => {
        console.error(
          "[consent audit] updateConsentAuditOutcome failed:",
          e instanceof Error ? e.message : String(e),
        );
      });
  }
  // Strip the internal expectedTo marker from the results echoed back.
  const cleaned = results.map(({ expectedTo, ...rest }) => rest);
  const summary = `${icon} ${verb} ${okN}/${total}${tail}`;
  const verification = pv.length ? renderPostVerifyReport(pv) : undefined;
  return okVerbatim(
    renderExecutionReport({
      summary,
      errors: results.map((r) => r.error).filter((e): e is string => !!e),
      verification,
      results: cleaned,
    }),
    "execution-report",
    { summary, results: cleaned, ...(verification ? { verification } : {}) },
  );
}

/**
 * Ядро исполнения `gmail_send` — вынесено из тела тула (Максим, 2026-08-05),
 * чтобы БЫТЬ ВЫЗЫВАЕМЫМ И ИЗ обычного MCP tool-хендлера (модель вызвала
 * execute второй раз), И ИЗ фонового авто-поллера (кнопка в Telegram сама
 * триггерит это, без участия модели вообще) — см. `autoExecute.ts`'s
 * doc-comment про то, почему это НЕ MCP-параметр, а отдельная функция.
 * Ничего в самой логике не изменилось — просто извлечена в функцию.
 */
async function executeSendBatchCore(
  g: GoogleClients,
  accountName: string,
  selfEmail: string | undefined,
  payload: SendBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const sendMessages = payload.messages;
  const results = await mapWithLimit(sendMessages, async (msg) => {
    try {
      const atts = msg.attachments?.length ? await resolveAttachments(g, msg.attachments) : undefined;
      const raw = buildRawEmail({ to: msg.to, subject: msg.subject, body: msg.body, cc: msg.cc, bcc: msg.bcc, attachments: atts });
      logSendPreSnapshot(accountName, msg);
      const res = await g.gmail.users.messages.send({ userId: "me", requestBody: { raw } });
      return { messageId: res.data.id, threadId: res.data.threadId, expectedTo: msg.to };
    } catch (e) {
      return { error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildSendResult(g, results, sendMessages.length, selfEmail, "Отправлено", {
    consentStore,
    auditId,
    preSnapshot: outboundPreSnapshot(sendMessages),
  });
}

/** Достаёт человекочитаемый текст из CallToolResult — тот же текст, что
 * увидела бы модель, для отчёта в Telegram (см. autoExecute.ts's ExecuteFn). */
function extractText(result: CallToolResult): string {
  const first = result.content?.[0];
  return first && first.type === "text" ? first.text : JSON.stringify(result);
}

registerAutoExecutor("gmail_send", {
  rehash: (addressing) => sha256(addressing),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as SendBatchPayload;
    const g = ctx.clients.resolve(p.account);
    const selfEmail = await accountEmail(g, p.account);
    const result = await executeSendBatchCore(g, p.account, selfEmail, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- Consent-gate preview builder for the 4 send tools (package A3) --------
//
// A.4 / output-format.md §7.1: From (label + real email) / To / Cc / Subject /
// Attachments / When (schedule_send, LA time) / first ~400 chars of the body.
// All externally-influenced fields go through safeText — a crafted subject or
// original-message header must not be able to forge extra preview lines.
// consent.ts's renderPlanned() appends the manifest id/expiry/"show verbatim"
// tail ON TOP of what this returns — this function must NOT add those itself.

interface SendPreviewItem {
  to: string;
  cc?: string;
  bcc?: string;
  subject: string;
  body: string;
  attachments?: number;
  attachmentNames?: string[];
  sendAt?: Date;
  /** Non-blocking notice (e.g. self-reply) — rendered as a bullet, not a refusal. */
  warning?: string;
}

/**
 * Строка(и) «- Текст:» в превью плана. Однострочное тело остаётся на той же
 * строке (как было), многострочное уходит под заголовок с отступом — так
 * список в письме читается списком, а не одной слипшейся строкой.
 */
function renderPreviewBody(body: string): string {
  const block = safeBlock(body, { maxLines: 24, maxChars: 700 });
  if (!block) return "- Текст: (пусто)";
  const lines = block.split("\n");
  if (lines.length === 1) return `- Текст: ${lines[0].trim()}`;
  return `- Текст:\n${block}`;
}

function renderSendPreview(opts: { verb: string; fromLabel: string; items: SendPreviewItem[] }): string {
  const header = `### 📤 План: ${opts.verb} — ${opts.items.length}`;
  const blocks = opts.items.map((it, i) => {
    const lines = [
      opts.items.length > 1 ? `**${i + 1}.**` : undefined,
      `- От кого: ${safeText(opts.fromLabel, 200)}`,
      `- Кому: ${safeText(it.to, 300)}`,
      it.cc ? `- Копия: ${safeText(it.cc, 300)}` : undefined,
      it.bcc ? `- Скрытая копия: ${safeText(it.bcc, 300)}` : undefined,
      `- Тема: ${safeText(it.subject, 200) || "(без темы)"}`,
      it.attachments
        ? `- Вложения: ${it.attachments}${
            it.attachmentNames?.length ? ` (${it.attachmentNames.map((n) => safeText(n, 60)).join(", ")})` : ""
          }`
        : undefined,
      it.sendAt ? `- Когда: ${formatLaTime(it.sendAt.getTime())} PT` : undefined,
      it.warning ? `- ⚠️ ${safeText(it.warning, 200)}` : undefined,
      // Тело — МНОГОСТРОЧНО (safeBlock, не safeText): человек утверждает
      // отправку по этому превью, а `safeText` схлопывал `\n` в пробелы и
      // превращал перечисление в кашу «1. Первое 2. Второе». Построчная
      // санитизация внутри safeBlock оставляет ту же защиту от подделки
      // строк плана, что и раньше.
      renderPreviewBody(it.body),
    ].filter((l): l is string => l != null);
    return lines.join("\n");
  });
  return `${header}\n\n${blocks.join("\n\n")}`;
}

/** Compact pre-mutation outbound snapshot for the audit row (§5.2) — account
 * is implicit (the audit row already carries accountLabel), never a full body. */
function outboundPreSnapshot(
  items: Array<{ to: string; cc?: string; bcc?: string; subject: string; body?: string }>,
): unknown {
  return items.map((it) => ({
    to: it.to,
    cc: it.cc,
    bcc: it.bcc ? "<set>" : undefined,
    subject: it.subject,
    bodyPreview: (it.body ?? "").replace(/\s+/g, " ").slice(0, 80),
  }));
}

// ---- Payload shapes stored in consent_manifests for the 4 gated tools ------
// These are exactly what `decision.payload` carries back in the confirmed
// branch — the source of truth for the mutation, never the caller's arguments
// on the execute call (plan §A3 blocker requirement).

interface SendBatchPayload {
  account: string;
  messages: {
    to: string;
    subject: string;
    body: string;
    cc?: string;
    bcc?: string;
    attachments?: AttachmentInput[];
  }[];
}

interface ScheduleBatchPayload {
  account: string;
  messages: {
    to: string;
    subject: string;
    body: string;
    cc?: string;
    bcc?: string;
    attachments?: AttachmentInput[];
    sendAt: string;
  }[];
}

interface ReplyPlanItem {
  messageId: string;
  body: string;
  replyAll: boolean;
  attachments?: AttachmentInput[];
  /** Recomputed by `rehash` on execute — the actual binding this gate defends. */
  fromAddr: string;
  resolvedTo: string;
  subject: string;
  messageIdHeader: string;
  references: string;
  threadId?: string;
  cc?: string;
}

interface ReplyBatchPayload {
  account: string;
  replies: ReplyPlanItem[];
}

interface ForwardPlanItem {
  messageId: string;
  to: string;
  body?: string;
  subject: string;
  /** Recomputed by `rehash` on execute — detects the original drifting/vanishing. */
  origFrom: string;
  origSubject: string;
}

interface ForwardBatchPayload {
  account: string;
  items: ForwardPlanItem[];
}

// ---- Payload shapes for the T1 gated tools ---------------------------------

interface DraftBatchPayload {
  account: string;
  drafts: {
    to: string;
    subject: string;
    body: string;
    cc?: string;
    bcc?: string;
    attachments?: AttachmentInput[];
  }[];
}

interface ModifyLabelsItem {
  messageId: string;
  subject: string;
  from: string;
  addLabelIds: string[];
  removeLabelIds: string[];
}
interface ModifyLabelsPayload {
  account: string;
  items: ModifyLabelsItem[];
}
/** Same binding-projection convention as `idBatchHashPayload` — identity only
 * (messageId/subject/from), NOT the addLabelIds/removeLabelIds action itself
 * (that comes from the manifest's payload, protected the same way as
 * gmail_send's `messages`). */
function modifyLabelsHashPayload(p: ModifyLabelsPayload) {
  return { account: p.account, items: p.items.map(({ messageId, subject, from }) => ({ messageId, subject, from })) };
}

interface SnoozeItem extends IdBatchItem {
  unsnoozeAt: string;
}
interface SnoozeBatchPayload {
  account: string;
  items: SnoozeItem[];
}

interface CreateLabelPayload {
  account: string;
  labels: {
    name: string;
    labelListVisibility?: "labelShow" | "labelShowIfUnread" | "labelHide";
    messageListVisibility?: "show" | "hide";
    backgroundColor?: string;
    textColor?: string;
  }[];
}

interface UpdateLabelItem {
  labelId: string;
  currentName: string;
  name?: string;
  labelListVisibility?: "labelShow" | "labelShowIfUnread" | "labelHide";
  messageListVisibility?: "show" | "hide";
  backgroundColor?: string;
  textColor?: string;
}
interface UpdateLabelPayload {
  account: string;
  items: UpdateLabelItem[];
}

interface DeleteLabelItem {
  id: string;
  name: string;
  messageCount: number;
}
interface DeleteLabelPayload {
  account: string;
  labels: DeleteLabelItem[];
}

interface SaveAttachmentItem {
  messageId: string;
  attachmentId: string;
  filename: string;
  size: number;
  fileName?: string;
  folderId?: string;
  mimeType?: string;
}
interface SaveAttachmentPayload {
  account: string;
  items: SaveAttachmentItem[];
}

interface ExportThreadPayload {
  account: string;
  threadId: string;
  subject: string;
  messageCount: number;
  folderId?: string;
  folderName?: string;
  format: "eml_files" | "mbox";
  scope: "all" | "last" | "first";
}

interface UploadSessionPayload {
  account: string;
  files: { name: string; mimeType?: string; sizeBytes?: number }[];
}

/**
 * Pre-snapshot of an outbound message before the irreversible send
 * (identity-postverify.md §5.2). Until the consent_audit table exists (pkg A1)
 * this lands in the server log — NEVER the full body, only a short preview.
 */
function logSendPreSnapshot(
  accountName: string,
  msg: { to: string; cc?: string; bcc?: string; subject: string; body?: string },
): void {
  const preview = (msg.body ?? "").replace(/\s+/g, " ").slice(0, 80);
  console.error(
    `[send pre-snapshot] account=${accountName} to=${msg.to}` +
      (msg.cc ? ` cc=${msg.cc}` : "") +
      (msg.bcc ? " bcc=<set>" : "") +
      ` subject=${JSON.stringify(msg.subject)} body[0:80]=${JSON.stringify(preview)}`,
  );
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
 * multicast — i.e. NOT a public destination.
 *
 * ЕДИНСТВЕННАЯ таблица диапазонов на весь сервер живёт в `../safeFetch.ts`
 * (её же использует гугл-only `safeGoogleFetch` для сессий загрузки).
 * Здесь — только реэкспорт, чтобы две копии не разъезжались и чтобы
 * существующие тесты, импортирующие `isBlockedIp`/`pinnedLookup` из этого
 * модуля, продолжали работать.
 */
export { isBlockedIp, pinnedLookup };

/** A resolved-and-vetted host: every address in `addrs` already passed isBlockedIp. */
interface ResolvedHost {
  url: URL;
  addrs: { address: string; family: 4 | 6 }[];
}

/**
 * Resolves + validates a URL for a server-side fetch: https-only, and every
 * resolved IP must be public. Throws a 🛑-style refusal on anything unsafe.
 * Returns the parsed URL AND the exact vetted addresses, so the caller can
 * pin the actual TCP connection to one of them (see `fetchAttachmentSafely`
 * below for why re-resolving is unsafe). `lookup` is injectable for tests.
 */
async function resolveAndValidateHost(rawUrl: string, lookup: LookupFn): Promise<ResolvedHost> {
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
  const literalKind = net.isIP(host);
  if (literalKind) {
    if (isBlockedIp(host)) throw new Error("🛑 Ссылка ведёт на внутренний/приватный адрес — вложение не скачано.");
    return { url, addrs: [{ address: host, family: literalKind as 4 | 6 }] };
  }
  let resolved: { address: string }[];
  try {
    resolved = await lookup(host);
  } catch {
    throw new Error("🛑 Не удалось разрешить имя хоста ссылки — вложение не скачано.");
  }
  if (!resolved.length) throw new Error("🛑 Имя хоста ссылки не разрешается ни в один адрес — вложение не скачано.");
  const addrs: { address: string; family: 4 | 6 }[] = [];
  for (const a of resolved) {
    if (isBlockedIp(a.address)) {
      throw new Error("🛑 Имя хоста ссылки разрешается во внутренний/приватный адрес — вложение не скачано.");
    }
    const fam = net.isIP(a.address);
    addrs.push({ address: a.address, family: (fam === 6 ? 6 : 4) as 4 | 6 });
  }
  return { url, addrs };
}

/**
 * Validates a URL for a server-side fetch: https-only, and every resolved IP
 * must be public. Throws a 🛑-style refusal on anything unsafe. Returns the
 * parsed URL when clean. `lookup` is injectable for offline tests.
 *
 * NOTE: this alone does not protect a subsequent `fetch(url)` against DNS
 * rebinding — see `fetchAttachmentSafely`, which pins the connection to the
 * exact addresses validated here instead of letting the HTTP client resolve
 * the host again.
 */
export async function assertPublicUrl(rawUrl: string, lookup: LookupFn = defaultLookup): Promise<URL> {
  const { url } = await resolveAndValidateHost(rawUrl, lookup);
  return url;
}

// `pinnedLookup` (прибивает соединение к уже проверенным адресам, никакого
// повторного резолва) живёт в `../safeFetch.ts` и реэкспортируется выше.

/**
 * Fetches a URL into a Buffer with SSRF validation, manual redirects (each
 * Location re-validated), a per-request timeout and a streaming size cap
 * enforced WHILE downloading (never buffers past the cap). Returns the bytes
 * and the response content-type. Exported for tests.
 *
 * DNS-rebinding / TOCTOU fix: `resolveAndValidateHost` resolves + validates
 * the host exactly ONCE per hop. The actual TCP/TLS connection is then
 * pinned to that SAME vetted address via a per-hop undici `Agent` with a
 * custom `connect.lookup` (see `pinnedLookup`) — the HTTP client is never
 * allowed to re-resolve the hostname itself. Without this, an attacker
 * serving a short-TTL DNS record could answer the validation lookup with a
 * public IP and the connect-time lookup (a completely independent resolve
 * inside the HTTP client) with a private one, e.g. Railway's
 * 169.254.169.254 metadata endpoint — validated-but-not-what-you-connect-to.
 * Host header and TLS SNI are left untouched (still the real hostname, via
 * the `Agent`'s connector, which reads `servername`/`host` from the request
 * URL, not from the resolved IP) so certificate validation still works
 * normally against the real hostname.
 *
 * We deliberately use `undici`'s OWN `fetch` + `Agent` pair (same package,
 * same realm) instead of Node's global `fetch` with an externally-built
 * dispatcher: Node's global fetch is powered by an INTERNAL undici bundled
 * into the Node binary (this repo's runtime: Node 22, internal undici
 * 6.24.1) with its own request-handler wire format, and handing it a
 * dispatcher built from the separately-installed `undici` npm package
 * throws (`InvalidArgumentError: invalid onRequestStart method`) whenever
 * the two versions' internal handler interfaces disagree — verified
 * empirically while building this fix. Using undici's fetch+Agent together
 * sidesteps that version-skew trap entirely: both come from the exact same
 * module instance, so pinning cannot silently regress on a Node bump.
 */
export type PinnedFetchFn = typeof pinnedFetch;

export async function fetchAttachmentSafely(
  rawUrl: string,
  maxBytes: number,
  lookup: LookupFn = defaultLookup,
  // Injectable for offline tests — must be given a `dispatcher` to actually
  // exercise the pin. Defaults to undici's real fetch (see the doc comment
  // above for why it must be undici's, not Node's global, fetch).
  fetchImpl: PinnedFetchFn = pinnedFetch,
): Promise<{ buf: Buffer; contentType: string | null }> {
  let current = rawUrl;
  for (let hop = 0; hop <= MAX_ATTACHMENT_REDIRECTS; hop++) {
    const { url, addrs } = await resolveAndValidateHost(current, lookup);
    const dispatcher = new UndiciAgent({
      connect: { lookup: pinnedLookup(addrs), timeout: FETCH_TIMEOUT_MS },
    });
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      let resp: Awaited<ReturnType<typeof pinnedFetch>>;
      try {
        resp = await fetchImpl(url, {
          redirect: "manual",
          signal: ctrl.signal,
          headers: { accept: "*/*" },
          dispatcher,
        });
      } catch (e) {
        if ((e as { name?: string })?.name === "AbortError") {
          throw new Error("🛑 Источник вложения не ответил вовремя (таймаут). Вложение не скачано.");
        }
        throw new Error("🛑 Не удалось соединиться с источником вложения. Вложение не скачано.");
      }
      // Manual redirect: re-validate + re-pin the target on next hop.
      if (resp.status >= 300 && resp.status < 400 && resp.headers.get("location")) {
        current = new URL(resp.headers.get("location")!, url).toString();
        continue;
      }
      if (!resp.ok) {
        throw new Error(`🛑 Источник вложения ответил ошибкой (HTTP ${resp.status}). Вложение не скачано.`);
      }
      // Fast pre-check: a declared Content-Length over the cap is refused up front.
      const declared = Number(resp.headers.get("content-length") ?? "");
      if (Number.isFinite(declared) && declared > maxBytes) {
        throw new Error(
          `🛑 Вложение по ссылке — ${Math.round(declared / (1024 * 1024))} МБ; Gmail ограничивает письмо 25 МБ. Не скачано.`,
        );
      }
      const contentType = resp.headers.get("content-type")?.split(";")[0]?.trim() ?? null;
      const buf = await readCappedStream(resp.body as unknown as ReadableStream<Uint8Array> | null, maxBytes);
      return { buf, contentType };
    } finally {
      clearTimeout(timer);
      void dispatcher.close().catch(() => {});
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
  /**
   * Consent-gate storage (package A1, `src/consent.ts`'s `ConsentStore`). null
   * exactly when Postgres isn't configured. The 4 gated send tools below
   * refuse outright when this is null — gate.md §3.5: no durable manifest
   * storage means no gate, and that must never become a silent bypass.
   */
  consentStore: ConsentStore | null;
  /**
   * Gate knobs (TTL / anti-doublet gap / batch cap), always present even when
   * consentStore is null so a refusal message can still be built without a
   * crash. Real value comes from `consentServerConfig` in server.ts (env-driven).
   */
  consentCfg: ConsentConfig;
  /**
   * Read-only access to the consent_audit log (package A4). null exactly when
   * Postgres isn't configured (same honest-degradation rule as `store`) — the
   * gate itself is off in that case too, so there is no audit to read.
   */
  auditStore: AuditStore | null;
  /**
   * Optional out-of-band Telegram-approval layer (plan-tg-approval.md).
   * undefined ⇒ `requireConsent`'s `tg` branch never runs — behaviour is
   * byte-for-byte identical to before this field existed. Production always
   * passes `tgApprovalGate` from server.ts, whose `enabledFor()` is itself
   * false unless TG_APPROVAL_ENABLED=true.
   */
  tg?: TgApprovalGate;
  /**
   * Automation_key DI (docs/TZ_automation_key_consent_gate.md), passed through
   * to every gated tool's `requireConsent({ checkAutomationKey })`. undefined
   * ⇒ the automation branch in `requireConsent` never runs — byte-for-byte as
   * before this field existed (same invariant as `tg` above). Production
   * passes `makeCheckAutomationKey()` from server.ts.
   */
  checkAutomationKey?: (key: string, tool: string) => Promise<{ ok: boolean; channel?: string }>;
  /**
   * Подменяемый транспорт для исходящих запросов к Google (`safeGoogleFetch`).
   * ПРОД НИКОГДА ЭТО НЕ ПЕРЕДАЁТ — поле существует только чтобы офлайн-тесты
   * могли подставить фейковый fetch/резолвер вместо настоящей сети (как
   * `fetchAttachmentSafely` принимает `lookup`/`fetchImpl` параметрами).
   * Это НЕ MCP-параметр: модель не может ничего сюда положить, поле живёт в
   * контексте регистрации инструментов, а не в схеме вызова.
   */
  safeFetch?: SafeFetchDeps;
}

/** Fallback gate config for callers that don't wire a real one (offline unit
 * tests exercising other tools). Mirrors config.ts's `loadConsentGateConfig()`
 * defaults; production always gets the real env-driven config from server.ts. */
const DEFAULT_CONSENT_CFG: ConsentConfig = {
  server: "gmail",
  consentTtlMs: 3_600_000,
  minConsentGapMs: 10_000,
  sendBatchMax: 10,
};

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

/**
 * YYYY-MM-DD из заголовка `Date`, или "" если он не разбирается.
 *
 * День — по Лос-Анджелесу (`laDateStamp`), а не по UTC: письмо, пришедшее в
 * 17:00 PT, раньше попадало в имя файла экспорта уже СЛЕДУЮЩИМ днём.
 */
function dateStamp(dateHeader: string): string {
  if (!dateHeader) return "";
  const d = new Date(dateHeader);
  return isNaN(d.getTime()) ? "" : laDateStamp(d.getTime());
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

// ---- Авто-исполнение по кнопке в Telegram: ядра + регистрация ------------
//
// Максим, 2026-08-05: «нажал кнопку — должно сразу исполниться на бэке, не
// ждать повторного вызова моделью». Паттерн (см. `executeSendBatchCore` +
// `registerAutoExecutor("gmail_send", …)` выше) распространён здесь на
// остальные гейтованные тулы: тело "confirmed"-ветки каждого тула вынесено в
// одноимённую `execute<Тул>Core` функцию, которую дергает и обычный
// MCP-хендлер (второй вызов моделью), и фоновый поллер напрямую. Регистрация
// — на уровне МОДУЛЯ (не внутри `registerGmailTools`, которая перевызывается
// на каждый MCP-запрос — см. `autoExecute.ts`'s doc-comment).
//
// Ничего в логике самих мутаций не изменилось — это чистое извлечение в
// функции, byte-for-byte то же поведение, что было в теле тула.

/** Оборачивает `(g, addressing)`-rehash (та же функция, что уходит в
 * `requireConsent` для этого тула — НЕ упрощённая копия) в
 * `autoExecute.ts`'s `RehashFn`: резолвит живой `g` из `ctx.clients` по
 * `account`-метке, которая есть в каждом payload (rehash самого поллера не
 * получает per-request `g`, только `ctx`, см. `AutoExecutorCtx`). */
function autoRehash<P extends { account: string }>(
  core: (g: GoogleClients, addressing: P) => string | Promise<string>,
): (addressing: unknown, ctx: AutoExecutorCtx) => string | Promise<string> {
  return (addressing, ctx) => {
    const p = addressing as P;
    return core(ctx.clients.resolve(p.account), p);
  };
}

// ---- gmail_reply -----------------------------------------------------------

/** Real binding для gmail_reply: та же логика, что раньше жила инлайн в
 * `rehash` этого тула — re-reads каждого оригинала's From header. */
async function rehashReplyBatch(g: GoogleClients, addressing: ReplyBatchPayload): Promise<string> {
  const fresh = await mapWithLimit(addressing.replies, async (r) => {
    try {
      const orig = await g.gmail.users.messages.get({
        userId: "me",
        id: r.messageId,
        format: "metadata",
        metadataHeaders: ["From"],
      });
      const freshFrom = header(orig.data.payload?.headers, "From");
      return { ...r, fromAddr: freshFrom, resolvedTo: extractEmail(freshFrom) };
    } catch {
      return { ...r, fromAddr: "__UNREADABLE__", resolvedTo: "__UNREADABLE__" };
    }
  });
  return sha256({ account: addressing.account, replies: fresh });
}

async function executeReplyBatchCore(
  g: GoogleClients,
  accountName: string,
  selfEmail: string | undefined,
  payload: ReplyBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.replies, async (item) => {
    try {
      const atts = item.attachments?.length ? await resolveAttachments(g, item.attachments) : undefined;
      const raw = buildRawEmail({
        to: item.fromAddr,
        cc: item.cc,
        subject: item.subject,
        body: item.body,
        inReplyTo: item.messageIdHeader || undefined,
        references: item.references || undefined,
        attachments: atts,
      });
      logSendPreSnapshot(accountName, { to: item.fromAddr, cc: item.cc, subject: item.subject, body: item.body });
      const draft = await g.gmail.users.drafts.create({
        userId: "me",
        requestBody: { message: { raw, threadId: item.threadId } },
      });
      const res = await g.gmail.users.drafts.send({
        userId: "me",
        requestBody: { id: draft.data.id! },
      });
      return { messageId: res.data.id, expectedTo: item.fromAddr };
    } catch (e) {
      return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildSendResult(g, results, payload.replies.length, selfEmail, "Ответов отправлено", {
    consentStore,
    auditId,
    preSnapshot: outboundPreSnapshot(payload.replies.map((r) => ({ to: r.fromAddr, cc: r.cc, subject: r.subject, body: r.body }))),
  });
}

registerAutoExecutor("gmail_reply", {
  rehash: autoRehash(rehashReplyBatch),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as ReplyBatchPayload;
    const g = ctx.clients.resolve(p.account);
    const selfEmail = await accountEmail(g, p.account);
    const result = await executeReplyBatchCore(g, p.account, selfEmail, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_forward ----------------------------------------------------------

async function rehashForwardBatch(g: GoogleClients, addressing: ForwardBatchPayload): Promise<string> {
  const fresh = await mapWithLimit(addressing.items, async (it) => {
    try {
      const orig = await g.gmail.users.messages.get({
        userId: "me",
        id: it.messageId,
        format: "metadata",
        metadataHeaders: ["From", "Subject"],
      });
      const h = orig.data.payload?.headers;
      return { ...it, origFrom: header(h, "From"), origSubject: header(h, "Subject") };
    } catch {
      return { ...it, origFrom: "__UNREADABLE__", origSubject: "__UNREADABLE__" };
    }
  });
  return sha256({ account: addressing.account, items: fresh });
}

async function executeForwardBatchCore(
  g: GoogleClients,
  accountName: string,
  selfEmail: string | undefined,
  payload: ForwardBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.items, async (item) => {
    try {
      const orig = await g.gmail.users.messages.get({ userId: "me", id: item.messageId, format: "full" });
      const h = orig.data.payload?.headers;
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
      const raw = buildRawEmail({ to: item.to, subject: item.subject, body, attachments: atts.length ? atts : undefined });
      logSendPreSnapshot(accountName, { to: item.to, subject: item.subject, body: item.body });
      const res = await g.gmail.users.messages.send({ userId: "me", requestBody: { raw } });
      return { messageId: res.data.id, expectedTo: item.to };
    } catch (e) {
      return { id: item.messageId, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildSendResult(g, results, payload.items.length, selfEmail, "Переслано", {
    consentStore,
    auditId,
    preSnapshot: outboundPreSnapshot(payload.items.map((it) => ({ to: it.to, subject: it.subject, body: it.body }))),
  });
}

registerAutoExecutor("gmail_forward", {
  rehash: autoRehash(rehashForwardBatch),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as ForwardBatchPayload;
    const g = ctx.clients.resolve(p.account);
    const selfEmail = await accountEmail(g, p.account);
    const result = await executeForwardBatchCore(g, p.account, selfEmail, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_create_draft ------------------------------------------------------

async function executeDraftBatchCore(
  g: GoogleClients,
  payload: DraftBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.drafts, async (d) => {
    try {
      const atts = d.attachments?.length ? await resolveAttachments(g, d.attachments) : undefined;
      const raw = buildRawEmail({ to: d.to, subject: d.subject, body: d.body, cc: d.cc, bcc: d.bcc, attachments: atts });
      const res = await g.gmail.users.drafts.create({
        userId: "me",
        requestBody: { message: { raw } },
      });
      return { draftId: res.data.id, to: d.to, subject: d.subject };
    } catch (e) {
      return { to: d.to, subject: d.subject, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.drafts.length,
    verb: "Создано",
    summaryIcon: "📝",
    verify: (r) => postVerifyDraftExists(g, r.draftId, r.subject),
    reportTitle: "Независимая проверка создания черновика",
    reportSubtitle: "запрошено ⇄ живые черновики Gmail",
    consentStore,
    auditId,
  });
}

registerAutoExecutor("gmail_create_draft", {
  rehash: (addressing) => sha256(addressing),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as DraftBatchPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeDraftBatchCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_archive / gmail_trash (both IdBatchPayload) ----------------------
// rehash reused as-is: `rehashIdBatch` (module-level already, precedent this
// whole extraction follows for the other tools below).

async function executeArchiveCore(
  g: GoogleClients,
  payload: IdBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.items, async (item) => {
    try {
      await g.gmail.users.messages.modify({
        userId: "me",
        id: item.id,
        requestBody: { removeLabelIds: ["INBOX"] },
      });
      return { id: item.id, subject: item.subject, from: item.from };
    } catch (e) {
      return { id: item.id, subject: item.subject, from: item.from, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Архивировано",
    summaryIcon: "📥",
    verify: (r) => postVerifyNotInInbox(g, r.id, r.subject),
    reportTitle: "Независимая проверка архивирования",
    reportSubtitle: "запрошено ⇄ живые метки Gmail",
    consentStore,
    auditId,
  });
}

registerAutoExecutor("gmail_archive", {
  rehash: autoRehash(rehashIdBatch),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as IdBatchPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeArchiveCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

async function executeTrashCore(
  g: GoogleClients,
  payload: IdBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.items, async (item) => {
    try {
      await g.gmail.users.messages.trash({ userId: "me", id: item.id });
      return { id: item.id, subject: item.subject, from: item.from };
    } catch (e) {
      return { id: item.id, subject: item.subject, from: item.from, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Удалено (в корзину)",
    summaryIcon: "🗑",
    verify: (r) => postVerifyInTrash(g, r.id, r.subject),
    reportTitle: "Независимая проверка удаления в Корзину",
    reportSubtitle: "запрошено ⇄ живые метки Gmail",
    consentStore,
    auditId,
    preSnapshot: payload.items.map((it) => ({ id: it.id, subject: it.subject, from: it.from, labelIds: it.labelIds })),
  });
}

registerAutoExecutor("gmail_trash", {
  rehash: autoRehash(rehashIdBatch),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as IdBatchPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeTrashCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_modify_labels ------------------------------------------------------

async function rehashModifyLabels(g: GoogleClients, addressing: ModifyLabelsPayload): Promise<string> {
  const idn = await fetchMsgIdentity(g, addressing.items.map((it) => it.messageId));
  const fresh = addressing.items.map((it) => {
    const m = idn.get(it.messageId);
    return m
      ? { messageId: it.messageId, subject: m.subject, from: m.from }
      : { messageId: it.messageId, subject: "__UNREADABLE__", from: "__UNREADABLE__" };
  });
  return sha256({ account: addressing.account, items: fresh });
}

async function executeModifyLabelsCore(
  g: GoogleClients,
  payload: ModifyLabelsPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.items, async (item) => {
    try {
      await g.gmail.users.messages.modify({
        userId: "me",
        id: item.messageId,
        requestBody: { addLabelIds: item.addLabelIds, removeLabelIds: item.removeLabelIds },
      });
      return { id: item.messageId, subject: item.subject, from: item.from, addLabelIds: item.addLabelIds, removeLabelIds: item.removeLabelIds };
    } catch (e) {
      return {
        id: item.messageId,
        subject: item.subject,
        from: item.from,
        addLabelIds: item.addLabelIds,
        removeLabelIds: item.removeLabelIds,
        error: String(e instanceof Error ? e.message : e),
      };
    }
  });
  return buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Изменено",
    summaryIcon: "🏷️",
    verify: (r) => postVerifyLabelsApplied(g, r.id, r.subject, r.addLabelIds, r.removeLabelIds),
    reportTitle: "Независимая проверка изменения меток",
    reportSubtitle: "запрошено ⇄ живые метки Gmail",
    consentStore,
    auditId,
  });
}

registerAutoExecutor("gmail_modify_labels", {
  rehash: autoRehash(rehashModifyLabels),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as ModifyLabelsPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeModifyLabelsCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_snooze -------------------------------------------------------------
// rehash reused as-is: `rehashIdBatch` (SnoozeItem structurally extends
// IdBatchItem — same convention the manual tool handler already uses via
// `rehashIdBatch(g, addressing as IdBatchPayload)`).

async function executeSnoozeCore(
  g: GoogleClients,
  accountName: string,
  payload: SnoozeBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
  store: Pick<PgStore, "addSnooze"> | null,
  userToken: string | null,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.items, async (item) => {
    try {
      const unsnoozeAt = new Date(item.unsnoozeAt);
      if (isNaN(unsnoozeAt.getTime())) {
        return { id: item.id, subject: item.subject, error: `Cannot parse date "${item.unsnoozeAt}". Use ISO 8601.` };
      }
      if (unsnoozeAt <= new Date()) {
        return { id: item.id, subject: item.subject, error: `Snooze time "${item.unsnoozeAt}" is already in the past.` };
      }
      await g.gmail.users.messages.modify({
        userId: "me",
        id: item.id,
        requestBody: { removeLabelIds: ["INBOX"] },
      });
      if (store) {
        await store.addSnooze({ userToken, accountName, messageId: item.id, unsnoozeAt });
      }
      return {
        id: item.id,
        subject: item.subject,
        unsnoozeAt: unsnoozeAt.toISOString(),
        persisted: !!store,
      };
    } catch (e) {
      return { id: item.id, subject: item.subject, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Отложено",
    summaryIcon: "⏰",
    verify: (r) => postVerifyNotInInbox(g, r.id, r.subject),
    reportTitle: "Независимая проверка отложенного возврата",
    reportSubtitle: "запрошено ⇄ живые метки Gmail (сам возврат в inbox проверяется позже, фоном)",
    consentStore,
    auditId,
  });
}

registerAutoExecutor("gmail_snooze", {
  rehash: autoRehash(rehashIdBatch),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as SnoozeBatchPayload;
    const g = ctx.clients.resolve(p.account);
    // ctx.store — тот же адаптер, что per-request путь получает как
    // snoozeCtx.store; null ровно когда DATABASE_URL не настроен (та же
    // честная деградация, executeSnoozeCore просто не персистит).
    const result = await executeSnoozeCore(g, p.account, p, auditId, ctx.consentStore, ctx.store, ctx.userToken);
    return extractText(result);
  },
});

// ---- gmail_schedule_send --------------------------------------------------

async function executeScheduleSendCore(
  g: GoogleClients,
  accountName: string,
  payload: ScheduleBatchPayload,
  auditId: string,
  consentStore: ConsentStore,
  store: Pick<PgStore, "addScheduledSend">,
  userToken: string | null,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.messages, async (msg) => {
    try {
      const sendAt = new Date(msg.sendAt);
      if (isNaN(sendAt.getTime())) {
        return { to: msg.to, subject: msg.subject, error: `Cannot parse date "${msg.sendAt}". Use ISO 8601.` };
      }
      if (sendAt <= new Date()) {
        return { to: msg.to, subject: msg.subject, error: `sendAt "${msg.sendAt}" is already in the past.` };
      }
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
  const errs = results
    .filter((r): r is { to: string; subject: string; error: string } => "error" in r && !!r.error)
    .map((r) => r.error)
    .join("; ");
  await consentStore
    .updateConsentAuditOutcome(auditId, {
      outcome: ok_.length > 0 ? "confirmed" : "failed",
      postVerify:
        `🕗 Поставлено в очередь ${ok_.length}/${results.length}; фактическая отправка произойдёт позже — ` +
        "проверяйте через gmail_list_scheduled_sends.",
      error: errs || null,
      preSnapshot: outboundPreSnapshot(payload.messages),
    })
    .catch((e) => {
      console.error(
        "[consent audit] updateConsentAuditOutcome failed:",
        e instanceof Error ? e.message : String(e),
      );
    });
  // Тот же человекочитаемый формат, что и у остальных гейтованных мутаций:
  // этот путь тоже авто-исполняется кнопкой в Telegram, где `content[0].text`
  // показывается человеку КАК ЕСТЬ (post-verify здесь нет по природе тула —
  // письмо ещё не ушло, проверять в «Отправленных» нечего).
  const summary = `🕗 Scheduled ${ok_.length}/${results.length} message(s)`;
  return okVerbatim(
    renderExecutionReport({
      summary,
      errors: results.filter((r) => "error" in r && !!r.error).map((r) => (r as { error: string }).error),
      results,
    }),
    "execution-report",
    { summary, results },
  );
}

registerAutoExecutor("gmail_schedule_send", {
  rehash: (addressing) => sha256(addressing),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as ScheduleBatchPayload;
    if (!ctx.store) {
      // Тот же отказ, что manual-путь даёт синхронно на плане (`if (!store)
      // return fail(...)`) — здесь манифест уже мог существовать (DATABASE_URL
      // был на момент плана), но Postgres временно недоступен к моменту тика
      // поллера; честно отказываем, а не молча теряем очередь на отправку.
      throw new Error(
        "Отложенная отправка недоступна: хранилище (DATABASE_URL) сейчас недоступно — попробуйте позже.",
      );
    }
    const g = ctx.clients.resolve(p.account);
    const result = await executeScheduleSendCore(g, p.account, p, auditId, ctx.consentStore, ctx.store, ctx.userToken);
    return extractText(result);
  },
});

// ---- gmail_cancel_scheduled_send -------------------------------------------
//
// GATED as of 2026-08-06. It used to be exempt, with "защитное действие
// (отмена отправки), сознательно вне гейта" as the reason — i.e. cancelling was
// treated as safe because it points in the "undo" direction. That does not
// survive contact with what the gate is actually for: the gate protects the
// OWNER'S INTENT, not one particular direction of change.
//
//  - the intent being destroyed here is one the owner already confirmed —
//    gmail_schedule_send is itself gated, so "queue this" needed a yes while
//    "un-queue it" needed nothing. A model could silently undo a confirmed
//    decision, which is precisely the asymmetry a gate exists to prevent;
//  - there is NO un-cancel. The row goes to 'canceled' and the send never
//    happens; nothing restores it;
//  - it fails silently. Nobody notices a mail that did not go out until the
//    recipient asks about it;
//  - the ids are bare integers copied out of a list, so an off-by-one cancels a
//    different message than the one meant.

interface CancelScheduledSendItem {
  id: number;
  toPreview: string;
  subjectPreview: string;
  /** ISO string of what the queue says RIGHT NOW — part of the binding hash. */
  sendAt: string;
}

interface CancelScheduledSendPayload {
  account: string;
  items: CancelScheduledSendItem[];
}

/** The slice of the queue store this tool needs (plan, rehash and execute). */
type ScheduledSendStore = Pick<PgStore, "listScheduledSends" | "cancelScheduledSend">;

/** Reads the live queue rows behind the requested ids. Throws (→ the plan
 * fails, nothing is cancelled) when an id is not actually pending: better to
 * refuse than to build a plan whose preview shows blanks. */
async function readPendingScheduledSends(
  store: ScheduledSendStore,
  accountName: string,
  ids: number[],
): Promise<CancelScheduledSendItem[]> {
  const pending = await store.listScheduledSends(accountName, "pending");
  const byId = new Map(pending.map((r) => [r.id, r]));
  return ids.map((id) => {
    const row = byId.get(id);
    if (!row) {
      throw new Error(
        `Отправка ${id} не найдена среди ожидающих на аккаунте «${accountName}» — уже ушла, уже отменена ` +
          "или это чужой id. Ничего не отменено; посмотрите gmail_list_scheduled_sends.",
      );
    }
    return { id, toPreview: row.toPreview, subjectPreview: row.subjectPreview, sendAt: row.sendAt.toISOString() };
  });
}

/** REAL binding (gate.md §3.3 п.2): goes back to the QUEUE at execute time and
 * hashes what is there NOW. A message that left (or was cancelled by someone
 * else, or had its time changed) between plan and confirmation no longer
 * hashes the same, so the stale approval is refused instead of hitting a row
 * the человек never saw. `__GONE__` is a deliberate sentinel — a vanished row
 * must change the hash, not silently drop out of it. */
async function rehashCancelScheduledSend(
  store: ScheduledSendStore,
  addressing: CancelScheduledSendPayload,
): Promise<string> {
  const pending = await store.listScheduledSends(addressing.account, "pending");
  const byId = new Map(pending.map((r) => [r.id, r]));
  const fresh = addressing.items.map((it) => {
    const row = byId.get(it.id);
    return row
      ? { id: it.id, toPreview: row.toPreview, subjectPreview: row.subjectPreview, sendAt: row.sendAt.toISOString() }
      : { id: it.id, toPreview: "__GONE__", subjectPreview: "__GONE__", sendAt: "__GONE__" };
  });
  return sha256({ account: addressing.account, items: fresh });
}

/** Independent post-verify: the row must actually be in 'canceled' afterwards —
 * never trust the UPDATE's own rowCount as proof. */
async function postVerifyScheduledSendCanceled(
  store: ScheduledSendStore,
  accountName: string,
  id: number,
  subjectHint: string,
): Promise<VerifyLine & { detail: string }> {
  const label = safeText(subjectHint) || "(без темы)";
  let canceled: Awaited<ReturnType<ScheduledSendStore["listScheduledSends"]>>;
  try {
    canceled = await store.listScheduledSends(accountName, "canceled");
  } catch (e) {
    return {
      outcome: "warn",
      line: `- ⚠️ **«${label}»** (#${id}) — не удалось перепроверить (${safeText(e instanceof Error ? e.message : String(e), 60)})`,
      detail: "read failed",
    };
  }
  if (!canceled.some((r) => r.id === id)) {
    return { outcome: "mismatch", line: `- ❌ **«${label}»** (#${id}) — в живой очереди НЕ значится отменённой`, detail: "not canceled" };
  }
  return { outcome: "ok", line: `- ✅ **«${label}»** (#${id}) — отменена, подтверждено по живой очереди`, detail: "canceled" };
}

async function executeCancelScheduledSendCore(
  store: ScheduledSendStore,
  payload: CancelScheduledSendPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results: { id: number; to: string; subject: string; sendAt: string; error?: string }[] = await mapWithLimit(
    payload.items,
    async (it) => {
      const base = { id: it.id, to: it.toPreview, subject: it.subjectPreview, sendAt: it.sendAt };
      try {
        const canceled = await store.cancelScheduledSend(it.id, payload.account);
        return canceled ? base : { ...base, error: "Already sent, already canceled, or unknown id." };
      } catch (e) {
        return { ...base, error: String(e instanceof Error ? e.message : e) };
      }
    },
  );
  return buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Отменено",
    summaryIcon: "🚫",
    verify: (r) => postVerifyScheduledSendCanceled(store, payload.account, r.id, r.subject),
    reportTitle: "Независимая проверка отмены отложенных отправок",
    reportSubtitle: "запрошено ⇄ живая очередь этого сервера",
    consentStore,
    auditId,
    preSnapshot: payload.items,
  });
}

registerAutoExecutor("gmail_cancel_scheduled_send", {
  rehash: (addressing, ctx: AutoExecutorCtx) => {
    if (!ctx.store) {
      throw new Error("Отмена отложенной отправки недоступна: хранилище (DATABASE_URL) сейчас недоступно.");
    }
    return rehashCancelScheduledSend(ctx.store, addressing as CancelScheduledSendPayload);
  },
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    if (!ctx.store) {
      // Same refusal the manual path gives synchronously: the manifest may have
      // been built while Postgres was up, but the poller ticks later.
      throw new Error("Отмена отложенной отправки недоступна: хранилище (DATABASE_URL) сейчас недоступно — попробуйте позже.");
    }
    const result = await executeCancelScheduledSendCore(
      ctx.store,
      payload as CancelScheduledSendPayload,
      auditId,
      ctx.consentStore,
    );
    return extractText(result);
  },
});

// ---- gmail_save_attachment_to_drive ----------------------------------------

async function rehashSaveAttachment(g: GoogleClients, addressing: SaveAttachmentPayload): Promise<string> {
  const fresh = await mapWithLimit(addressing.items, async (it) => {
    try {
      const msg = await g.gmail.users.messages.get({ userId: "me", id: it.messageId, format: "full" });
      const found = collectAttachments(msg.data.payload).find((x) => x.attachmentId === it.attachmentId);
      return found
        ? { messageId: it.messageId, attachmentId: it.attachmentId, filename: found.filename, size: found.size }
        : { messageId: it.messageId, attachmentId: it.attachmentId, filename: "__UNREADABLE__", size: -1 };
    } catch {
      return { messageId: it.messageId, attachmentId: it.attachmentId, filename: "__UNREADABLE__", size: -1 };
    }
  });
  return sha256({ account: addressing.account, items: fresh });
}

async function executeSaveAttachmentCore(
  g: GoogleClients,
  payload: SaveAttachmentPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.items, async (item) => {
    try {
      const att = await g.gmail.users.messages.attachments.get({
        userId: "me",
        messageId: item.messageId,
        id: item.attachmentId,
      });
      const buffer = Buffer.from(att.data.data ?? "", "base64url");
      const filename = item.fileName ?? item.filename ?? "attachment";
      const res = await g.drive.files.create({
        requestBody: { name: filename, parents: item.folderId ? [item.folderId] : undefined },
        media: { mimeType: item.mimeType ?? "application/octet-stream", body: Readable.from(buffer) },
        fields: "id,name,mimeType,size,webViewLink",
      });
      return { fileId: res.data.id, fileName: res.data.name, messageId: item.messageId, attachmentId: item.attachmentId };
    } catch (e) {
      return { messageId: item.messageId, attachmentId: item.attachmentId, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Сохранено",
    summaryIcon: "💾",
    verify: (r) => postVerifyDriveFileExists(g, r.fileId, r.fileName),
    reportTitle: "Независимая проверка сохранения в Drive",
    reportSubtitle: "запрошено ⇄ живой Drive",
    consentStore,
    auditId,
  });
}

registerAutoExecutor("gmail_save_attachment_to_drive", {
  rehash: autoRehash(rehashSaveAttachment),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as SaveAttachmentPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeSaveAttachmentCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_create_label ------------------------------------------------------

async function executeCreateLabelCore(
  g: GoogleClients,
  payload: CreateLabelPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.labels, async (l) => {
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
      return { id: res.data.id, name: res.data.name ?? l.name };
    } catch (e) {
      return { name: l.name, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.labels.length,
    verb: "Создано",
    summaryIcon: "🏷️",
    verify: (r) => postVerifyLabelExists(g, r.id ?? "", r.name),
    reportTitle: "Независимая проверка создания меток",
    reportSubtitle: "запрошено ⇄ живые метки Gmail",
    consentStore,
    auditId,
  });
}

registerAutoExecutor("gmail_create_label", {
  rehash: (addressing) => sha256(addressing),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as CreateLabelPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeCreateLabelCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_update_label -------------------------------------------------------

async function rehashUpdateLabel(g: GoogleClients, addressing: UpdateLabelPayload): Promise<string> {
  const fresh = await mapWithLimit(addressing.items, async (it) => {
    const live = await fetchLabel(g, it.labelId);
    return { labelId: it.labelId, currentName: live?.name ?? "__UNREADABLE__" };
  });
  return sha256({ account: addressing.account, items: fresh });
}

async function executeUpdateLabelCore(
  g: GoogleClients,
  payload: UpdateLabelPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.items, async (item) => {
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
      return { id: res.data.id ?? item.labelId, name: res.data.name ?? item.name ?? item.currentName };
    } catch (e) {
      return { id: item.labelId, name: item.name ?? item.currentName, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Обновлено",
    summaryIcon: "✏️",
    verify: (r) => postVerifyLabelExists(g, r.id, r.name),
    reportTitle: "Независимая проверка изменения меток",
    reportSubtitle: "запрошено ⇄ живые метки Gmail",
    consentStore,
    auditId,
  });
}

registerAutoExecutor("gmail_update_label", {
  rehash: autoRehash(rehashUpdateLabel),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as UpdateLabelPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeUpdateLabelCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_delete_label -------------------------------------------------------

async function rehashDeleteLabel(g: GoogleClients, addressing: DeleteLabelPayload): Promise<string> {
  const fresh = await mapWithLimit(addressing.labels, async (it) => {
    const live = await fetchLabel(g, it.id);
    return { id: it.id, name: live?.name ?? "__UNREADABLE__" };
  });
  return sha256({ account: addressing.account, labels: fresh });
}

async function executeDeleteLabelCore(
  g: GoogleClients,
  payload: DeleteLabelPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const results = await mapWithLimit(payload.labels, async (l) => {
    try {
      await g.gmail.users.labels.delete({ userId: "me", id: l.id });
      return { id: l.id, name: l.name };
    } catch (e) {
      return { id: l.id, name: l.name, error: String(e instanceof Error ? e.message : e) };
    }
  });
  return buildMutationResult({
    results,
    total: payload.labels.length,
    verb: "Удалено",
    summaryIcon: "🗑️",
    verify: (r) => postVerifyLabelGone(g, r.id, r.name),
    reportTitle: "Независимая проверка удаления меток",
    reportSubtitle: "запрошено ⇄ живые метки Gmail",
    consentStore,
    auditId,
    preSnapshot: payload.labels.map((l) => ({ id: l.id, name: l.name, messageCount: l.messageCount })),
  });
}

registerAutoExecutor("gmail_delete_label", {
  rehash: autoRehash(rehashDeleteLabel),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as DeleteLabelPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeDeleteLabelCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_export_thread_eml ------------------------------------------------

/** Cheap identity read for plan/rehash: shared by both (moved to module scope
 * so `rehash` — now module-level for the auto-executor — can call the exact
 * same function the `plan` phase uses; previously a local closure duplicated
 * for each `registerGmailTools()` invocation, now a single top-level fn). */
async function readThreadIdentity(g: GoogleClients, id: string): Promise<{ subject: string; messageCount: number }> {
  const stub = await g.gmail.users.threads.get({
    userId: "me",
    id,
    format: "metadata",
    metadataHeaders: ["Subject"],
  });
  const msgs = stub.data.messages ?? [];
  if (!msgs.length) throw new Error(`Тред ${id} не найден или пуст.`);
  const subject = header(msgs[0].payload?.headers, "Subject") || "(без темы)";
  return { subject, messageCount: msgs.length };
}

async function rehashExportThread(g: GoogleClients, addressing: ExportThreadPayload): Promise<string> {
  try {
    const { subject, messageCount } = await readThreadIdentity(g, addressing.threadId);
    return sha256({ ...addressing, subject, messageCount });
  } catch {
    return sha256({ ...addressing, subject: "__UNREADABLE__", messageCount: -1 });
  }
}

async function executeExportThreadCore(
  g: GoogleClients,
  payload: ExportThreadPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  const stub = await g.gmail.users.threads.get({ userId: "me", id: payload.threadId, format: "minimal" });
  const ids = (stub.data.messages ?? []).map((m) => m.id).filter((x): x is string => !!x);
  if (!ids.length) {
    await consentStore
      .updateConsentAuditOutcome(auditId, { outcome: "failed", error: `thread ${payload.threadId} has no messages` })
      .catch(() => {});
    return fail(`Thread ${payload.threadId} has no messages (check the threadId).`);
  }
  const allMessages = await mapWithLimit(ids, (id) =>
      g.gmail.users.messages.get({ userId: "me", id, format: "raw" }).then((r) => r.data),);
  const messages =
    payload.scope === "last"
      ? [allMessages[allMessages.length - 1]]
      : payload.scope === "first"
        ? [allMessages[0]]
        : allMessages;

  let parentId = payload.folderId;
  if (payload.folderName) {
    const folder = await g.drive.files.create({
      requestBody: {
        name: payload.folderName,
        mimeType: "application/vnd.google-apps.folder",
        parents: payload.folderId ? [payload.folderId] : undefined,
      },
      fields: "id",
    });
    parentId = folder.data.id ?? payload.folderId;
  }

  const rawBuf = (m: gmail_v1.Schema$Message) => Buffer.from(m.raw ?? "", "base64url");
  const produced: { fileId?: string | null; fileName?: string | null; error?: string }[] = [];

  if (payload.format === "mbox") {
    try {
      const parts: Buffer[] = [];
      for (const m of messages) {
        const raw = rawBuf(m);
        parts.push(Buffer.from(mboxFromLine(raw.toString("latin1")), "latin1"));
        parts.push(escapeMboxFrom(raw));
        parts.push(Buffer.from("\n", "latin1"));
      }
      const mbox = Buffer.concat(parts);
      const subj = decodeMimeWords(headerFromRaw(rawBuf(messages[0]).toString("latin1"), "Subject")) || payload.subject;
      const res = await g.drive.files.create({
        requestBody: { name: `${sanitizeName(subj)}.mbox`, parents: parentId ? [parentId] : undefined },
        media: { mimeType: "application/mbox", body: Readable.from(mbox) },
        fields: "id,name,webViewLink,size",
      });
      produced.push({ fileId: res.data.id, fileName: res.data.name });
    } catch (e) {
      produced.push({ error: String(e instanceof Error ? e.message : e) });
    }
  } else {
    const files = await mapWithLimit(messages, async (m, i) => {
      try {
        const buf = rawBuf(m);
        const raw = buf.toString("latin1");
        const stamp = dateStamp(headerFromRaw(raw, "Date"));
        const subj = decodeMimeWords(headerFromRaw(raw, "Subject")) || "no-subject";
        const prefix = messages.length > 1 ? `${String(i + 1).padStart(2, "0")}_` : "";
        const name = `${prefix}${stamp ? stamp + "_" : ""}${sanitizeName(subj)}.eml`;
        const res = await g.drive.files.create({
          requestBody: { name, parents: parentId ? [parentId] : undefined },
          media: { mimeType: "message/rfc822", body: Readable.from(buf) },
          fields: "id,name,webViewLink,size",
        });
        return { fileId: res.data.id, fileName: res.data.name };
      } catch (e) {
        return { error: String(e instanceof Error ? e.message : e) };
      }
    });
    produced.push(...files);
  }

  const result = await buildMutationResult({
    results: produced,
    total: produced.length,
    verb: "Экспортировано",
    summaryIcon: "📧",
    verify: (r) => postVerifyDriveFileExists(g, r.fileId, r.fileName ?? payload.subject),
    reportTitle: "Независимая проверка экспорта треда",
    reportSubtitle: "запрошено ⇄ живой Drive",
    consentStore,
    auditId,
    preSnapshot: { threadId: payload.threadId, subject: payload.subject, messageCount: payload.messageCount },
    extra: { folderId: parentId ?? null },
  });
  return result;
}

registerAutoExecutor("gmail_export_thread_eml", {
  rehash: autoRehash(rehashExportThread),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as ExportThreadPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeExportThreadCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

// ---- gmail_create_upload_session -------------------------------------------

async function executeUploadSessionCore(
  g: GoogleClients,
  payload: UploadSessionPayload,
  auditId: string,
  consentStore: ConsentStore,
  fetchDeps?: SafeFetchDeps,
): Promise<CallToolResult> {
  const token = await g.accessToken();
  const folderId = await ensureUploadFolder(g);
  const results = await mapWithLimit(payload.files, async ({ name, mimeType, sizeBytes }) => {
    try {
      const contentType = mimeType ?? "application/octet-stream";
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

      // safeGoogleFetch, а не голый fetch: здесь уходит Bearer-токен аккаунта,
      // и молча последовать за перенаправлением на чужой хост означало бы
      // отдать этот токен туда. Сам адрес собран из константы
      // DRIVE_UPLOAD_ENDPOINT, но проверка единая для всех исходящих.
      const res = await safeGoogleFetch(
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
        fetchDeps,
      );
      if (!res.ok) {
        return { name, error: `Google refused the session (HTTP ${res.status}): ${(await res.text()).slice(0, 500)}` };
      }
      const uploadUrl = res.headers.get("location");
      if (!uploadUrl) {
        return { name, error: "Google accepted the request but returned no Location header (no session URI)." };
      }
      // Даже адрес, пришедший от самого Google, проверяем: дальше по нему
      // будет ходить сервер (gmail_confirm_upload), и хранить непроверенный
      // адрес — значит отложить проблему, а не решить её.
      try {
        assertAllowedGoogleUrl(uploadUrl);
      } catch (e) {
        return {
          name,
          error: `Google вернул недопустимый адрес сессии загрузки (${e instanceof Error ? e.message : String(e)}).`,
        };
      }
      const remembered = await rememberUploadSession({
        account: payload.account,
        uploadUrl,
        driveFileId: fileId,
        name: name ?? null,
        mimeType: contentType,
        sizeBytes: sizeBytes ?? null,
      });
      return {
        name,
        driveFileId: fileId,
        // Непрозрачный идентификатор — ИМЕННО ЕГО ждёт обратно
        // `gmail_confirm_upload`. Сам адрес обратно не принимается (SSRF).
        sessionId: remembered.sessionId,
        uploadUrl,
        mimeType: contentType,
        sizeBytes: sizeBytes ?? null,
        howTo:
          `PUT ${uploadUrl} with header "Content-Type: ${contentType}"` +
          (sizeBytes ? ` and "Content-Length: ${sizeBytes}"` : "") +
          ", body = the raw file bytes. Then check it with gmail_confirm_upload using the " +
          "`sessionId` above (NOT the uploadUrl — the server keeps the address itself and does " +
          "not accept one from a tool argument).",
        thenSend: `Attach it with attachments: [{"driveFileId": "${fileId}"}].`,
      };
    } catch (e) {
      return { name, error: String(e instanceof Error ? e.message : e) };
    }
  });
  const result = await buildMutationResult({
    results,
    total: payload.files.length,
    verb: "Открыто",
    summaryIcon: "🚀",
    verify: (r) => postVerifyDriveFileExists(g, r.driveFileId, r.name),
    reportTitle: "Независимая проверка загрузочных сессий",
    reportSubtitle: "запрошено ⇄ живой Drive (плейсхолдер; сама загрузка байт клиентом здесь НЕ проверяется)",
    consentStore,
    auditId,
    note:
      "Gmail will only carry the attachment once the client has PUT the bytes — a message sent before that " +
      "would go out with an empty file. Check with gmail_confirm_upload when in doubt. " +
      "Gmail caps a whole message at 25 MB.",
  });
  return result;
}

registerAutoExecutor("gmail_create_upload_session", {
  rehash: (addressing) => sha256(addressing),
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as UploadSessionPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeUploadSessionCore(g, p, auditId, ctx.consentStore, ctx.safeFetch);
    return extractText(result);
  },
});

// ---- gmail_get_download_url -------------------------------------------------
//
// ГЕЙТОВАН. Раньше был помечен `readOnlyHint` и вызывался моделью без единой
// кнопки. «Только чтение» здесь — иллюзия: инструмент не читает вложение, он
// РАЗДАЁТ К НЕМУ ДОСТУП. Выданная ссылка сама является доступом: кто её
// получил — скачает вложение без всякой авторизации, живёт она до 12 часов и
// НЕ ОТЗЫВАЕТСЯ. Для почты это хуже, чем для Диска: вложение — это кусок
// переписки, и утечка такой ссылки в лог, в чат или в чужой контекст равна
// утечке самого письма. По последствиям это выдача прав, а не чтение.
//
// Binding РЕАЛЬНЫЙ: перечитывает живое письмо и ищет в нём это вложение
// (имя, тип, размер) — если между планом и подтверждением письмо удалили или
// вложение стало другим, дрейф ловится и ссылка не выдаётся.

export interface DownloadUrlItem {
  messageId: string;
  attachmentId: string;
  filename?: string;
  mimeType?: string;
}
export interface DownloadUrlPayload {
  account: string;
  ttlMinutes: number;
  items: DownloadUrlItem[];
}

/** Живой снимок каждого запрошенного вложения — основа биндинга и превью. */
async function downloadUrlBindingSnapshot(g: GoogleClients, items: DownloadUrlItem[]) {
  return mapWithLimit(items, async (item) => {
    try {
      const msg = await g.gmail.users.messages.get({ userId: "me", id: item.messageId, format: "full" });
      const found = collectAttachments(msg.data.payload).find((a) => a.attachmentId === item.attachmentId);
      const subject = header(msg.data.payload?.headers, "Subject");
      const from = header(msg.data.payload?.headers, "From");
      return {
        messageId: item.messageId,
        attachmentId: item.attachmentId,
        found: !!found,
        // ЖИВЫЕ имя/тип из письма — это и есть личность вложения, за которую
        // отвечает биндинг: подменить файл за тем же attachmentId, не сломав
        // хэш, нельзя. Имя, которое передал вызывающий, хранится ОТДЕЛЬНО
        // (`saveAs`) и в превью показывается отдельной пометкой — иначе
        // согласие можно было бы получить под чужим именем файла.
        filename: found?.filename ?? null,
        mimeType: found?.mimeType ?? null,
        saveAs: item.filename ?? null,
        mimeTypeOverride: item.mimeType ?? null,
        size: found?.size ?? null,
        subject: subject || null,
        from: from || null,
      };
    } catch {
      // Письмо не прочиталось (удалено/нет прав/чужой id). Это НЕ ошибка
      // плана: вызывающий мог задать имя и тип сам. Но в снимке это видно, и
      // в превью человек прочитает «письмо перечитать не удалось».
      return {
        messageId: item.messageId,
        attachmentId: item.attachmentId,
        found: false,
        filename: null,
        mimeType: null,
        saveAs: item.filename ?? null,
        mimeTypeOverride: item.mimeType ?? null,
        size: null,
        subject: null,
        from: null,
      };
    }
  });
}

async function downloadUrlRehash(g: GoogleClients, addressing: unknown): Promise<string> {
  const a = addressing as DownloadUrlPayload;
  const snapshot = await downloadUrlBindingSnapshot(g, a.items);
  return sha256({ account: a.account, ttlMinutes: a.ttlMinutes, items: snapshot });
}

/** Человеческая формулировка того, ЧТО именно подтверждает владелец. Вынесена
 * отдельной функцией, потому что это и есть текст, который человек читает
 * над кнопкой «✅ Подтвердить» в Telegram: невнятный текст обесценивает всю
 * кнопку — подтверждают то, что поняли. */
export function downloadUrlConsentWarning(ttlMinutes: number, expiresAtMs: number): string {
  return (
    "⚠️ **Ссылка — это и есть доступ к вложению.** Любой, у кого она окажется (переслали, попала в " +
    "лог, в чужой контекст), скачает файл БЕЗ входа в почту и без каких-либо прав. " +
    `**Отозвать выданную ссылку нельзя** — она работает, пока не истечёт срок: ${ttlMinutes} мин ` +
    `(примерно до ${formatLaTime(expiresAtMs)} PT).`
  );
}

/** Хвост превью: буквально расшифровывает, что делает кнопка подтверждения. */
export function downloadUrlConsentButtonLine(count: number, ttlMinutes: number): string {
  return (
    `_Кнопка «✅ Подтвердить» означает: ВЫДАТЬ ${count === 1 ? "ссылку" : `${count} ссылки`}, по ` +
    `${count === 1 ? "которой" : "которым"} вложение скачает любой, у кого она есть; отозвать нельзя; ` +
    `живёт ~${ttlMinutes} мин._`
  );
}

/** Post-verify для выданной ссылки: токен реально сохранён и указывает на то
 * же самое вложение (а не «сервер сказал, что выдал»). */
export async function postVerifyDownloadLink(
  downloadUrl: string | null | undefined,
  messageId: string,
  attachmentId: string,
  label: string,
): Promise<VerifyLine & { detail: string }> {
  const lbl = safeText(label) || "(вложение)";
  if (!downloadUrl) {
    return { outcome: "warn", line: `- ⚠️ **«${lbl}»** — ссылка не выдана`, detail: "no link" };
  }
  const token = downloadUrl.split("/dl/")[1] ?? "";
  const target = await resolveDownloadLink(token);
  if (!target) {
    return {
      outcome: "mismatch",
      line: `- ❌ **«${lbl}»** — выданной ссылки нет в хранилище сервера`,
      detail: "token missing",
    };
  }
  if (target.messageId !== messageId || target.attachmentId !== attachmentId) {
    return {
      outcome: "mismatch",
      line: `- ❌ **«${lbl}»** — ссылка ведёт к другому вложению (${safeText(target.messageId, 40)}/${safeText(target.attachmentId, 40)})`,
      detail: "wrong target",
    };
  }
  return {
    outcome: "ok",
    line: `- ✅ **«${lbl}»** — ссылка действует до ${formatLaTime(target.expiresAt)} PT и ведёт к этому вложению; отозвать её нельзя`,
    detail: "issued",
  };
}

async function executeGetDownloadUrlCore(
  g: GoogleClients,
  payload: DownloadUrlPayload,
  auditId: string,
  consentStore: ConsentStore,
): Promise<CallToolResult> {
  interface LinkResult {
    messageId: string;
    attachmentId: string;
    filename?: string;
    mimeType?: string;
    bytes?: number | null;
    downloadUrl?: string;
    expiresAt?: string;
    error?: string;
  }
  const results = await mapWithLimit<DownloadUrlItem, LinkResult>(payload.items, async (item) => {
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
          account: payload.account,
          messageId: item.messageId,
          attachmentId: item.attachmentId,
          name: filename || "attachment",
          mimeType: mimeType ?? "application/octet-stream",
          size,
        },
        payload.ttlMinutes,
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
  const result = await buildMutationResult({
    results,
    total: payload.items.length,
    verb: "Выдано ссылок:",
    summaryIcon: "🔗",
    verify: (r) => postVerifyDownloadLink(r.downloadUrl, r.messageId, r.attachmentId, r.filename ?? r.messageId),
    reportTitle: "Независимая проверка выданных ссылок",
    reportSubtitle: "выданная ссылка ⇄ запись в хранилище ссылок сервера",
    consentStore,
    auditId,
    note:
      "Каждая ссылка работает без какого-либо входа, пока не истечёт срок — обращайтесь с ней как с паролем " +
      "к этому одному файлу. Отозвать её нельзя.",
  });
  return result;
}

registerAutoExecutor("gmail_get_download_url", {
  rehash: (addressing, ctx: AutoExecutorCtx) => {
    const p = addressing as DownloadUrlPayload;
    return downloadUrlRehash(ctx.clients.resolve(p.account), addressing);
  },
  execute: async (payload, auditId, ctx: AutoExecutorCtx) => {
    const p = payload as DownloadUrlPayload;
    const g = ctx.clients.resolve(p.account);
    const result = await executeGetDownloadUrlCore(g, p, auditId, ctx.consentStore);
    return extractText(result);
  },
});

export function registerGmailTools(
  server: McpServer,
  clients: UserClients,
  snoozeCtx: GmailSnoozeContext = {
    store: null,
    userToken: null,
    consentStore: null,
    consentCfg: DEFAULT_CONSENT_CFG,
    auditStore: null,
  },
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
      annotations: { readOnlyHint: true },
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
        summary: `🔍 Поиск Gmail «${q || "(всё)"}» — ${msgs.length} ${plural(msgs.length, "письмо", "письма", "писем")}${list.data.nextPageToken ? " (есть следующая страница)" : ""}`,
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
      annotations: { readOnlyHint: true },
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
        summary: `📊 ${count}${!!pageToken ? "+" : ""} ${countThreads ? plural(count, "переписка", "переписки", "переписок") : plural(count, "письмо", "письма", "писем")} по запросу «${q || "(вся почта)"}»`,
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
      annotations: { readOnlyHint: true },
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
        summary: `📧 Получено ${ok_.length}/${messageIds.length} ${plural(messageIds.length, "письмо", "письма", "писем")}${err_.length ? ` (ошибок: ${err_.length})` : ""}`,
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
      annotations: { readOnlyHint: true },
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
        summary: `📧 Получено ${ok_.length}/${threadIds.length} ${plural(threadIds.length, "цепочка", "цепочки", "цепочек")}`,
        results,
      });
    }),
  );

  // ---- gmail_send (array) --------------------------------------------------

  server.registerTool(
    "gmail_send",
    {
      title: "Send emails",
      description:
        "Send one or more new emails (optionally with attachments). Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with `messages`) " +
        "to build a plan and return a human-readable preview — NOTHING is sent yet. Show that preview to the " +
        "user verbatim and wait for their reply. Call again with the returned `manifest_id` and the user's " +
        "VERBATIM `user_reply` to actually send — the approved batch is read back from the plan, not from " +
        "whatever `messages` the second call carries (if any is passed, it is ignored). " +
        "`to`/`cc`/`bcc` may be comma-separated lists.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, messages, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Отправка недоступна: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести письмо через гейт подтверждения и поэтому не отправляет — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);
      const selfEmail = await accountEmail(g, accountName);
      const fromLabel = selfEmail ? `${accountName} (${selfEmail})` : accountName;

      const decision = await requireConsent<SendBatchPayload>({
        tool: "gmail_send",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: () => {
          if (!messages || !messages.length) {
            throw new Error("Нужен непустой `messages`, чтобы построить план отправки.");
          }
          const payload: SendBatchPayload = { account: accountName, messages };
          const preview = renderSendPreview({
            verb: "Отправка письма",
            fromLabel,
            items: messages.map((m) => ({
              to: m.to,
              cc: m.cc,
              bcc: m.bcc,
              subject: m.subject,
              body: m.body,
              attachments: m.attachments?.length,
              attachmentNames: m.attachments
                ?.map((a) => a.filename ?? a.driveFileId ?? "файл")
                .filter((x): x is string => !!x),
            })),
          });
          return { payload, objectHash: sha256(payload), preview, batchSize: messages.length };
        },
        // Binding вырождена (план §A3 / вывод 0.2): новое письмо не привязано ни
        // к какому живому объекту, который можно перечитать — единственная
        // защита в том, что payload берётся ИЗ манифеста (см. confirmed ниже),
        // а не из аргументов execute-вызова. sha256(addressing) допустим ЗДЕСЬ
        // ИМЕННО потому, что addressing УЖЕ равен payload — нет отдельного
        // "живого мира", способного разойтись с ним. Контраст: gmail_reply/
        // gmail_forward ниже реально сходят в Gmail за свежим состоянием.
        rehash: (addressing) => sha256(addressing),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeSendBatchCore(g, accountName, selfEmail, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_reply (array) -------------------------------------------------

  server.registerTool(
    "gmail_reply",
    {
      title: "Reply to emails",
      description:
        "Reply within the same thread of one or more existing messages. Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with `replies`) " +
        "to build a plan — this ONLY reads the original message(s), it creates no draft and sends nothing. Show " +
        "the returned preview to the user verbatim and wait for their reply (note: if the original message was " +
        "sent BY this account, the preview warns the reply will go back to yourself). Call again with the " +
        "returned `manifest_id` and the user's VERBATIM `user_reply` to actually send.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, replies, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Ответ недоступен: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести письмо через гейт подтверждения и поэтому не отправляет — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);
      const selfEmail = await accountEmail(g, accountName);
      const fromLabel = selfEmail ? `${accountName} (${selfEmail})` : accountName;

      const decision = await requireConsent<ReplyBatchPayload>({
        tool: "gmail_reply",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        // Plan phase ONLY reads the originals (messages.get) to resolve the
        // real recipient and build the preview — no drafts.create here (that
        // was the incident-2 precursor: a draft is a mutation too). The exact
        // same metadata call the old single-phase handler used, just moved
        // earlier and re-used at execute time instead of repeated (vывод 0.9).
        plan: async () => {
          if (!replies || !replies.length) {
            throw new Error("Нужен непустой `replies`, чтобы построить план ответа.");
          }
          const items: ReplyPlanItem[] = await mapWithLimit(replies, async (item) => {
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
            return {
              messageId: item.messageId,
              body: item.body,
              replyAll: item.replyAll ?? false,
              attachments: item.attachments,
              fromAddr,
              resolvedTo: extractEmail(fromAddr),
              subject,
              messageIdHeader,
              references,
              threadId: orig.data.threadId ?? undefined,
              cc,
            };
          });
          const payload: ReplyBatchPayload = { account: accountName, replies: items };
          const preview = renderSendPreview({
            verb: "Ответ на письмо",
            fromLabel,
            items: items.map((it) => ({
              to: it.fromAddr,
              cc: it.cc,
              subject: it.subject,
              body: it.body,
              attachments: it.attachments?.length,
              // Incident-2 prevention (vывод 0.7): warn, don't refuse — notes to
              // self are legitimate; the gate's confirmation step is the real guard.
              warning:
                selfEmail && it.resolvedTo && it.resolvedTo === selfEmail.toLowerCase()
                  ? "Ответ уйдёт отправителю исходного письма. Исходное отправлено ВАМИ — ответ придёт вам же."
                  : undefined,
            })),
          });
          return { payload, objectHash: sha256(payload), preview, batchSize: items.length };
        },
        // Real binding, not degenerate: re-reads each original message's From
        // header RIGHT NOW and recomputes resolvedTo. Everything else in the
        // item is copied verbatim from the stored payload (unchanged) — so the
        // resulting hash differs from objectHash ONLY when the live recipient
        // drifted or the original became unreadable (deleted). That is what
        // makes this a real re-read, not `sha256(addressing)` in disguise: the
        // comparison's outcome depends on live Gmail state, not just on what
        // was already in the manifest.
        rehash: (addressing) => rehashReplyBatch(g, addressing as ReplyBatchPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeReplyBatchCore(g, accountName, selfEmail, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_forward (array) -----------------------------------------------

  server.registerTool(
    "gmail_forward",
    {
      title: "Forward emails",
      description:
        "Forward one or more existing messages (including their attachments) to new recipients. Two-mode " +
        "consent-gated tool (mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` " +
        "(with `items`) to build a plan and return a preview — nothing is forwarded yet. Show the preview to the " +
        "user verbatim and wait for their reply. Call again with the returned `manifest_id` and the user's " +
        "VERBATIM `user_reply` to actually forward.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, items, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Пересылка недоступна: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести письмо через гейт подтверждения и поэтому не отправляет — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);
      const selfEmail = await accountEmail(g, accountName);
      const fromLabel = selfEmail ? `${accountName} (${selfEmail})` : accountName;

      const decision = await requireConsent<ForwardBatchPayload>({
        tool: "gmail_forward",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        // Plan phase only reads the original (cheap metadata read) to build the
        // preview and an identity fingerprint (From/Subject) — attachment bytes
        // are NOT touched here, only at execute (avoids downloading/holding
        // large blobs for a plan that might never be confirmed).
        plan: async () => {
          if (!items || !items.length) {
            throw new Error("Нужен непустой `items`, чтобы построить план пересылки.");
          }
          const built: ForwardPlanItem[] = await mapWithLimit(items, async (item) => {
            const orig = await g.gmail.users.messages.get({
              userId: "me",
              id: item.messageId,
              format: "metadata",
              metadataHeaders: ["From", "Subject", "Date", "To"],
            });
            const h = orig.data.payload?.headers;
            const origFrom = header(h, "From");
            const origSubject = header(h, "Subject");
            let subject = origSubject;
            if (!/^fwd:/i.test(subject)) subject = "Fwd: " + subject;
            return { messageId: item.messageId, to: item.to, body: item.body, subject, origFrom, origSubject };
          });
          const payload: ForwardBatchPayload = { account: accountName, items: built };
          const preview = renderSendPreview({
            verb: "Пересылка письма",
            fromLabel,
            items: built.map((it) => ({
              to: it.to,
              subject: it.subject,
              body:
                (it.body ? it.body + "\n\n" : "") +
                `[Пересылается письмо от ${it.origFrom || "?"}: «${it.origSubject || "(без темы)"}»]`,
            })),
          });
          return { payload, objectHash: sha256(payload), preview, batchSize: built.length };
        },
        // Real binding: re-reads each original's From/Subject right now — if the
        // message vanished (trashed/deleted) or its identity fingerprint changed
        // since the plan, the recomputed hash differs from objectHash and the
        // gate refuses "state changed, build a new plan" rather than forwarding
        // whatever it can still find.
        rehash: (addressing) => rehashForwardBatch(g, addressing as ForwardBatchPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeForwardBatchCore(g, accountName, selfEmail, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_create_draft (array) ------------------------------------------

  server.registerTool(
    "gmail_create_draft",
    {
      title: "Create drafts",
      description:
        "Create one or more draft emails (not sent) for the user to review/send later. Two-mode consent-gated " +
        "tool (mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with " +
        "`drafts`) to build a plan and return a preview — nothing is created yet. Show the preview to the user " +
        "verbatim and wait for their reply. Call again with the returned `manifest_id` and the user's VERBATIM " +
        "`user_reply` to actually create the draft(s).",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, drafts, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Создание черновика недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не " +
            "может провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);
      const selfEmail = await accountEmail(g, accountName);
      const fromLabel = selfEmail ? `${accountName} (${selfEmail})` : accountName;

      const decision = await requireConsent<DraftBatchPayload>({
        tool: "gmail_create_draft",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: () => {
          if (!drafts || !drafts.length) {
            throw new Error("Нужен непустой `drafts`, чтобы построить план создания черновика.");
          }
          const payload: DraftBatchPayload = { account: accountName, drafts };
          const preview = renderSendPreview({
            verb: "Создание черновика",
            fromLabel,
            items: drafts.map((d) => ({
              to: d.to,
              cc: d.cc,
              bcc: d.bcc,
              subject: d.subject,
              body: d.body,
              attachments: d.attachments?.length,
            })),
          });
          return { payload, objectHash: sha256(payload), preview, batchSize: drafts.length };
        },
        // Degenerate binding (same reasoning as gmail_send/gmail_create_label):
        // a not-yet-existing draft has no live object to re-read — the
        // protection is `payload` coming from the manifest, not this hash.
        rehash: (addressing) => sha256(addressing),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeDraftBatchCore(g, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_archive (array, absorbs batch_archive) ------------------------

  server.registerTool(
    "gmail_archive",
    {
      title: "Archive emails",
      description:
        "Archive one or more messages by removing them from the Inbox (they stay searchable). Two-mode " +
        "consent-gated tool (mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` " +
        "(with `messageIds`) to build a plan and return a preview — nothing is archived yet. Show the preview to " +
        "the user verbatim and wait for their reply. Call again with the returned `manifest_id` and the user's " +
        "VERBATIM `user_reply` to actually archive.",
      inputSchema: {
        account,
        messageIds: z
          .array(z.string())
          .optional()
          .describe(
            "Message id(s) to archive. Required to build a plan (first call, no manifest_id/user_reply). " +
              "Ignored on the execute call — the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, messageIds, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Архивирование недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<IdBatchPayload>({
        tool: "gmail_archive",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: () => buildIdBatchPlan(g, accountName, messageIds, "Архивирование писем", "archive"),
        rehash: (addressing) => rehashIdBatch(g, addressing as IdBatchPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeArchiveCore(g, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_trash (array, absorbs batch_trash) ----------------------------

  server.registerTool(
    "gmail_trash",
    {
      title: "Delete emails (to Trash)",
      description:
        "Move one or more messages to Trash (reversible; auto-purges after ~30 days). Two-mode consent-gated " +
        "tool (mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with " +
        "`messageIds`) to build a plan and return a preview — nothing is trashed yet. Show the preview to the " +
        "user verbatim and wait for their reply. Call again with the returned `manifest_id` and the user's " +
        "VERBATIM `user_reply` to actually trash.",
      inputSchema: {
        account,
        messageIds: z
          .array(z.string())
          .optional()
          .describe(
            "Message id(s) to trash. Required to build a plan (first call, no manifest_id/user_reply). " +
              "Ignored on the execute call — the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, messageIds, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Удаление в Корзину недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не " +
            "может провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<IdBatchPayload>({
        tool: "gmail_trash",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: () => buildIdBatchPlan(g, accountName, messageIds, "Удаление писем в Корзину", "trash"),
        rehash: (addressing) => rehashIdBatch(g, addressing as IdBatchPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeTrashCore(g, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_modify_labels (array, absorbs batch_modify_labels) ------------

  server.registerTool(
    "gmail_modify_labels",
    {
      title: "Modify labels (read/unread/star/...)",
      description:
        "Add and/or remove labels on one or more messages. System labels include UNREAD, STARRED, IMPORTANT, INBOX, SPAM. " +
        "Mark as read = remove UNREAD; star = add STARRED. Use gmail_list_labels for custom label ids. Two-mode " +
        "consent-gated tool (mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` " +
        "(with `items`, each {messageId, addLabelIds?, removeLabelIds?}) to build a plan and return a preview — " +
        "nothing is modified yet. Show the preview to the user verbatim and wait for their reply. Call again with " +
        "the returned `manifest_id` and the user's VERBATIM `user_reply` to actually modify.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, items, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Изменение меток недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<ModifyLabelsPayload>({
        tool: "gmail_modify_labels",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: async () => {
          if (!items || !items.length) {
            throw new Error("Нужен непустой `items`, чтобы построить план изменения меток.");
          }
          const idn = await fetchMsgIdentity(g, items.map((i) => i.messageId));
          const unreadable = items.filter((i) => idn.get(i.messageId) == null).map((i) => i.messageId);
          if (unreadable.length) {
            throw new Error(`Не удалось прочитать письмо(а) ${unreadable.join(", ")} — проверьте id. Ничего не изменено.`);
          }
          const built: ModifyLabelsItem[] = items.map((i) => {
            const m = idn.get(i.messageId)!;
            return {
              messageId: i.messageId,
              subject: m.subject,
              from: m.from,
              addLabelIds: i.addLabelIds ?? [],
              removeLabelIds: i.removeLabelIds ?? [],
            };
          });
          const payload: ModifyLabelsPayload = { account: accountName, items: built };
          const lines = built.map((it) => {
            const delta = [
              it.addLabelIds.length ? `+${it.addLabelIds.join(",")}` : "",
              it.removeLabelIds.length ? `-${it.removeLabelIds.join(",")}` : "",
            ]
              .filter(Boolean)
              .join(" ");
            return `- «${safeText(it.subject) || "(без темы)"}» (${it.messageId}) — ${safeText(it.from) || "?"}: ${delta || "(без изменений)"}`;
          });
          const preview = `### 📤 План: Изменение меток — ${built.length}\n\n${lines.join("\n")}`;
          return { payload, objectHash: sha256(modifyLabelsHashPayload(payload)), preview, batchSize: built.length };
        },
        // Real binding: re-reads subject/from for every messageId right now
        // (addLabelIds/removeLabelIds are the ACTION, not the identity being
        // bound — they come from the manifest's payload, protected the same
        // way gmail_send's messages are).
        rehash: (addressing) => rehashModifyLabels(g, addressing as ModifyLabelsPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeModifyLabelsCore(g, payload, auditId, consentStore);
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
        "says which happened, so this is never silently false advertising. Pass `unsnoozeAt` as an ISO 8601 " +
        "datetime, e.g. '2024-01-15T09:00:00'. Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with `items`) " +
        "to build a plan and return a preview — nothing is snoozed yet. Show the preview to the user verbatim " +
        "and wait for their reply. Call again with the returned `manifest_id` and the user's VERBATIM " +
        "`user_reply` to actually snooze.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, items, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Отложенный возврат в inbox недоступен: не настроено хранилище согласия (DATABASE_URL). Без него " +
            "сервер не может провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<SnoozeBatchPayload>({
        tool: "gmail_snooze",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: async () => {
          if (!items || !items.length) {
            throw new Error("Нужен непустой `items`, чтобы построить план отложенного возврата в inbox.");
          }
          const idn = await fetchMsgIdentity(g, items.map((i) => i.messageId));
          const unreadable = items.filter((i) => idn.get(i.messageId) == null).map((i) => i.messageId);
          if (unreadable.length) {
            throw new Error(`Не удалось прочитать письмо(а) ${unreadable.join(", ")} — проверьте id. Ничего не изменено.`);
          }
          const built: SnoozeItem[] = items.map((i) => {
            const m = idn.get(i.messageId)!;
            return { id: i.messageId, subject: m.subject, from: m.from, labelIds: m.labelIds, unsnoozeAt: i.unsnoozeAt };
          });
          const payload: SnoozeBatchPayload = { account: accountName, items: built };
          const lines = built.map((it) => {
            const d = new Date(it.unsnoozeAt);
            const when = isNaN(d.getTime()) ? `«${it.unsnoozeAt}» (не парсится!)` : `${formatLaTime(d.getTime())} PT`;
            return `- «${safeText(it.subject) || "(без темы)"}» (${it.id}) — ${safeText(it.from) || "?"}: разбудить ${when}`;
          });
          const preview = `### 📤 План: Отложенный возврат в inbox — ${built.length}\n\n${lines.join("\n")}`;
          return { payload, objectHash: sha256(idBatchHashPayload(payload)), preview, batchSize: built.length };
        },
        rehash: (addressing) => rehashIdBatch(g, addressing as IdBatchPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      const { store, userToken } = snoozeCtx;
      // userToken is null for onboarded (native-OAuth) deployments — that's
      // expected, not a reason to skip persisting; accountName alone is
      // enough for the scheduler to find the right account later.
      return executeSnoozeCore(g, accountName, payload, auditId, consentStore, store, userToken);
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
        "Two-mode consent-gated tool (mcp-development-standard/references/gate.md): call WITHOUT " +
        "`manifest_id`/`user_reply` (with `messages`) to build a plan and return a preview — nothing is queued " +
        "yet. Show the preview to the user verbatim and wait for their reply. Call again with the returned " +
        "`manifest_id` and the user's VERBATIM `user_reply` to actually queue it. " +
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, messages, manifest_id, user_reply, automation_key }) => {
      const { store, userToken, consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!store) {
        return fail(
          "Отложенная отправка недоступна: на сервере не настроен DATABASE_URL (Railway Postgres). Без него " +
            "негде хранить письмо до момента sendAt (запланированного времени отправки). Используйте " +
            "gmail_send, чтобы отправить прямо сейчас.",
        );
      }
      if (!consentStore) {
        return fail(
          "Отложенная отправка недоступна: не настроено хранилище согласия. Без него сервер не может провести " +
            "письмо через гейт подтверждения и поэтому не ставит его в очередь — обратитесь к администратору сервера.",
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
      const selfEmail = await accountEmail(g, accountName);
      const fromLabel = selfEmail ? `${accountName} (${selfEmail})` : accountName;

      const decision = await requireConsent<ScheduleBatchPayload>({
        tool: "gmail_schedule_send",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: () => {
          if (!messages || !messages.length) {
            throw new Error("Нужен непустой `messages`, чтобы построить план отложенной отправки.");
          }
          const payload: ScheduleBatchPayload = { account: accountName, messages };
          const preview = renderSendPreview({
            verb: "Отложенная отправка",
            fromLabel,
            items: messages.map((m) => {
              const d = new Date(m.sendAt);
              return {
                to: m.to,
                cc: m.cc,
                bcc: m.bcc,
                subject: m.subject,
                body: m.body,
                attachments: m.attachments?.length,
                sendAt: isNaN(d.getTime()) ? undefined : d,
              };
            }),
          });
          return { payload, objectHash: sha256(payload), preview, batchSize: messages.length };
        },
        // Degenerate binding, same reasoning as gmail_send: a not-yet-existing
        // scheduled message has no live external object to re-read — the whole
        // point is that it is built and validated at plan time and never
        // touched again except via the manifest.
        rehash: (addressing) => sha256(addressing),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      // Resolving attachments/building the raw MIME (inside the core fn) NOW,
      // rather than at sendAt, means a bad driveFileId or an over-quota Drive
      // fails this call instead of silently rotting in the queue.
      return executeScheduleSendCore(g, accountName, payload, auditId, consentStore, store, userToken);
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
        return ok({ summary: "Отложенных отправок нет — DATABASE_URL не настроен, очередь физически негде хранить.", results: [] });
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
        summary: `🕗 ${rows.length} ${plural(rows.length, "письмо", "письма", "писем")} со статусом «${wanted}»`,
        ...(note ? { note } : {}),
        results: rows.map((r) => ({
          id: r.id,
          to: r.toPreview,
          subject: r.subjectPreview,
          // Время — по Лос-Анджелесу (как в превью плана и журнале согласий),
          // а не в UTC: раньше два места одного сервера показывали одно и то же
          // событие в поясах, расходящихся летом на семь часов.
          sendAt: laIso(r.sendAt.getTime()),
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
      description:
        "Cancel one or more messages queued by gmail_schedule_send, as long as they have not already gone out. " +
        "There is no un-cancel: a cancelled message is never sent. Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with `ids`) to " +
        "build a plan and return a preview — nothing is cancelled yet. Show the preview to the user verbatim and " +
        "wait for their reply. Call again with the returned `manifest_id` and the user's VERBATIM `user_reply` to " +
        "actually cancel.",
      inputSchema: {
        account,
        ids: z
          .array(z.number().int())
          .optional()
          .describe(
            "Ids from gmail_list_scheduled_sends. Required to build a plan (first call, no manifest_id/" +
              "user_reply). Ignored on the execute call — the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, ids, manifest_id, user_reply, automation_key }) => {
      const { store, consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!store) {
        return fail("DATABASE_URL is not configured, so there is nothing scheduled to cancel.");
      }
      if (!consentStore) {
        return fail(
          "Отмена отложенной отправки недоступна: не настроено хранилище согласия (DATABASE_URL). Без него " +
            "сервер не может провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<CancelScheduledSendPayload>({
        tool: "gmail_cancel_scheduled_send",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        // Plan reads the LIVE queue: the preview names who each message was
        // going to, its subject and when it would have gone out — so the
        // person confirming sees what they are about to lose, not bare ids.
        plan: async () => {
          if (!ids || !ids.length) {
            throw new Error("Нужен непустой `ids`, чтобы построить план отмены отложенных отправок.");
          }
          const built = await readPendingScheduledSends(store, accountName, ids);
          const payload: CancelScheduledSendPayload = { account: accountName, items: built };
          const lines = built.map(
            (it) =>
              `- #${it.id} → **${safeText(it.toPreview, 80)}** — «${safeText(it.subjectPreview, 80)}», ушло бы ` +
              `${formatLaTime(new Date(it.sendAt).getTime())}`,
          );
          const preview =
            `### 📤 План: Отмена отложенной отправки — ${built.length}\n\n${lines.join("\n")}\n\n` +
            "Эти письма НЕ будут отправлены. Обратной операции нет.";
          return { payload, objectHash: sha256(payload), preview, batchSize: built.length };
        },
        rehash: (addressing) => rehashCancelScheduledSend(store, addressing as CancelScheduledSendPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeCancelScheduledSendCore(store, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_get_attachment (array) ----------------------------------------

  server.registerTool(
    "gmail_get_attachment",
    {
      title: "Download email attachments",
      description:
        "Download one or more attachments' content. Get `attachmentId` from gmail_get_message's `attachments`. " +
        "The attachment's real filename and MIME type are read FROM THE MESSAGE (they are not taken from the " +
        "call arguments), and an attachmentId that does not belong to the given messageId is refused outright. " +
        "Text attachments return as text; binaries as base64; `maxBytes` caps BOTH.",
      inputSchema: {
        account,
        items: z
          .array(
            z.object({
              messageId: z.string(),
              attachmentId: z.string(),
              maxBytes: z.number().int().min(1).max(8_000_000).default(750_000).optional(),
            }),
          )
          .min(1),
      },
      annotations: { readOnlyHint: true },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      // Identity-guard (mcp-development-standard §4): что за файл скачан —
      // решает ПИСЬМО, а не аргументы вызова. Приёмка 2026-08-07 показала три
      // следствия старого поведения: (1) `filename`/`mimeType` в ответе были
      // эхом аргументов («ВЫДУМАННОЕ-ИМЯ.zip» возвращалось как есть), то есть
      // проверить, что именно скачано, было нечем; (2) по этому же эху
      // выбиралась ветка «текст или base64», из-за чего `mimeType:"text/plain"`
      // на PNG снимал лимит; (3) `attachmentId` из письма А, поданный с
      // `messageId` письма Б (без вложений вовсе), возвращал 4619 байт и
      // «1/1 успешно» — сервер эхом подтверждал привязку, которой не было.
      // Теперь на каждое письмо делается один запрос за его структурой (кэш на
      // батч), и attachmentId обязан в этой структуре найтись.
      const metaCache = new Map<string, Promise<Map<string, { filename: string; mimeType: string; size: number }>>>();
      const attachmentsOf = (messageId: string) => {
        let pending = metaCache.get(messageId);
        if (!pending) {
          pending = (async () => {
            const res = await g.gmail.users.messages.get({ userId: "me", id: messageId, format: "full" });
            const map = new Map<string, { filename: string; mimeType: string; size: number }>();
            for (const a of collectAttachments(res.data.payload)) {
              map.set(a.attachmentId, { filename: a.filename, mimeType: a.mimeType, size: a.size });
            }
            return map;
          })();
          metaCache.set(messageId, pending);
        }
        return pending;
      };
      const results = await mapWithLimit(items, async (item) => {
          const base = { messageId: item.messageId, attachmentId: item.attachmentId };
          let known: { filename: string; mimeType: string; size: number } | undefined;
          try {
            known = (await attachmentsOf(item.messageId)).get(item.attachmentId);
          } catch (e) {
            // Fail-closed: не смогли прочитать письмо — не скачиваем вслепую.
            return {
              ...base,
              filename: null,
              mimeType: null,
              error: `🛑 Не удалось прочитать письмо ${item.messageId}, чтобы сверить с ним вложение: ${safeText(e instanceof Error ? e.message : e, 200)}. Ничего не скачано.`,
            };
          }
          if (!known) {
            return {
              ...base,
              filename: null,
              mimeType: null,
              error: `🛑 Вложение ${item.attachmentId} не принадлежит письму ${item.messageId} — в этом письме такого вложения нет. Возьмите attachmentId из поля attachments того же письма (gmail_get_message). Ничего не скачано.`,
            };
          }
          const limit = item.maxBytes ?? 750_000;
          const meta = { ...base, filename: known.filename, mimeType: known.mimeType };
          const tooLarge = (bytes: number) =>
            `Вложение «${safeText(known!.filename, 80)}» — ${bytes} ${plural(bytes, "байт", "байта", "байт")}, это больше лимита maxBytes=${limit}. Поднимите maxBytes (до 8 МБ) или сохраните файл на Диск через gmail_save_attachment_to_drive. Ничего не скачано.`;
          // Лимит проверяется ДО скачивания — по размеру из письма, — и
          // ПОВТОРНО по факту. Раньше проверка стояла после ветки isTextual,
          // и для текстовых вложений не работала вовсе: лог/csv/json любого
          // размера вливался в диалог целиком.
          if (known.size > limit) {
            return { ...meta, bytes: known.size, error: tooLarge(known.size) };
          }
          try {
            const res = await g.gmail.users.messages.attachments.get({
              userId: "me",
              messageId: item.messageId,
              id: item.attachmentId,
            });
            const buf = Buffer.from(res.data.data ?? "", "base64url");
            const full = { ...meta, bytes: buf.length };
            if (buf.length > limit) return { ...full, error: tooLarge(buf.length) };
            if (isTextual(known.mimeType)) {
              return { ...full, text: buf.toString("utf8"), encoding: "text" };
            }
            return { ...full, content: buf.toString("base64"), encoding: "base64" };
          } catch (e) {
            return { ...meta, error: String(e instanceof Error ? e.message : e) };
          }
        });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📎 Получено ${ok_.length}/${items.length} ${plural(items.length, "вложение", "вложения", "вложений")}`,
        results,
      });
    }),
  );

  // ---- gmail_get_attachment_text (array) -----------------------------------

  // NOT gated — a deliberate, and NARROW, exemption. Rationale: reading an
  // invoice PDF is a routine read-shaped question; a plan/confirm round-trip on
  // every one of them trains the owner to rubber-stamp confirmations, which is
  // how a gate quietly stops being a gate.
  //
  // What this tool is NOT is read-only, and it no longer implies otherwise (it
  // used to ship with NO annotations at all, which reads as "nothing to see
  // here"). Google's OCR forces a real Google Doc into the owner's Drive, so
  // this is a write, it is classified as one by the source scan in
  // scripts/test-gate-coverage.mjs, and it must stay accounted for there.
  //
  // Three properties are what make the exemption defensible rather than a
  // hidden hole (see cleanupOcrTempDoc above):
  //  1. the scratch copy goes to the TRASH, never files.delete — irreversible
  //     deletion must not be a side effect of reading text;
  //  2. an identity guard refuses to touch anything that is not our own
  //     "gmcp-ocr-tmp" Google Doc;
  //  3. a cleanup that fails is REPORTED in this tool's own result, not just
  //     logged — the previous version logged it and still answered a clean
  //     "extracted N/N", so the user never learned about the leftover.

  server.registerTool(
    "gmail_get_attachment_text",
    {
      title: "Read attachments as text (OCR)",
      description:
        "Extract the TEXT of one or more email attachments (PDF, scan, image) using Google Drive's built-in OCR. " +
        "Use this to actually READ invoices/receipt PDFs. NOT a pure read: Google's OCR only works on a Google " +
        `Doc, so this creates a temporary Google Doc ("${OCR_TEMP_NAME}") in YOUR Drive per attachment, reads the ` +
        "text, then moves that copy to the trash. If a copy cannot be cleaned up, the result says so explicitly " +
        "and names the leftover file id — pass that on to the user instead of reporting a clean run.",
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
      // No readOnlyHint: this creates and trashes a real Drive file. Reversible
      // (trash, not permanent delete) → destructiveHint: false.
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, items }) => {
      const g = clients.resolve(account);
      const leftovers: OcrCleanupFailure[] = [];
      const results = await mapWithLimit(items, async (item) => {
          let docId: string | null = null;
          try {
            const att = await g.gmail.users.messages.attachments.get({
              userId: "me",
              messageId: item.messageId,
              id: item.attachmentId,
            });
            const buffer = Buffer.from(att.data.data ?? "", "base64url");
            const created = await g.drive.files.create({
              requestBody: { name: OCR_TEMP_NAME, mimeType: GOOGLE_DOC_MIME },
              media: { mimeType: item.mimeType ?? "application/pdf", body: Readable.from(buffer) },
              ocrLanguage: item.ocrLanguage,
              fields: "id",
            });
            docId = created.data.id ?? null;
            if (!docId) {
              throw new Error("Google Drive did not return a file id for the temporary OCR document.");
            }
            const doc = await g.docs.documents.get({ documentId: docId });
            const text = documentToPlainText(doc.data);
            return { messageId: item.messageId, attachmentId: item.attachmentId, text };
          } catch (e) {
            return { messageId: item.messageId, attachmentId: item.attachmentId, error: String(e instanceof Error ? e.message : e) };
          } finally {
            if (docId) {
              const failure = await cleanupOcrTempDoc(g, docId, "gmail_get_attachment_text");
              if (failure) leftovers.push(failure);
            }
          }
        });
      const ok_ = results.filter((r) => !("error" in r));
      return ok({
        summary: `📄 Текст извлечён из ${ok_.length}/${items.length} ${plural(items.length, "вложения", "вложений", "вложений")}`,
        ...(leftovers.length ? { warning: ocrLeftoverWarning(leftovers), leftoverTempFiles: leftovers } : {}),
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
        "Get `attachmentId`/`filename` from gmail_get_message. Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with `items`) to " +
        "build a plan and return a preview — nothing is copied yet. Show the preview to the user verbatim and " +
        "wait for their reply. Call again with the returned `manifest_id` and the user's VERBATIM `user_reply` to " +
        "actually save to Drive.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, items, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Сохранение в Drive недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не " +
            "может провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<SaveAttachmentPayload>({
        tool: "gmail_save_attachment_to_drive",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        // Plan reads the MIME tree (format=full) to locate the attachment's
        // real filename/size for identity — it does NOT download the
        // attachment's bytes (those live behind a separate attachments.get
        // call, only made at execute), so a plan that never gets confirmed
        // never pulls a heavy blob for nothing.
        plan: async () => {
          if (!items || !items.length) {
            throw new Error("Нужен непустой `items`, чтобы построить план сохранения вложений в Drive.");
          }
          const built: SaveAttachmentItem[] = await mapWithLimit(items, async (item) => {
            const msg = await g.gmail.users.messages.get({ userId: "me", id: item.messageId, format: "full" });
            const found = collectAttachments(msg.data.payload).find((a) => a.attachmentId === item.attachmentId);
            if (!found) {
              throw new Error(
                `Вложение ${item.attachmentId} не найдено в письме ${item.messageId} — ничего не сохранено.`,
              );
            }
            return {
              messageId: item.messageId,
              attachmentId: item.attachmentId,
              filename: found.filename,
              size: found.size,
              fileName: item.fileName,
              folderId: item.folderId,
              mimeType: item.mimeType,
            };
          });
          const payload: SaveAttachmentPayload = { account: accountName, items: built };
          const lines = built.map(
            (it) =>
              `- «${safeText(it.filename)}» (${it.size} байт) из письма ${it.messageId} → Drive` +
              (it.folderId ? ` (папка ${it.folderId})` : "") +
              (it.fileName ? `, сохранить как «${safeText(it.fileName)}»` : ""),
          );
          const preview = `### 📤 План: Сохранение вложений в Drive — ${built.length}\n\n${lines.join("\n")}`;
          return {
            payload,
            objectHash: sha256({ account: accountName, items: built.map(({ messageId, attachmentId, filename, size }) => ({ messageId, attachmentId, filename, size })) }),
            preview,
            batchSize: built.length,
          };
        },
        // Real binding: re-reads each message's MIME tree right now and
        // re-locates the attachment — a vanished message/attachment or a
        // changed filename/size forces a mismatch instead of trusting the plan.
        rehash: (addressing) => rehashSaveAttachment(g, addressing as SaveAttachmentPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeSaveAttachmentCore(g, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_list_labels (unchanged) ---------------------------------------

  server.registerTool(
    "gmail_list_labels",
    {
      title: "List labels",
      description: "List all Gmail labels (system + custom) with their ids.",
      inputSchema: { account },
      annotations: { readOnlyHint: true },
    },
    guard(async ({ account }) => {
      const g = clients.resolve(account);
      const res = await g.gmail.users.labels.list({ userId: "me" });
      const labels = (res.data.labels ?? []).map((l) => ({ id: l.id, name: l.name, type: l.type }));
      const userLabels = labels.filter((l) => l.type === "user");
      const systemLabels = labels.filter((l) => l.type === "system");
      return ok({
        summary: `🏷️ ${labels.length} ${plural(labels.length, "ярлык", "ярлыка", "ярлыков")} — системных: ${systemLabels.length}, пользовательских: ${userLabels.length}`,
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
        "Tip: call gmail_list_labels first to check if a label with the same name already exists. Two-mode " +
        "consent-gated tool (mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` " +
        "(with `labels`) to build a plan and return a preview — nothing is created yet. Show the preview to the " +
        "user verbatim and wait for their reply. Call again with the returned `manifest_id` and the user's " +
        "VERBATIM `user_reply` to actually create.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, labels, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Создание метки недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<CreateLabelPayload>({
        tool: "gmail_create_label",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: () => {
          if (!labels || !labels.length) {
            throw new Error("Нужен непустой `labels`, чтобы построить план создания меток.");
          }
          const payload: CreateLabelPayload = { account: accountName, labels };
          const lines = labels.map((l) => `- «${safeText(l.name, 200)}»`);
          const preview = `### 📤 План: Создание меток — ${labels.length}\n\n${lines.join("\n")}`;
          return { payload, objectHash: sha256(payload), preview, batchSize: labels.length };
        },
        // Degenerate binding (same reasoning as gmail_send): a not-yet-existing
        // label has no live object to re-read — protection is `payload` coming
        // from the manifest, not this hash.
        rehash: (addressing) => sha256(addressing),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeCreateLabelCore(g, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_update_label (array) ------------------------------------------

  server.registerTool(
    "gmail_update_label",
    {
      title: "Update labels",
      description:
        "Rename one or more labels or change their visibility/color. Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with `items`) " +
        "to build a plan and return a preview — nothing is changed yet. Show the preview to the user verbatim " +
        "and wait for their reply. Call again with the returned `manifest_id` and the user's VERBATIM " +
        "`user_reply` to actually update.",
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
          .optional()
          .describe(
            "Required to build a plan (first call, no manifest_id/user_reply). Ignored on the execute call — " +
              "the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, items, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Изменение метки недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<UpdateLabelPayload>({
        tool: "gmail_update_label",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        // Plan reads the CURRENT name of every label — the identity-guard
        // pair (id + name) identity-postverify.md §4 requires: a caller
        // passing only an id gets the current name filled in by the server,
        // never asked to supply it (same convention as archive/trash above).
        plan: async () => {
          if (!items || !items.length) {
            throw new Error("Нужен непустой `items`, чтобы построить план изменения меток.");
          }
          const found = await mapWithLimit(items, (item) => fetchLabel(g, item.labelId));
          const missing = items.filter((_, i) => found[i] == null).map((i) => i.labelId);
          if (missing.length) {
            throw new Error(`Метка(и) ${missing.join(", ")} не найдена(ы) — проверьте id. Ничего не изменено.`);
          }
          const built: UpdateLabelItem[] = items.map((item, i) => ({
            labelId: item.labelId,
            currentName: found[i]!.name,
            name: item.name,
            labelListVisibility: item.labelListVisibility,
            messageListVisibility: item.messageListVisibility,
            backgroundColor: item.backgroundColor,
            textColor: item.textColor,
          }));
          const payload: UpdateLabelPayload = { account: accountName, items: built };
          const lines = built.map((it) => {
            const changes = [
              it.name && it.name !== it.currentName ? `имя → «${safeText(it.name, 200)}»` : undefined,
              it.labelListVisibility ? `видимость в списке → ${it.labelListVisibility}` : undefined,
              it.messageListVisibility ? `видимость у писем → ${it.messageListVisibility}` : undefined,
              it.backgroundColor || it.textColor ? "цвет" : undefined,
            ].filter((x): x is string => !!x);
            return `- Метка «${safeText(it.currentName)}» (${it.labelId}) → ${changes.join(", ") || "(без изменений)"}`;
          });
          const preview = `### 📤 План: Изменение меток — ${built.length}\n\n${lines.join("\n")}`;
          return {
            payload,
            objectHash: sha256({ account: accountName, items: built.map(({ labelId, currentName }) => ({ labelId, currentName })) }),
            preview,
            batchSize: built.length,
          };
        },
        // Real binding: re-reads each label's live name right now — catches a
        // concurrent rename between plan and execute.
        rehash: (addressing) => rehashUpdateLabel(g, addressing as UpdateLabelPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeUpdateLabelCore(g, payload, auditId, consentStore);
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
        "System labels (INBOX, SENT, etc.) cannot be deleted. Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with `labelIds`) " +
        "to build a plan and return a preview — nothing is deleted yet. Show the preview to the user verbatim " +
        "and wait for their reply. Call again with the returned `manifest_id` and the user's VERBATIM " +
        "`user_reply` to actually delete.",
      inputSchema: {
        account,
        labelIds: z
          .array(z.string())
          .optional()
          .describe(
            "Label ID(s) to delete. Required to build a plan (first call, no manifest_id/user_reply). Ignored " +
              "on the execute call — the approved batch is read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: true },
    },
    guard(async ({ account, labelIds, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Удаление метки недоступно: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<DeleteLabelPayload>({
        tool: "gmail_delete_label",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        // Plan reads each label's current name AND a best-effort message
        // count (identity-postverify.md §5.2 pre-snapshot requirement for
        // this irreversible op) — a failed count never blocks the plan, it
        // just shows 0 (informational only, never part of the hash below).
        plan: async () => {
          if (!labelIds || !labelIds.length) {
            throw new Error("Нужен непустой `labelIds`, чтобы построить план удаления меток.");
          }
          const built: DeleteLabelItem[] = await mapWithLimit(labelIds, async (id) => {
            const live = await fetchLabel(g, id);
            if (!live) throw new Error(`Метка ${id} не найдена — проверьте id. Ничего не изменено.`);
            let messageCount = 0;
            try {
              const r = await g.gmail.users.messages.list({ userId: "me", labelIds: [id], maxResults: 1 });
              messageCount = r.data.resultSizeEstimate ?? 0;
            } catch {
              /* best-effort — count is informational, never blocks the plan */
            }
            return { id, name: live.name, messageCount };
          });
          const payload: DeleteLabelPayload = { account: accountName, labels: built };
          const lines = built.map(
            (it) => `- Метка «${safeText(it.name)}» (${it.id}) — писем с этой меткой: ${it.messageCount}`,
          );
          const preview = `### 📤 План: Удаление меток — ${built.length}\n\n${lines.join("\n")}`;
          return {
            payload,
            objectHash: sha256({ account: accountName, labels: built.map(({ id, name }) => ({ id, name })) }),
            preview,
            batchSize: built.length,
          };
        },
        // Real binding: re-reads each label's live name right now — a
        // deleted/renamed label forces a mismatch instead of trusting the plan.
        rehash: (addressing) => rehashDeleteLabel(g, addressing as DeleteLabelPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeDeleteLabelCore(g, payload, auditId, consentStore);
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
        "one .mbox archive. Get threadId from gmail_search or gmail_get_thread. Two-mode consent-gated tool " +
        "(mcp-development-standard/references/gate.md): call WITHOUT `manifest_id`/`user_reply` (with " +
        "`threadId` etc.) to build a plan and return a preview — nothing is exported yet. Show the preview to " +
        "the user verbatim and wait for their reply. Call again with the returned `manifest_id` and the user's " +
        "VERBATIM `user_reply` to actually export.",
      inputSchema: {
        account,
        threadId: z
          .string()
          .optional()
          .describe(
            "Gmail thread id to export (also accepts a single message's threadId). Required to build a plan " +
              "(first call, no manifest_id/user_reply). Ignored on the execute call — read back from the manifest.",
          ),
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
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, threadId, folderId, folderName, format, scope, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Экспорт треда недоступен: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);
      const fmt = format ?? "eml_files";
      const scp = scope ?? "all";

      // Cheap identity read for plan/rehash: threads.get(format="metadata")
      // gives the message count AND the first message's Subject in ONE call —
      // no raw bytes fetched here (those only happen at execute). Module-level
      // `readThreadIdentity(g, id)` now (moved so `rehash` — module-level for
      // the auto-executor — can call the exact same function `plan` uses).

      const decision = await requireConsent<ExportThreadPayload>({
        tool: "gmail_export_thread_eml",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: async () => {
          if (!threadId) {
            throw new Error("Нужен непустой `threadId`, чтобы построить план экспорта.");
          }
          const { subject, messageCount } = await readThreadIdentity(g, threadId);
          const payload: ExportThreadPayload = {
            account: accountName,
            threadId,
            subject,
            messageCount,
            folderId,
            folderName,
            format: fmt,
            scope: scp,
          };
          const dest = folderName ? `новая папка «${safeText(folderName, 100)}»` : folderId ? `папка ${folderId}` : "корень Drive";
          const preview =
            `### 📤 План: Экспорт треда — 1\n\n` +
            `- «${safeText(subject)}» (${threadId}), сообщений: ${messageCount}, формат: ${fmt}, охват: ${scp} → ${dest}`;
          return { payload, objectHash: sha256(payload), preview };
        },
        // Real binding: re-reads the thread's live subject/message count right
        // now — a thread that vanished/grew/shrank since the plan forces a
        // mismatch instead of exporting whatever is still there.
        rehash: (addressing) => rehashExportThread(g, addressing as ExportThreadPayload),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeExportThreadCore(g, payload, auditId, consentStore);
    }),
  );

  // ---- gmail_get_download_url (array) --------------------------------------

  server.registerTool(
    "gmail_get_download_url",
    {
      title: "Выдать ссылку-доступ на вложение (скачает любой, у кого она есть)",
      description:
        "Hand out a temporary download link per attachment so the client (phone, browser, script) can fetch the " +
        "bytes directly, instead of gmail_get_attachment inlining them into this conversation. Use it for anything " +
        "large or binary, or whenever the user wants to keep the file rather than read its content here. " +
        "Get `attachmentId` from gmail_get_message; filename and type are looked up automatically when omitted. " +
        "THIS IS NOT A READ: the link IS the credential. Anyone holding it downloads that attachment with NO " +
        "sign-in and no permissions, and the link CANNOT be revoked — it works until it expires " +
        `(default ${DEFAULT_TTL_MINUTES} minutes, max ${MAX_TTL_MINUTES / 60} hours). Leaking it into a log, a chat ` +
        "or another context is equivalent to leaking that piece of the correspondence. It grants access to that " +
        "single attachment — not to the message, and not to the mailbox. That is why it is a " +
        "two-mode consent-gated tool (mcp-development-standard/references/gate.md): call WITHOUT " +
        "`manifest_id`/`user_reply` (with `items`) to build a plan and return a preview — NO link is issued yet. " +
        "Show the preview to the user verbatim and wait for their reply. Call again with the returned " +
        "`manifest_id` and the user's VERBATIM `user_reply` to actually issue the link(s).",
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
          .optional()
          .describe(
            "Attachments to mint links for. Required to build a plan (first call, no manifest_id/user_reply). " +
              "Ignored on the execute call — the approved batch is read back from the manifest.",
          ),
        ttlMinutes: z
          .number()
          .int()
          .min(1)
          .max(MAX_TTL_MINUTES)
          .optional()
          .describe(
            `How long each link stays valid. Default ${DEFAULT_TTL_MINUTES} minutes, hard maximum ` +
              `${MAX_TTL_MINUTES} minutes (${MAX_TTL_MINUTES / 60} hours). Part of what is confirmed.`,
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      // НЕ readOnlyHint и НЕ «безобидное» действие: инструмент выдаёт
      // неаутентифицированный, неотзываемый доступ тому, кому попадёт ссылка —
      // тот же класс, что drive_share в соседнем репозитории. Поэтому
      // destructiveHint: true (последствие необратимо) + openWorldHint: true
      // (ссылка уходит во внешний мир).
      annotations: { destructiveHint: true, openWorldHint: true },
    },
    guard(async ({ account, items, ttlMinutes, manifest_id, user_reply, automation_key }) => {
      if (!downloadsAvailable()) {
        return fail(
          "Download links are unavailable: this server does not know its own public URL. " +
            "Set PUBLIC_BASE_URL (on Railway, turn on public networking). " +
            "gmail_get_attachment still works for small attachments.",
        );
      }
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Выдача ссылок недоступна: не настроено хранилище согласия (DATABASE_URL). Без него сервер не может " +
            "провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);
      const ttl = Math.min(ttlMinutes ?? DEFAULT_TTL_MINUTES, MAX_TTL_MINUTES);

      const decision = await requireConsent<DownloadUrlPayload>({
        tool: "gmail_get_download_url",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        // План перечитывает MIME-дерево каждого письма (format=full) и берёт
        // ЖИВЫЕ имя/тип/размер вложения — байты не качаются, ссылка не
        // выдаётся, пока человек не подтвердит.
        plan: async () => {
          if (!items || !items.length) {
            throw new Error("Нужен непустой `items`, чтобы построить план выдачи ссылок.");
          }
          const snapshot = await downloadUrlBindingSnapshot(g, items);
          const payload: DownloadUrlPayload = { account: accountName, ttlMinutes: ttl, items };
          const lines = snapshot.map((s) => {
            // В превью человек видит ЖИВОЕ имя из письма, а не то, которое
            // подставил вызывающий: иначе согласие можно было бы получить под
            // подменённым именем файла («invoice.pdf» вместо «passport.jpg»).
            // Имя от вызывающего показывается отдельной пометкой.
            const head = `- **«${safeText(s.filename ?? s.saveAs ?? s.attachmentId, 60)}»**`;
            const renamed =
              s.saveAs && s.saveAs !== s.filename ? `; будет отдан под именем «${safeText(s.saveAs, 60)}»` : "";
            if (!s.found) {
              return (
                `${head} — ⚠️ письмо ${safeText(s.messageId, 40)} перечитать не удалось (удалено/нет доступа); ` +
                `имя и тип не проверены — ссылка будет выдана по данным вызывающего${renamed}`
              );
            }
            return (
              `${head} (${safeText(s.mimeType ?? "", 40)}, ${s.size ?? "?"} байт)` +
              ` — из письма «${safeText(s.subject ?? "(без темы)", 60)}» от ${safeText(s.from ?? "(?)", 60)}${renamed}`
            );
          });
          const preview =
            `### 📤 План: Выдать ссылки на вложения — ${items.length}\n\n` +
            `${downloadUrlConsentWarning(ttl, Date.now() + ttl * 60_000)}\n\n` +
            `${lines.join("\n")}\n\n` +
            `${downloadUrlConsentButtonLine(items.length, ttl)}`;
          return {
            payload,
            objectHash: sha256({ account: accountName, ttlMinutes: ttl, items: snapshot }),
            preview,
            batchSize: items.length,
          };
        },
        // Real binding: re-reads each message + its attachment right now — a
        // message deleted or an attachment swapped between plan and execute
        // forces a mismatch instead of handing out a link to whatever is there.
        rehash: (addressing) => downloadUrlRehash(g, addressing),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeGetDownloadUrlCore(g, payload, auditId, consentStore);
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
          .optional()
          .describe(
            "Array of files to open upload sessions for. Required to build a plan (first call, no " +
              "manifest_id/user_reply). Ignored on the execute call — read back from the manifest.",
          ),
        manifest_id: z
          .string()
          .optional()
          .describe("Id of a plan built by a previous no-argument call. Pass together with `user_reply` to execute it."),
        user_reply: z.string().optional().describe(USER_REPLY_DOC),
        automation_key: z
          .string()
          .optional()
          .describe(
            "For headless automation only — a valid automation_key skips the human confirmation step " +
              "entirely. Humans and interactive assistants must NEVER guess or fabricate a value here; " +
              "leave it unset.",
          ),
      },
      annotations: { destructiveHint: false },
    },
    guard(async ({ account, files, manifest_id, user_reply, automation_key }) => {
      const { consentStore, consentCfg, tg, checkAutomationKey } = snoozeCtx;
      if (!consentStore) {
        return fail(
          "Загрузочная сессия недоступна: не настроено хранилище согласия (DATABASE_URL). Без него сервер не " +
            "может провести это действие через гейт подтверждения — обратитесь к администратору сервера.",
        );
      }
      const g = clients.resolve(account);
      const accountName = clients.canonicalName(account);

      const decision = await requireConsent<UploadSessionPayload>({
        tool: "gmail_create_upload_session",
        accountLabel: accountName,
        manifestId: manifest_id,
        userReply: user_reply,
        store: consentStore,
        cfg: consentCfg,
        tg,
        automationKey: automation_key,
        checkAutomationKey,
        plan: () => {
          if (!files || !files.length) {
            throw new Error("Нужен непустой `files`, чтобы построить план открытия загрузочных сессий.");
          }
          const payload: UploadSessionPayload = { account: accountName, files };
          const lines = files.map(
            (f) => `- «${safeText(f.name, 200)}»${f.sizeBytes ? ` (${f.sizeBytes} байт)` : ""} → Drive/${UPLOAD_FOLDER_NAME}`,
          );
          const preview = `### 📤 План: Открытие загрузочных сессий — ${files.length}\n\n${lines.join("\n")}`;
          return { payload, objectHash: sha256(payload), preview, batchSize: files.length };
        },
        // Degenerate binding (same reasoning as gmail_send): a not-yet-existing
        // upload session/placeholder has no live object to re-read.
        rehash: (addressing) => sha256(addressing),
      });

      if (decision.kind === "planned") return okVerbatim(decision.preview, "plan");
      // Исполнено другим каналом во время sync-wait — ОТЧЁТ, не отказ (см. consent.ts).
      if (decision.kind === "already_executed") return okVerbatim(decision.report, "execution-report");
      if (decision.kind === "refused") return okVerbatim(decision.result, "refusal");

      const { payload, auditId } = decision;
      return executeUploadSessionCore(g, payload, auditId, consentStore, snoozeCtx.safeFetch);
    }),
  );

  // ЧТО ЗДЕСЬ ИСПРАВЛЕНО. Раньше этот инструмент принимал `uploadUrl` —
  // АДРЕС, ПРИШЕДШИЙ В АРГУМЕНТЕ, — шёл по нему без единой проверки и
  // возвращал тело ответа в диалог. Это давало подделку запроса со стороны
  // сервера (SSRF): модель, которой скормили нужный текст, заставляла сервер
  // постучаться во внутреннюю сеть (метаданные облака 169.254.169.254,
  // приватные диапазоны, localhost) и вернуть ответ наружу. Теперь адрес не
  // принимается ВООБЩЕ: сервер сам выдал его при создании сессии, сам и
  // хранит (uploadSessions.ts), а наружу отдаёт только непрозрачный
  // `sessionId`. Плюс второй рубеж — safeGoogleFetch (allowlist хостов
  // Google + запрет приватных адресов на уровне реального соединения +
  // проверка каждого перенаправления).
  server.registerTool(
    "gmail_confirm_upload",
    {
      title: "Check a direct upload",
      description:
        "Ask Google how an upload started by gmail_create_upload_session is doing. Pass the `sessionId` that " +
        "session returned — the upload address itself is kept server-side and is NOT accepted as an argument. " +
        "Reports `complete` (the file is ready to attach), `in_progress` (how many bytes arrived, so the client " +
        "knows where to resume), or `expired` (session gone — open a new one). Uploads nothing itself. " +
        "The body of an unexpected answer is never echoed back into the conversation.",
      inputSchema: {
        uploads: z
          .array(
            z.object({
              sessionId: z
                .string()
                .describe(
                  "The opaque `sessionId` returned by gmail_create_upload_session. NOT a URL: the server looks " +
                    "the real upload address up in its own store.",
                ),
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
      // НЕ readOnlyHint: инструмент делает исходящий запрос наружу (пусть и по
      // адресу, который сервер хранит у себя, а не принимает от модели) и
      // читает собственное хранилище сессий. Пометка «только чтение» прятала
      // его и от теста покрытия гейтов, и от группировки разрешений клиента —
      // ровно так обе дыры и прожили незамеченными.
      annotations: { destructiveHint: false, openWorldHint: true },
    },
    guard(async ({ uploads }) => {
      const results = await mapWithLimit(uploads, async ({ sessionId, sizeBytes }) => {
        const session = await resolveUploadSession(sessionId);
        if (!session) {
          return {
            sessionId,
            error:
              "Сессия загрузки с таким `sessionId` не найдена (истекла или её создавал не этот сервер). " +
              "Создайте новую через gmail_create_upload_session.",
          };
        }
        try {
          // An empty PUT with "bytes */total" asks for status instead of sending
          // content; the session URI carries its own authorisation.
          // Перенаправления `safeGoogleFetch` вслепую не выполняет: каждый
          // `Location` проходит те же проверки, а обычный ответ «шли дальше» —
          // это 308 БЕЗ `Location`, его это не задевает.
          const res = await safeGoogleFetch(
            session.uploadUrl,
            {
              method: "PUT",
              headers: { "Content-Range": `bytes */${sizeBytes ?? session.sizeBytes ?? "*"}` },
            },
            snoozeCtx.safeFetch,
          );
          if (res.status === 200 || res.status === 201) {
            let file: { id?: string; name?: string; size?: string } = {};
            try {
              file = JSON.parse(await res.text());
            } catch {
              /* Google answered without a usable body — the id simply isn't there. */
            }
            return {
              sessionId,
              status: "complete" as const,
              driveFileId: file.id ?? session.driveFileId ?? null,
              name: file.name ?? session.name ?? null,
              size: file.size ?? null,
            };
          }
          if (res.status === 308) {
            // "Range: bytes=0-<last>" — absent when nothing has arrived yet.
            const range = res.headers.get("range");
            const last = range ? Number(range.split("-")[1]) : NaN;
            const bytesReceived = Number.isFinite(last) ? last + 1 : 0;
            return { sessionId, status: "in_progress" as const, bytesReceived, resumeFrom: bytesReceived };
          }
          if (res.status === 404 || res.status === 410) {
            return {
              sessionId,
              status: "expired" as const,
              error: "Google no longer knows this session (expired, cancelled, or finished long ago). Open a new one.",
            };
          }
          // Тело неожиданного ответа НАРУЖУ НЕ УХОДИТ. Адрес сюда больше не
          // приходит от модели, но эхо чужого тела в диалог — это канал утечки
          // сам по себе (security-checklist.md §6): наружу идёт только номер
          // статуса. Тело даже не читается.
          return {
            sessionId,
            error:
              `🛑 Неожиданный ответ на проверку загрузки: HTTP ${res.status}. ` +
              "Тело ответа наружу не передаётся; при повторении — открыть новую загрузочную сессию.",
          };
        } catch (e) {
          return { sessionId, error: String(e instanceof Error ? e.message : e) };
        }
      });
      return ok({
        summary: `📶 Проверено ${uploads.length} ${plural(uploads.length, "сессия", "сессии", "сессий")} загрузки`,
        results,
      });
    }),
  );

  // ---- gmail_consent_audit (package A4, `[R:полнота-1]`) --------------------
  // "Разбор инцидента без ssh" (limits-audit.md §11): both August 4th incidents
  // only came to light through a manual read of the Railway logs — there was
  // no way to ask the assistant itself "what did the consent gate actually
  // decide". This read-only tool is that missing path over the same
  // consent_audit table A1 already writes to (plan/refuse AND, once A3 fills
  // it in, the mutation's real outcome + post-verify result).

  server.registerTool(
    "gmail_consent_audit",
    {
      title: "Read the consent-gate audit log",
      description:
        "Read-only log of every decision the consent gate has made for gmail_send/reply/forward/schedule_send " +
        "(and, once gated, other write tools): plan built, confirmed, refused, or invalidated, plus — once the " +
        "mutation actually ran — its outcome and post-verify result. This is how to answer \"what actually " +
        "happened with that email\" or \"did the gate block anything today\" without reading server logs. " +
        "Filter by `since`/`until` (ISO 8601), `account`, `tool`, or `outcome` " +
        "(confirmed/refused/invalidated/failed — a manifest that's only been planned and never answered has no " +
        "audit row yet, nothing to show). Results are newest first, capped at 100 per page " +
        "(default 20); use `offset` to page through older rows. External text (the verbatim user_reply and the " +
        "outbound pre-snapshot) is shown neutralised, never as live markdown.",
      inputSchema: {
        account: z
          .string()
          .optional()
          .describe("Filter to one account label (e.g. 'work'). Omit to show all accounts, not just the default."),
        since: z.string().optional().describe("ISO 8601 datetime — only rows at or after this time."),
        until: z.string().optional().describe("ISO 8601 datetime — only rows at or before this time."),
        tool: z
          .string()
          .optional()
          .describe("Filter to one tool name, e.g. 'gmail_send'. Omit to show every gated tool."),
        outcome: z
          .enum(["confirmed", "refused", "invalidated", "failed"])
          .optional()
          .describe("Filter to one outcome. Omit to show all."),
        limit: z.number().int().min(1).max(100).default(20).optional().describe("Max rows to return (1-100, default 20)."),
        offset: z.number().int().min(0).default(0).optional().describe("Skip this many newest-first rows — for paging past the first `limit`."),
      },
      annotations: { readOnlyHint: true },
    },
    guard(async ({ account, since, until, tool, outcome, limit, offset }) => {
      const { auditStore, consentCfg } = snoozeCtx;
      if (!auditStore) {
        return ok({
          summary: "Журнал согласий недоступен — DATABASE_URL не настроен, значит ничего и не записывалось.",
          results: [],
        });
      }
      const parseWhen = (label: string, s?: string): number | undefined => {
        if (!s) return undefined;
        const t = Date.parse(s);
        if (Number.isNaN(t)) throw new Error(`Не могу разобрать ${label}="${s}". Нужен формат ISO 8601, например 2026-08-04T00:00:00-07:00.`);
        return t;
      };
      const filters = {
        server: consentCfg.server,
        since: parseWhen("since", since),
        until: parseWhen("until", until),
        accountLabel: account?.trim() || undefined,
        tool: tool?.trim() || undefined,
        outcome,
      };
      const cap = limit ?? 20;
      const off = offset ?? 0;
      const [rows, total] = await Promise.all([
        auditStore.listConsentAudit(filters, cap, off),
        auditStore.countConsentAudit(filters),
      ]);

      const outcomeIcon = (o: string): string =>
        o === "confirmed" ? "✅" : o === "failed" ? "❌" : o === "refused" || o === "invalidated" ? "🛑" : "•";

      // Compact table (plan §A4: user_reply and pre_snapshot are EXTERNAL text
      // — safeText, always). tool/account/actor/outcome are server-controlled
      // (fixed tool names, config labels, "human"/"automation:<name>") so they
      // are shown as-is.
      const header = "| Время (PT) | Инструмент | Аккаунт | Actor | Исход | user_reply | post-verify | Детали |";
      const sep = "|---|---|---|---|---|---|---|---|";
      const lines = rows.map((r) => {
        const details = r.error
          ? `ошибка: ${safeText(r.error, 80)}`
          : r.preSnapshot
            ? `снимок: ${safeText(JSON.stringify(r.preSnapshot), 100)}`
            : "—";
        return (
          `| ${formatLaTime(r.ts)} | ${r.tool} | ${r.accountLabel} | ${r.actor} | ` +
          `${outcomeIcon(r.outcome)} ${r.outcome} | ${safeText(r.userReply, 60) || "—"} | ` +
          `${safeText(r.postVerifyResult ?? "", 60) || "—"} | ${details} |`
        );
      });

      const shownNote =
        total > off + rows.length
          ? `Показано ${rows.length} из ${total} (записи ${off + 1}–${off + rows.length}); ` +
            `есть ещё — вызовите снова с offset=${off + rows.length}.`
          : `Показано ${rows.length} из ${total}.`;

      const body = rows.length
        ? [header, sep, ...lines].join("\n")
        : "Нет записей, подходящих под фильтры.";

      return ok(`### 🧾 Журнал согласий\n\n${shownNote}\n\n${body}`);
    }),
  );
}
