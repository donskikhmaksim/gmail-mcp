/**
 * tg_approval.ts — optional out-of-band Telegram-button approval layer.
 *
 * Plan: `PLAN-tg-approval.md`. Normative base: `mcp-development-standard/
 * references/gate.md` §3.4 (the honest residual gap — `user_reply` can be
 * fabricated by the model; a button press in Telegram cannot).
 *
 * GENERIC, PORTABLE module (plan §7): meant to be copied byte-for-byte to the
 * other 4 Google MCP servers (sheets/calendar/docs/drive). It does NOT import
 * `store.ts` — the `tg_approvals` persistence is injected as `TgApprovalStore`
 * (same DI discipline `consent.ts` uses for `ConsentStore`), and does NOT
 * hardcode any per-server value — everything server-specific comes from
 * `TgApprovalConfig` (env-driven, `config.ts`).
 *
 * OFF BY DEFAULT: `TG_APPROVAL_ENABLED=false` (or unset) makes `enabledFor()`
 * always false and neither `notifyPlan` nor `checkApproval` ever talks to
 * Telegram — a fork without a configured bot behaves exactly as if this
 * module didn't exist. See `consent.ts`'s `tg?: TgApprovalGate` field, which
 * this module's `createTgApprovalGate()` output satisfies structurally.
 */

import { timingSafeEqual } from "node:crypto";
import { fetch as undiciFetch } from "undici";
import type { TgApprovalConfig } from "./config.js";

// ───────────────────────── DI contracts ─────────────────────────────────────

export interface TgApprovalRow {
  manifestId: string;
  server: string;
  chatId: string;
  messageId: number | null;
  /** "EXPIRED" — sweep-only terminal state (runApprovalSweep below): a
   * PENDING row whose own TTL passed before anyone tapped a button. Never
   * written by handleWebhook/consumeTgDecision*, only by the sweep. */
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  createdAt: number;
  expiresAt: number;
  decidedAt: number | null;
}

export interface StaleApprovalRow {
  manifestId: string;
  chatId: string;
  messageId: number | null;
}

/**
 * Storage this module expects. Implemented by store.ts's `tg_approvals`
 * functions (package P1), wired signature-for-signature in server.ts the same
 * way `consentStoreAdapter` is wired against `consent.ts`'s `ConsentStore`.
 */
export interface TgApprovalStore {
  createTgApproval(input: {
    manifestId: string;
    server: string;
    chatId: string;
    messageId: number | null;
    createdAt: number;
    expiresAt: number;
  }): Promise<void>;
  getTgApproval(manifestId: string, server: string): Promise<TgApprovalRow | null>;
  /** Atomic one-shot: `WHERE status = 'PENDING'` in the same statement as the
   * decision write. Returns null on any miss — anti-replay is closed in the
   * database, not in this module's JS. */
  consumeTgDecision(
    manifestId: string,
    server: string,
    status: "APPROVED" | "REJECTED",
  ): Promise<TgApprovalRow | null>;
  /**
   * Server-agnostic sibling of `consumeTgDecision`, used by `handleWebhook`.
   * ONE Telegram bot token can be shared across several MCP servers (gmail/
   * sheets/calendar/docs/drive/ticktick), but only one server physically owns
   * `/tg/webhook` (`registerWebhook`'s `TG_WEBHOOK_OWNER` guard below) — that
   * server's webhook receives button taps for manifests belonging to ANY of
   * them, and has no way to know which server a given `manifest_id` belongs
   * to ahead of time (`callback_data` carries only the id). Filtering by
   * `server` here (as `consumeTgDecision` does) would silently return zero
   * rows for every manifest not owned by the webhook-owning server, leaving
   * those approvals stuck PENDING forever. Safe to drop the filter because
   * `manifest_id` is globally unique (the table's PRIMARY KEY — see store.ts's
   * `ensureSchema()`), so no cross-server ambiguity is introduced. Returns the
   * row's real `server` so the caller can log which server the decision
   * belonged to. Same atomicity/TTL guard as `consumeTgDecision`.
   */
  consumeTgDecisionAnyServer(
    manifestId: string,
    status: "APPROVED" | "REJECTED",
  ): Promise<TgApprovalRow | null>;
  /** Sweep (runApprovalSweep below), webhook-owner-only: PENDING rows past
   * their own expiry — atomically claimed (flipped to EXPIRED) in the same
   * query, so a slow Telegram call on one sweep tick can't overlap the next
   * tick's claim of the same row. */
  claimExpiredPendingApprovals(nowMs: number, limit?: number): Promise<StaleApprovalRow[]>;
  /** Sweep, webhook-owner-only: APPROVED/REJECTED rows whose own TTL window
   * has elapsed since being decided — deleted in the same query (this table
   * is operational, not an audit log; consent_audit is the durable record). */
  claimStaleDecidedApprovals(nowMs: number, limit?: number): Promise<StaleApprovalRow[]>;
}

/** Same shape as `consent.ts`'s own `TgApprovalGate` interface — duplicated
 * there on purpose (consent.ts must not import this module); the object this
 * factory returns satisfies both structurally. */
export interface TgApprovalGate {
  enabledFor(tool: string): boolean;
  notifyPlan(
    manifestId: string,
    previewBody: string,
    /** `expiresAt` is the CONSENT manifest's own expiry — a CAP, not the
     * approval row's TTL directly (see `createTgApprovalGate`'s use of it:
     * `min(now() + cfg.ttlMs, meta.expiresAt)`). */
    meta: { tool: string; accountLabel: string; expiresAt: number },
  ): Promise<{ ok: boolean; error?: string }>;
  checkApproval(manifestId: string): Promise<"approved" | "pending" | "rejected" | "none">;
}

// ───────────────────────── Telegram HTTP plumbing ───────────────────────────

const TELEGRAM_API = "https://api.telegram.org";
// Telegram's own hard limit on sendMessage.text is 4096 UTF-16 code units;
// 3500 leaves room for the "<tool> · <account>" footer line + HTML tag
// overhead from mdToTelegramHtml without risking a 400 from the API. Раньше
// был 400 — Максим прямо попросил полный текст плана в боте, не обрезанный
// (задача #79), урезание было для другого дизайна (короткая подсказка).
const PREVIEW_CAP = 3500;

function apiUrl(cfg: TgApprovalConfig, method: string): string {
  return `${TELEGRAM_API}/bot${cfg.botToken}/${method}`;
}

function clipPreview(s: string, max = PREVIEW_CAP): string {
  const one = s.trim();
  return one.length > max ? one.slice(0, max) + "…" : one;
}

/**
 * Конвертер лёгкого markdown (того же, что рендерят `renderConsentBlock`/
 * `ConsentPlan.preview` в consent.ts — `### заголовок`, `**жирный**`,
 * `` `код` ``, `_курсив_`) в Telegram HTML parse_mode. Раньше `sendMessage`
 * уходил без `parse_mode` вообще — Telegram показывал сырые `###`/`**` как
 * буквальный текст (найдено по живому скриншоту прода — план `drive_upload_file`
 * с буквальными звёздочками в чате).
 *
 * Порядок обязателен: (1) HTML-экранирование СЫРОГО текста — до вставки любых
 * своих тегов, иначе получим двойное экранирование; (2) построчная замена
 * заголовков; (3) `**bold**` → `<b>`; (4) `` `code` `` → `<code>`; (5) `_italic_`
 * → `<i>`, но ТОЛЬКО когда подчёркивание не внутри слова (`(?<!\w)_.../(?!\w)`
 * — тот же приём, что GFM использует для «intraword emphasis», см.
 * CommonMark/GFM spec) — иначе имена файлов вида `n8n_email_algo_report.md`
 * (реальный кейс с того же скриншота) ломались бы: наивная замена съела бы
 * подчёркивания и раскурсивила бы середину имени файла.
 */
function mdToTelegramHtml(text: string): string {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return escaped
    .split("\n")
    .map((line) => {
      const h = /^(#{1,6})\s+(.*)$/.exec(line);
      return h ? `<b>${h[2]}</b>` : line;
    })
    .join("\n")
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/(?<!\w)_([^_\n]+)_(?!\w)/g, "<i>$1</i>");
}

interface TgCallResult {
  ok: boolean;
  result?: unknown;
  description?: string;
}

/**
 * One call to the Telegram Bot API. Uses undici's own `fetch` — same package
 * the rest of this server pins HTTP through (see `tools/gmail.ts`'s SSRF-
 * pinning comment) — for tooling consistency. No SSRF-pinning `Agent` is
 * needed HERE specifically: unlike attachment URLs (user/model-supplied),
 * `api.telegram.org` is a fixed, hardcoded host, never derived from tool input.
 */
export async function tgCall(cfg: TgApprovalConfig, method: string, body: unknown): Promise<TgCallResult> {
  const res = await undiciFetch(apiUrl(cfg, method), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let json: { ok?: boolean; result?: unknown; description?: string } = {};
  try {
    json = (await res.json()) as typeof json;
  } catch {
    /* non-JSON response — fall through, ok stays false */
  }
  return { ok: !!json.ok && res.ok, result: json.result, description: json.description };
}

/**
 * Отправляет ИТОГ исполнения В ТО ЖЕ сообщение Telegram, где были кнопки
 * (Максим, 2026-08-05: «нажал кнопку — сразу исполнилось, результат — сюда
 * же, без дополнительного „дай ссылку" в чате»). `editMessageText` заменяет и
 * текст (план → отчёт, включая ссылку/артефакт, если тул её вернул — это уже
 * часть готового текста отчёта, никакой отдельной логики под «эта ссылка»),
 * и `reply_markup` (кнопки снимаются в том же вызове — Telegram API это
 * позволяет одним запросом, отдельный editMessageReplyMarkup не нужен).
 * Best-effort: если чат/сообщение недоступны (человек удалил сообщение
 * руками) — не бросает, просто логирует, реальное исполнение УЖЕ произошло
 * и не должно откатываться из-за того, что отчёт некуда вписать.
 */
export async function reportAutoExecutionResult(
  cfg: TgApprovalConfig,
  chatId: string,
  messageId: number | null,
  reportText: string,
): Promise<void> {
  if (messageId == null) {
    console.error("TG auto-execute: messageId отсутствует, отчёт некуда вписать (chat=" + chatId + ")");
    return;
  }
  const res = await tgCall(cfg, "editMessageText", {
    chat_id: chatId,
    message_id: messageId,
    text: mdToTelegramHtml(clipPreview(reportText)),
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: [] },
  });
  if (!res.ok) {
    console.error(`TG auto-execute: editMessageText failed for message ${messageId}: ${res.description}`);
  }
}

// ───────────────────────── Gate factory (consent.ts side) ───────────────────

/**
 * Builds the `TgApprovalGate` that `consent.ts`'s `requireConsent` calls
 * through. `now` is injectable for offline unit tests (mirrors `consent.ts`'s
 * own `cfg.now` convention) — production leaves it as `Date.now`.
 */
export function createTgApprovalGate(
  cfg: TgApprovalConfig,
  store: TgApprovalStore,
  now: () => number = Date.now,
): TgApprovalGate {
  return {
    enabledFor(tool: string): boolean {
      if (!cfg.enabled) return false;
      if (!cfg.toolsAllowlist) return true; // empty allowlist = every gated tool
      return cfg.toolsAllowlist.has(tool);
    },

    async notifyPlan(manifestId, previewBody, meta) {
      try {
        const rawText = `${clipPreview(previewBody)}\n\n${meta.tool} · ${meta.accountLabel}`;
        const sent = await tgCall(cfg, "sendMessage", {
          chat_id: cfg.ownerChatId,
          text: mdToTelegramHtml(rawText),
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [
                { text: "✅ Подтвердить", callback_data: `a:${manifestId}` },
                { text: "🛑 Отклонить", callback_data: `r:${manifestId}` },
              ],
            ],
          },
        });
        if (!sent.ok) {
          return { ok: false, error: sent.description ?? "Telegram sendMessage failed" };
        }
        const messageId = (sent.result as { message_id?: number } | undefined)?.message_id ?? null;
        // Own TTL (TG_APPROVAL_TTL_MS / `cfg.ttlMs`), capped at `meta.expiresAt`
        // (the CONSENT manifest's own expiry): the approval row must never
        // outlive the plan it belongs to, but is otherwise free to expire
        // sooner on its own, independently configurable schedule (plan §2:
        // "свой lifecycle/TTL", not borrowed wholesale from CONSENT_TTL_MS).
        const expiresAt = Math.min(now() + cfg.ttlMs, meta.expiresAt);
        await store.createTgApproval({
          manifestId,
          server: cfg.server,
          chatId: cfg.ownerChatId,
          messageId,
          createdAt: now(),
          expiresAt,
        });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: (err as Error).message };
      }
    },

    async checkApproval(manifestId) {
      const row = await store.getTgApproval(manifestId, cfg.server);
      if (!row) return "none";
      if (row.status === "APPROVED") return "approved";
      if (row.status === "REJECTED") return "rejected";
      if (now() > row.expiresAt) return "none"; // TTL expired -- same handling as "never requested"
      return "pending";
    },
  };
}

// ───────────────────────── Webhook (Telegram → server) ──────────────────────

export interface TelegramCallbackUpdate {
  update_id?: number;
  callback_query?: {
    id: string;
    from?: { id?: number | string };
    data?: string;
    message?: { message_id?: number; chat?: { id?: number | string } };
  };
}

/** Constant-time secret_token compare (mirrors http.ts's own `secretMatches`
 * for the dashboard path). Exported so http.ts can use it against the
 * `X-Telegram-Bot-Api-Secret-Token` header without re-deriving the same logic. */
export function secretTokenMatches(provided: string, expected: string): boolean {
  if (!expected || !provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Handles ONE Telegram update, already past http.ts's secret_token check
 * (plan §3 check 1 — the only one of the 7 this module doesn't own, since it
 * needs the raw request header http.ts already has in hand). Every other
 * check lives here:
 *  2. owner-only          — `callback_query.from.id === TG_OWNER_CHAT_ID`.
 *  3. callback_data is an ADDRESS, not a trust fact — the decision is read
 *     back from the store by manifest_id; the button's own label is never
 *     taken at face value. TWO consume paths, chosen by `cfg.ownBot`
 *     (TG_BOT_TOKEN_OVERRIDE, config.ts):
 *       - `cfg.ownBot === false` (default, shared bot): the manifest may
 *         belong to ANY of the servers sharing this bot token (single shared
 *         webhook — see `registerWebhook`'s `TG_WEBHOOK_OWNER` guard), not
 *         necessarily this process's own `cfg.server` — hence
 *         `consumeTgDecisionAnyServer`, not the server-scoped
 *         `consumeTgDecision`. This is the byte-for-byte pre-existing path.
 *       - `cfg.ownBot === true` (this server has its own bot, its own
 *         webhook): every update arriving here was sent BY THIS SERVER'S OWN
 *         `notifyPlan` call to ITS OWN bot, so every manifest it could
 *         possibly be addressing already belongs to `cfg.server` — using the
 *         server-scoped `consumeTgDecision` here is both correct (no other
 *         server's approval can arrive on this webhook at all) and safer if
 *         Postgres happens to still be the same shared instance as the other
 *         5 servers (an own-bot server must never be able to decide a
 *         manifest that isn't its own, even if `manifest_id` collided).
 *  4. anti-replay         — atomic consume (`WHERE status = 'PENDING'`,
 *     either variant above); a second tap on the same callback is a no-op here.
 *  5. answerCallbackQuery — always called, so the tap's spinner clears.
 *  6. editMessageReplyMarkup — removes the buttons after ANY decision is
 *     recorded, so a second tap has nothing left to press.
 *  7. anything that isn't `callback_query` is ignored (early return).
 *
 * `onApproved` (опционально, Максим 2026-08-06: «отчёт пришёл спустя секунд
 * 10, надо ускорять») — ХУК НЕМЕДЛЕННОГО ИСПОЛНЕНИЯ. До него единственным
 * исполнителем был фоновый поллер с шагом 10 с (`http.ts`'s
 * `runAutoExecutePoller`), из-за чего между нажатием кнопки и результатом
 * стабильно проходило до 10 лишних секунд ожидания следующего тика. Обработчик
 * нажатия УЖЕ держит в руках выигравшее решение — он же и запускает исполнение,
 * поллер остаётся страховкой на случай, если процесс упал/перезапустился между
 * решением и исполнением.
 *
 * Контракт хука (важен для портируемости — этот файл копируется байт-в-байт в
 * остальные MCP-репозитории):
 *  • вызывается ТОЛЬКО когда атомарный `consumeTgDecisionAnyServer` реально
 *    вернул строку (то есть именно это нажатие выиграло гонку) и решение —
 *    APPROVED. Одноразовость по-прежнему закрыта ОДНИМ неделимым UPDATE в БД,
 *    здесь никакой второй проверки нет и быть не должно;
 *  • НЕ ожидается (`await` намеренно отсутствует): исполнение — фоновая работа,
 *    HTTP-ответ Telegram'у (200) и снятие кнопок не должны её ждать. Телеграм
 *    ретраит по таймауту, а ретрай на уже потреблённой строке — no-op;
 *  • ошибки хука проглатываются здесь же, чтобы упавшее исполнение не сорвало
 *    `answerCallbackQuery` (спиннер на кнопке у человека).
 */
export async function handleWebhook(
  cfg: TgApprovalConfig,
  store: TgApprovalStore,
  update: TelegramCallbackUpdate,
  onApproved?: (row: TgApprovalRow) => void | Promise<void>,
): Promise<void> {
  const cq = update.callback_query;
  if (!cq) return; // (7)

  const fromId = String(cq.from?.id ?? "");
  if (!cq.from || fromId === "" || fromId !== cfg.ownerChatId) {
    return; // (2) not the owner -- silently ignored; caller still answers Telegram 200
  }

  const data = cq.data ?? "";
  const m = /^([ar]):(.+)$/.exec(data);
  if (!m) return;
  const decision: "APPROVED" | "REJECTED" = m[1] === "a" ? "APPROVED" : "REJECTED";
  const manifestId = m[2];

  // (3) + (4): callback_data only ADDRESSES the manifest; the atomic UPDATE
  // is what actually decides + closes the replay race, in one statement.
  //
  // `cfg.ownBot === true`: this webhook belongs to THIS server's own bot —
  // every manifest it could possibly see is this server's own, so consume
  // server-scoped (also closes off cross-server manifest_id collisions on a
  // shared Postgres, belt-and-braces).
  //
  // `cfg.ownBot === false` (default): server-agnostic on purpose — this ONE
  // webhook (owned by whichever server has TG_WEBHOOK_OWNER=true) services
  // approval buttons for EVERY server sharing this bot token, so `cfg.server`
  // (always "$self") is the WRONG filter here — the manifest being decided
  // may belong to any of them. Safe because `manifest_id` is globally unique
  // (tg_approvals' PRIMARY KEY). Byte-for-byte the pre-existing behaviour.
  const consumed = cfg.ownBot
    ? await store.consumeTgDecision(manifestId, cfg.server, decision)
    : await store.consumeTgDecisionAnyServer(manifestId, decision);

  if (consumed && decision === "APPROVED" && onApproved) {
    // Немедленное исполнение — СРАЗУ после выигранного консюма и ДО правки
    // сообщения/ответа Telegram: чем раньше стартует фоновая работа, тем
    // меньше пауза до отчёта. Намеренно без `await` (см. док-комментарий):
    // ни этот обработчик, ни HTTP-ответ 200 не ждут исполнения.
    try {
      void Promise.resolve(onApproved(consumed)).catch((err) =>
        console.error(`TG approval: немедленное исполнение ${manifestId} упало:`, err),
      );
    } catch (err) {
      console.error(`TG approval: хук немедленного исполнения ${manifestId} бросил синхронно:`, err);
    }
  }

  if (consumed) {
    // (6) Remove the buttons -- best-effort, never blocks the decision itself.
    const chatId = cq.message?.chat?.id ?? cfg.ownerChatId;
    const messageId = cq.message?.message_id ?? consumed.messageId ?? undefined;
    if (messageId != null) {
      await tgCall(cfg, "editMessageReplyMarkup", {
        chat_id: chatId,
        message_id: messageId,
        reply_markup: { inline_keyboard: [] },
      }).catch(() => {});
    }
  }

  // (5) Always answer -- whether this tap won the race or arrived after the
  // decision was already made.
  const answerText = !consumed ? "Уже обработано" : decision === "APPROVED" ? "Подтверждено" : "Отклонено";
  await tgCall(cfg, "answerCallbackQuery", { callback_query_id: cq.id, text: answerText }).catch(() => {});
}

/**
 * Registers the webhook URL with Telegram at startup. No-op when the feature
 * is disabled, OR when this process is not the designated webhook owner
 * (`TG_WEBHOOK_OWNER`, see below). Logs the effective URL (or a failure)
 * loudly: TWO servers calling `setWebhook` for the SAME bot token silently
 * overwrite each other -- a log line here is the only place a deployer can
 * catch that before approvals start vanishing.
 *
 * ONE Telegram bot (`@maksim_mcp_approval_bot`) is now shared across all 6 of
 * Maksim's MCP servers (gmail/sheets/calendar/docs/drive-mcp + ticktick-mcp);
 * only ONE of them may physically own the webhook, since Telegram routes
 * every update for a bot token to whichever URL the LAST `setWebhook` call
 * registered. The self-guard below (checked HERE, not only at the call site
 * in http.ts) is deliberate defense-in-depth: this function is meant to be
 * copied byte-for-byte to the other 5 repos (same discipline as the rest of
 * this module, see the file's top doc-comment) -- if a future call site in
 * one of those copies forgets to gate the call externally, this function
 * still refuses to register a second webhook on its own.
 */
export async function registerWebhook(cfg: TgApprovalConfig): Promise<void> {
  if (!cfg.enabled) return;
  if (!cfg.webhookOwner && !cfg.ownBot) {
    console.error(
      `TG approval: TG_APPROVAL_ENABLED=true but TG_WEBHOOK_OWNER is not "true" and TG_BOT_TOKEN_OVERRIDE ` +
        `is not set -- this server will NOT call setWebhook and will not receive Telegram button taps. ` +
        `When one bot token is shared across several MCP servers, exactly ONE of them must set ` +
        `TG_WEBHOOK_OWNER=true; every other server must leave it unset (default false), or their ` +
        `setWebhook calls will silently overwrite each other and approvals for whichever server ` +
        `registered last will stop reaching anyone. (Alternatively, set TG_BOT_TOKEN_OVERRIDE to give ` +
        `this server its own bot -- it then owns its own webhook unconditionally, see below.)`,
    );
    return;
  }
  // `cfg.ownBot` (TG_BOT_TOKEN_OVERRIDE): `cfg.botToken` has ALREADY resolved
  // to the override at this point (config.ts's loadTgApprovalConfig), so the
  // `setWebhook` call below registers THIS server's own bot -- correct and
  // expected. The one sharp edge: if this SAME process also still carries
  // the legacy `TG_WEBHOOK_OWNER=true` (e.g. gmail-mcp, today's default
  // shared-bot webhook owner, later getting its own override too), that
  // flag's meaning silently flips underneath it -- `cfg.botToken` is no
  // longer the shared bot, so this call registers the webhook for the OWN
  // bot instead, and the shared bot's webhook (which some OTHER server was
  // relying on this process to keep registering) is never (re-)registered
  // by anyone. Loud warning instead of silent breakage -- this is a real
  // config hazard, not a hypothetical one, if TG_WEBHOOK_OWNER is ever left
  // on by mistake after adopting an own bot.
  if (cfg.webhookOwner && cfg.ownBot) {
    console.error(
      `TG approval: ВНИМАНИЕ — на этом сервере (${cfg.server}) одновременно TG_WEBHOOK_OWNER=true И ` +
        `TG_BOT_TOKEN_OVERRIDE заданы. setWebhook ниже зарегистрирует ТОЛЬКО свой собственный бот ` +
        `(TG_BOT_TOKEN_OVERRIDE) — общий бот (TG_BOT_TOKEN), для которого этот сервер был вебхук-` +
        `владельцем для ОСТАЛЬНЫХ серверов, вебхук больше не получит от НЕГО. Если так и задумано (этот ` +
        `сервер окончательно переезжает на свой бот) — ок, но передайте TG_WEBHOOK_OWNER=true другому ` +
        `серверу на общем боте; если нет — снимите TG_WEBHOOK_OWNER здесь.`,
    );
  }
  const url = `${cfg.publicBaseUrl.replace(/\/+$/, "")}/tg/webhook`;
  try {
    const res = await tgCall(cfg, "setWebhook", {
      url,
      secret_token: cfg.webhookSecret,
      // "message" добавлен ради ЕДИНСТВЕННОЙ команды `/automation_key`
      // (automation_key.ts, ТЗ_automation_key_hub.md) — прочий текст от
      // владельца боту просто не нужен и automation_key.ts сам игнорирует
      // любой текст, не начинающийся с `/automation_key`.
      allowed_updates: ["callback_query", "message"],
    });
    if (!res.ok) {
      console.error(`TG approval: setWebhook FAILED (${res.description ?? "unknown error"}) -- url=${url}`);
      return;
    }
    console.error(`TG approval: webhook registered at ${url} (server=${cfg.server})`);
  } catch (err) {
    console.error(`TG approval: setWebhook threw: ${(err as Error).message} -- url=${url}`);
  }
}

/**
 * Best-effort регистрация постоянных UI-точек входа бота
 * (`docs/TZ_automation_key_note_delivery_and_buttons.md` раздел 2):
 *  1. `setMyCommands` — `/automation_key` появляется в автодополнении команд
 *     Telegram при наборе `/` в чате с ботом (не нужно печатать вручную).
 *  2. `setChatMenuButton` — постоянная кнопка РЯДОМ С ПОЛЕМ ВВОДА (не в
 *     клавиатуре сообщения, отдельный persistent UI-элемент Telegram),
 *     открывающая мини-апп `automation-key-app` в одно касание.
 *
 * Оба вызова идемпотентны — Telegram просто переустанавливает то же самое
 * значение на каждом старте, без вреда, поэтому безопасно звать это на
 * КАЖДОМ старте КАЖДОГО сервера (в отличие от `registerWebhook`, которым
 * владеет ровно один сервер через `TG_WEBHOOK_OWNER` — здесь такого
 * ограничения нет, даже если бот-токен общий на всех шестерых). Каждый из
 * двух вызовов — независимый best-effort try/catch: сбой одного не мешает
 * другому и не бросает исключение наружу — вызывающий код (http.ts) зовёт
 * эту функцию без своего try/catch именно поэтому.
 */
export async function registerBotUiEntryPoints(cfg: TgApprovalConfig): Promise<void> {
  if (!cfg.enabled) return;

  try {
    const res = await tgCall(cfg, "setMyCommands", {
      commands: [
        { command: "automation_key", description: "Ключ для автоматики (временный/постоянный)" },
        // Веб-хаб подтверждений (docs/TZ_consent_web_hub.md часть 2) — РЯДОМ
        // с automation_key, не заменяет её. Обработчик — http.ts's `/tg/webhook`
        // (`isConsentHubMessage`); best-effort, ничего не бросает, если
        // CONSENT_HUB_SECRET не задан (обработчик тогда просто молчит).
        { command: "consent_hub", description: "Веб-хаб подтверждений (список + галочки)" },
      ],
    });
    if (!res.ok) {
      console.error(`TG approval: setMyCommands FAILED (${res.description ?? "unknown error"})`);
    }
  } catch (err) {
    console.error(`TG approval: setMyCommands threw: ${(err as Error).message}`);
  }

  if (!cfg.publicBaseUrl) {
    console.error("TG approval: publicBaseUrl не задан — кнопка меню чата (мини-апп) не устанавливается.");
    return;
  }
  try {
    const url = `${cfg.publicBaseUrl.replace(/\/+$/, "")}/automation-key-app`;
    const res = await tgCall(cfg, "setChatMenuButton", {
      menu_button: { type: "web_app", text: "Ключ", web_app: { url } },
    });
    if (!res.ok) {
      console.error(`TG approval: setChatMenuButton FAILED (${res.description ?? "unknown error"}) -- url=${url}`);
    }
  } catch (err) {
    console.error(`TG approval: setChatMenuButton threw: ${(err as Error).message}`);
  }
}

// ───────────────────────── Sweep (bot chat hygiene) ──────────────────────────

/**
 * Периодическая чистка (Максим, 2026-08-05): "кнопки по таймауту прям
 * удалять" / "такой же таймаут делать для удаления экрана после отказать".
 * Вызывается ТОЛЬКО на сервере-владельце вебхука (http.ts's setInterval,
 * гейтуется тем же `cfg.webhookOwner`, что и registerWebhook) — только он
 * держит рабочий путь записи в Telegram для строк ЛЮБОГО из 6 серверов (та
 * же логика, что у `consumeTgDecisionAnyServer` — таблица общая, читать
 * чужие строки здесь безопасно и осознанно).
 *
 * Две независимые группы, каждая — best-effort (одна упавшая правка
 * сообщения не должна ронять всю подчистку):
 *  1. PENDING, TTL истёк — никто не нажал кнопку. Кнопка снимается
 *     (`editMessageReplyMarkup` с пустой клавиатурой), само сообщение
 *     остаётся (текст плана — не мусор, может пригодиться для истории).
 *  2. APPROVED/REJECTED, TTL истёк с момента решения — сообщение целиком
 *     удаляется (`deleteMessage`), чтобы чат бота по умолчанию оставался
 *     пустым (осознанное UX-требование, не побочный эффект).
 */
export async function runApprovalSweep(
  cfg: TgApprovalConfig,
  store: TgApprovalStore,
  nowFn: () => number = Date.now,
): Promise<void> {
  if (!cfg.enabled || !cfg.webhookOwner) return;
  const now = nowFn();

  const expiredPending = await store.claimExpiredPendingApprovals(now);
  for (const row of expiredPending) {
    if (row.messageId == null) continue;
    await tgCall(cfg, "editMessageReplyMarkup", {
      chat_id: row.chatId,
      message_id: row.messageId,
      reply_markup: { inline_keyboard: [] },
    }).catch((err) => console.error(`TG sweep: editMessageReplyMarkup failed for ${row.manifestId}: ${err}`));
  }

  const staleDecided = await store.claimStaleDecidedApprovals(now);
  for (const row of staleDecided) {
    if (row.messageId == null) continue;
    await tgCall(cfg, "deleteMessage", {
      chat_id: row.chatId,
      message_id: row.messageId,
    }).catch((err) => console.error(`TG sweep: deleteMessage failed for ${row.manifestId}: ${err}`));
  }

  if (expiredPending.length || staleDecided.length) {
    console.error(
      `TG sweep: сняты кнопки у ${expiredPending.length} просроченных, ` +
        `удалено сообщений решённых — ${staleDecided.length}`,
    );
  }
}
