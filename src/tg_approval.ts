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
  status: "PENDING" | "APPROVED" | "REJECTED";
  createdAt: number;
  expiresAt: number;
  decidedAt: number | null;
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
const PREVIEW_CAP = 400;

function apiUrl(cfg: TgApprovalConfig, method: string): string {
  return `${TELEGRAM_API}/bot${cfg.botToken}/${method}`;
}

function clipPreview(s: string, max = PREVIEW_CAP): string {
  const one = s.trim();
  return one.length > max ? one.slice(0, max) + "…" : one;
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
async function tgCall(cfg: TgApprovalConfig, method: string, body: unknown): Promise<TgCallResult> {
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
        const text = `${clipPreview(previewBody)}\n\n${meta.tool} · ${meta.accountLabel}`;
        const sent = await tgCall(cfg, "sendMessage", {
          chat_id: cfg.ownerChatId,
          text,
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
 *     taken at face value. The manifest may belong to ANY of the servers
 *     sharing this bot token (single shared webhook — see `registerWebhook`'s
 *     `TG_WEBHOOK_OWNER` guard), not necessarily this process's own `cfg.
 *     server` — hence `consumeTgDecisionAnyServer` below, not the server-
 *     scoped `consumeTgDecision`.
 *  4. anti-replay         — atomic `consumeTgDecisionAnyServer` (`WHERE
 *     status = 'PENDING'`); a second tap on the same callback is a no-op here.
 *  5. answerCallbackQuery — always called, so the tap's spinner clears.
 *  6. editMessageReplyMarkup — removes the buttons after ANY decision is
 *     recorded, so a second tap has nothing left to press.
 *  7. anything that isn't `callback_query` is ignored (early return).
 */
export async function handleWebhook(
  cfg: TgApprovalConfig,
  store: TgApprovalStore,
  update: TelegramCallbackUpdate,
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
  // Server-agnostic on purpose: this ONE webhook (owned by whichever server
  // has TG_WEBHOOK_OWNER=true) services approval buttons for EVERY server
  // sharing this bot token, so `cfg.server` (always "$self") is the WRONG
  // filter here — the manifest being decided may belong to any of them.
  // Safe because `manifest_id` is globally unique (tg_approvals' PRIMARY KEY).
  const consumed = await store.consumeTgDecisionAnyServer(manifestId, decision);

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
  if (!cfg.webhookOwner) {
    console.error(
      `TG approval: TG_APPROVAL_ENABLED=true but TG_WEBHOOK_OWNER is not "true" -- this server will ` +
        `NOT call setWebhook and will not receive Telegram button taps. When one bot token is shared ` +
        `across several MCP servers, exactly ONE of them must set TG_WEBHOOK_OWNER=true; every other ` +
        `server must leave it unset (default false), or their setWebhook calls will silently overwrite ` +
        `each other and approvals for whichever server registered last will stop reaching anyone.`,
    );
    return;
  }
  const url = `${cfg.publicBaseUrl.replace(/\/+$/, "")}/tg/webhook`;
  try {
    const res = await tgCall(cfg, "setWebhook", {
      url,
      secret_token: cfg.webhookSecret,
      allowed_updates: ["callback_query"],
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
