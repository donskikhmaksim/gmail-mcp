import express, { type Request, type Response } from "express";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { Account, Config, User } from "./config.js";
import { buildMcpServer } from "./server.js";
import { GoogleFederatedProvider } from "./oauthProvider.js";
import {
  getGoogleAccounts,
  listGoogleAccounts,
  removeGoogleAccount,
  setDefaultAccount,
  renameAccount,
  listApprovedUnexecuted,
  getApprovedUnexecuted,
  listPendingConsents,
  storeReady,
  type AutoExecuteCandidateRow,
} from "./store.js";
import { renderDashboard } from "./dashboard.js";
import { renderConsentHubPage, summarizePendingManifest, type PendingConsentItem } from "./consent_hub.js";
import { logDashboardLocation, logConsentHubLocation } from "./logRedaction.js";
import { initDownloads, resolveDownloadLink } from "./downloads.js";
import { buildUserClients } from "./accounts.js";
import {
  tgApprovalConfig,
  tgApprovalStoreAdapter,
  consentStoreAdapter,
  consentServerConfig,
  pgStoreAdapter,
  automationKeyConfig,
  automationWindowStoreAdapter,
} from "./server.js";
import {
  handleWebhook,
  registerWebhook,
  registerBotUiEntryPoints,
  runApprovalSweep,
  reportAutoExecutionResult,
  secretTokenMatches,
  tgCall,
} from "./tg_approval.js";
import {
  handleAutomationKeyMessage,
  handleAutomationKeyCallback,
  generateAndDeliverKeyForScope,
  isValidDurationMs,
  windowStatus,
  humanScope,
  reissueNoteForWindow,
  normalizeScopeTokens,
  SCOPE_TOKEN_RE,
  MAX_SCOPE_TOKENS,
  LIST_LIMIT as AUTOMATION_KEY_LIST_LIMIT,
} from "./automation_key.js";
import { renderAutomationKeyMiniAppPage, verifyTelegramInitData } from "./automation_key_miniapp.js";
import { tryAutoExecute } from "./consent.js";
import { getAutoExecutor, type AutoExecutorCtx } from "./autoExecute.js";
import { buildGatedToolsCatalog } from "./gated_tools_catalog.js";
import { loadExternalCatalogUrls, loadConsentHubSecret } from "./config.js";
import { fetch as undiciFetch } from "undici";

const JSONRPC_UNAUTHORIZED = {
  jsonrpc: "2.0" as const,
  error: { code: -32001, message: "Unauthorized" },
  id: null,
};

function tokensEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function extractLegacyToken(req: Request): string {
  const header = req.header("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match?.[1]) return match[1];
  const apiKey = req.header("x-api-key");
  if (apiKey) return apiKey;
  const q = req.query?.key ?? req.query?.token;
  if (typeof q === "string") return q;
  return "";
}

function resolveLegacyUser(req: Request, config: Config): User | null {
  const provided = extractLegacyToken(req);
  if (!provided) return null;
  for (const user of config.users) {
    if (user.token && tokensEqual(provided, user.token)) return user;
  }
  return null;
}

/**
 * Chooses which User to serve a static-token (legacy MCP_AUTH_TOKEN) request
 * with, when onboarding is enabled: prefer live Postgres-backed accounts,
 * falling back to the env-configured `legacyUser` only when onboarding has
 * nothing linked yet (or is disabled). Pulled out of handleMcp as a pure,
 * Express-free function so it is unit-testable without a running server or a
 * real database — see scripts/test-credential-source.mjs.
 */
export async function selectLegacyOrOnboardingUser(
  legacyUser: User,
  onboardingEnabled: boolean,
  fetchOnboardingUser: () => Promise<User | null>,
): Promise<User | null> {
  if (!onboardingEnabled) return legacyUser;
  const onboardingUser = await fetchOnboardingUser();
  return onboardingUser ?? (legacyUser.accounts.length ? legacyUser : null);
}

/** Builds the User from ALL Google accounts linked to this instance via onboarding. */
export async function userFromGoogleAccounts(config: Config): Promise<User | null> {
  const accounts = await getGoogleAccounts();
  if (!accounts.length) return null;
  const clientId = config.onboarding.googleClientId!;
  const clientSecret = config.onboarding.googleClientSecret!;
  const mapped: Account[] = accounts.map((a) => ({
    name: a.label,
    email: a.email,
    auth: { mode: "oauth", clientId, clientSecret, refreshToken: a.refreshToken },
  }));
  const def = accounts.find((a) => a.isDefault) ?? accounts[0];
  return {
    name: def.email,
    accounts: mapped,
    defaultAccount: def.label,
  };
}

/**
 * Content-Disposition that survives non-ASCII names: a sanitised fallback for
 * old clients plus the RFC 5987 UTF-8 form modern ones prefer.
 */
function contentDisposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/** Constant-time compare for the dashboard path secret. */
function secretMatches(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Package S5 (`[R:приоритеты-3]`, plan §0.13): fail-closed `/mcp` when no
 * auth mechanism is configured. `config.requireAuth` is false exactly when a
 * deployment sets neither `MCP_AUTH_TOKEN` nor onboarding OAuth — before this
 * fix, `handleMcp` served every caller as `config.users[0]` with ZERO
 * authentication, including the 4 consent-gated send tools: an external
 * caller could invoke `gmail_send` and simply supply its own `user_reply`,
 * walking straight through the gate (STANDARD §1.2 obход, §1.5 fail-closed by
 * default). Refuse with 503 instead. The only escape hatch is an explicit env
 * opt-out for local development, logged loudly every time it's read so it
 * can't go unnoticed in a deploy's logs.
 *
 * Read fresh (not cached at module scope) so a single process can run
 * multiple server instances with different env — see
 * scripts/test-s5-failclosed.mjs, which does exactly that.
 */
function allowUnauthenticated(): boolean {
  return process.env.MCP_ALLOW_UNAUTHENTICATED?.trim().toLowerCase() === "true";
}

const NO_AUTH_CONFIGURED_MESSAGE =
  "No authentication is configured for this server (no MCP_AUTH_TOKEN, no onboarding OAuth). " +
  "Refusing unauthenticated access to /mcp, since that would let ANY caller invoke every tool " +
  "unauthenticated -- including the 4 consent-gated send tools, where the caller could simply " +
  "supply its own user_reply and walk through the gate. Set MCP_AUTH_TOKEN, enable onboarding " +
  "OAuth, or (LOCAL DEVELOPMENT ONLY) set MCP_ALLOW_UNAUTHENTICATED=true.";

/**
 * Авто-исполнение по кнопке в Telegram (Максим, 2026-08-05: «нажал кнопку —
 * должно сразу исполниться на бэке, не ждать повторного вызова моделью»).
 * В ОТЛИЧИЕ от `runApprovalSweep` (тот работает ТОЛЬКО на владельце
 * вебхука) — этот поллер работает НА КАЖДОМ сервере, включая этот, без
 * гейта по `webhookOwner`: исполнение полностью децентрализовано, сервер
 * следит только за СВОИМИ манифестами (`consent_manifests.server` = свой
 * server) — никакой межпроцессной связи с другими серверами не нужно,
 * кнопка уже централизованно решается общим вебхуком (см. `handleWebhook`),
 * а этот поллер просто видит результат в общем Postgres.
 *
 * Два независимых режима гейта (Максим подтвердил явно) остаются нетронуты:
 * если `TG_APPROVAL_ENABLED=false` (или тул не в allowlist) — сюда манифест
 * вообще не попадёт (нет строки в tg_approvals), обычный чат-«да»-путь через
 * `requireConsent()` работает побайтово как раньше.
 */
async function runAutoExecutePoller(config: Config): Promise<void> {
  const candidates = await listApprovedUnexecuted(consentServerConfig.server, Date.now());
  if (!candidates.length) return;

  // Один ctx на весь тик — тот же объект уходит и в rehash (для тулов с
  // настоящим биндингом, которым нужен живой `g`), и в execute, см.
  // `autoExecute.ts`'s `AutoExecutorCtx` doc-comment.
  const ctx = await buildAutoExecuteCtx(config);
  if (!ctx) {
    console.error("TG auto-execute: нет доступного пользователя — пропускаю тик поллера");
    return;
  }

  for (const c of candidates) {
    await executeApprovedCandidate(c, ctx);
  }
}

/**
 * Собирает контекст исполнения (аккаунты Google + адаптеры хранилища) — общий
 * для ОБОИХ путей исполнения: фонового поллера (тик) и немедленного запуска по
 * нажатию кнопки (`executeApprovedNow`). `store` — ТОТ ЖЕ адаптер, что
 * per-request путь получает как `snoozeCtx.store` (server.ts's
 * `buildMcpServer`) — `null` ровно когда DATABASE_URL не настроен, честно как и
 * там. Возвращает null, когда ни одного Google-аккаунта нет — исполнять нечем.
 */
async function buildAutoExecuteCtx(config: Config): Promise<AutoExecutorCtx | null> {
  const user = (await userFromGoogleAccounts(config)) ?? config.users[0] ?? null;
  if (!user) return null;
  return {
    clients: buildUserClients(user),
    consentStore: consentStoreAdapter,
    userToken: user.token ?? null,
    store: storeReady() ? pgStoreAdapter : null,
  };
}

/**
 * Исполняет ОДИН одобренный кандидат. Единственное место, где живёт связка
 * «захват → исполнение → отчёт», общая для поллера и для немедленного пути:
 * захват (одноразовость) — атомарный `consumeManifest` ВНУТРИ `tryAutoExecute`,
 * поэтому два одновременных вызова этой функции на один манифест дают ровно
 * одно исполнение (второй получит `null` и молча выйдет). Никогда не бросает.
 */
async function executeApprovedCandidate(c: AutoExecuteCandidateRow, ctx: AutoExecutorCtx): Promise<void> {
  const executor = getAutoExecutor(c.tool);
  if (!executor) {
    // Инструмент ещё не переведён на новый паттерн (см. autoExecute.ts) —
    // манифест останется PENDING/APPROVED и будет исполнен, как только
    // модель сама позовёт execute (старый путь), либо когда этот тул
    // получит свой executor. НЕ ошибка, просто ещё не покрыто.
    return;
  }
  try {
    const result = await tryAutoExecute(
      { manifestId: c.manifestId, tool: c.tool, accountLabel: c.accountLabel },
      executor.rehash,
      consentStoreAdapter,
      consentServerConfig,
      ctx,
    );
    if (!result) return; // гонка/дрейф/истёк — тихо пропускаем, это не ошибка
    const reportText = await executor.execute(result.payload, result.auditId, ctx);
    await reportAutoExecutionResult(tgApprovalConfig, c.chatId, c.messageId, reportText);
  } catch (err) {
    console.error(`TG auto-execute: ошибка при исполнении ${c.tool}/${c.manifestId}:`, err);
    // НЕ помечаем как исполненное при ошибке ДО tryAutoExecute — если он
    // успел вызвать consumeManifest (манифест одноразовый), повторной
    // попытки уже не будет; отчёт об ошибке всё равно стоит попытаться
    // отправить, чтобы Максим не остался с зависшими кнопками в боте.
    await reportAutoExecutionResult(
      tgApprovalConfig, c.chatId, c.messageId,
      `🛑 Ошибка при автоисполнении «${c.tool}»: ${err instanceof Error ? err.message : String(err)}`,
    ).catch(() => {});
  }
}

/**
 * НЕМЕДЛЕННОЕ исполнение по нажатию кнопки (Максим, 2026-08-06: «отчёт пришёл
 * спустя секунд 10, надо ускорять» — фактический замер по проду: кнопка нажата
 * 13:22:28, аудит исполнения 13:22:34, то есть ожидание следующего тика
 * поллера съедало до 10 с на ровном месте).
 *
 * Вызывается из хука `handleWebhook`'s `onApproved` — то есть ТОЛЬКО когда
 * атомарный консюм решения в БД уже выиграл именно это нажатие. Основной путь;
 * поллер ниже остаётся страховкой (перезапуск процесса, упавший хук, решение,
 * принятое пока сервер лежал).
 *
 * Server-scoping: вебхук-владелец получает нажатия по манифестам ВСЕХ
 * серверов, делящих один бот-токен, поэтому чужие здесь отсекаются дважды —
 * явной проверкой `row.server` у вызывающего и `m.server = $2` внутри
 * `getApprovedUnexecuted`. Чужой манифест исполнит поллер его собственного
 * сервера, ровно как и раньше.
 */
async function executeApprovedNow(config: Config, manifestId: string): Promise<void> {
  const candidate = await getApprovedUnexecuted(manifestId, consentServerConfig.server, Date.now());
  // null — либо манифест не наш/истёк/уже потреблён (например поллер успел
  // первым), либо тул ещё не покрыт авто-исполнением: это не ошибка.
  if (!candidate) return;
  const ctx = await buildAutoExecuteCtx(config);
  if (!ctx) {
    console.error("TG auto-execute: нет доступного пользователя — немедленное исполнение отложено до поллера");
    return;
  }
  await executeApprovedCandidate(candidate, ctx);
}

/** Базовые URL-ы четырёх соседних сервисов, чей `/automation-key-catalog`
 * фетчит мини-апп (docs/TZ_automation_key_method_catalog.md) — вычислено
 * один раз на модуль, тем же приёмом, что и `tgApprovalConfig`/`automationKeyConfig`
 * в server.ts (чистое чтение env, без побочных эффектов/бросков). */
const externalCatalogUrls = loadExternalCatalogUrls();

// ═══════════════════════ Веб-хаб подтверждений (docs/TZ_consent_web_hub.md, часть 2) ═══════════════════════

/** Общий секрет хаба — ОДНА строка на всех 5 сервисах (env `CONSENT_HUB_SECRET`).
 * `undefined` ⇒ обе локальные ручки (`/pending-consents`, `/pending-consents/decide`)
 * и обе хабовые (`/consent-hub/:secret`, `/consent-hub-api/*`) отвечают 404 —
 * fail-closed по умолчанию, та же дисциплина, что у `DASHBOARD_SECRET`. */
const consentHubSecret = loadConsentHubSecret();

/** Константный по времени guard для `X-Consent-Hub-Secret` — используется
 * И локальными `/pending-consents*` (проверяют СВОЙ секрет), И хабовыми
 * `/consent-hub-api/*` (проверяют, что браузер прислал ПРАВИЛЬНЫЙ секрет
 * gmail-mcp, прежде чем сервер сам добавит его в запросы к соседям). Секрет
 * не задан ⇒ 404 (не 401/403 — не подтверждаем существование роута, ТЗ тест 7/8). */
function consentHubGuard(req: Request, res: Response): boolean {
  if (!consentHubSecret) {
    res.status(404).end();
    return false;
  }
  const provided = req.header("x-consent-hub-secret") ?? "";
  if (!provided || !secretMatches(provided, consentHubSecret)) {
    res.status(404).end();
    return false;
  }
  return true;
}

type DecideOutcome =
  | { status: 200; body: { ok: true; outcome: "confirmed" | "refused"; result?: string } }
  | { status: number; body: { ok: false; error: string } };

/** `decide confirm` для СВОИХ манифестов — РОВНО тот же путь, что нажатие
 * кнопки в Telegram (`executeApprovedCandidate`/`executeApprovedNow` выше):
 * `tryAutoExecute` (binding + атомарный consume) + зарегистрированный
 * `executor.execute()` (autoExecute.ts) — без дублирования логики. */
async function decideOwnConfirm(config: Config, manifestId: string): Promise<DecideOutcome> {
  const row = await consentStoreAdapter.getManifest(manifestId, consentServerConfig.server);
  if (!row) return { status: 404, body: { ok: false, error: "not_found" } };
  if (row.status !== "AWAITING_CONSENT") return { status: 409, body: { ok: false, error: "already_decided" } };
  if (Date.now() > row.expiresAt) return { status: 410, body: { ok: false, error: "expired" } };
  const executor = getAutoExecutor(row.tool);
  if (!executor) return { status: 422, body: { ok: false, error: "not_supported" } };
  const ctx = await buildAutoExecuteCtx(config);
  if (!ctx) return { status: 503, body: { ok: false, error: "no_account" } };
  // Binding — ПЕРЕД consume, чтобы отдать отдельный, машиночитаемый
  // `binding_mismatch` (ТЗ), а не слить его в общий `already_decided`.
  const currentHash = await executor.rehash(row.payload, ctx);
  if (currentHash !== row.objectHash) return { status: 409, body: { ok: false, error: "binding_mismatch" } };
  const result = await tryAutoExecute(
    { manifestId, tool: row.tool, accountLabel: row.accountLabel },
    executor.rehash,
    consentStoreAdapter,
    consentServerConfig,
    ctx,
  );
  if (!result) return { status: 409, body: { ok: false, error: "already_decided" } }; // проиграл гонку атомарного consume
  const reportText = await executor.execute(result.payload, result.auditId, ctx);
  return { status: 200, body: { ok: true, outcome: "confirmed", result: reportText } };
}

/** `decide reject` для СВОИХ манифестов — тот же путь отказа, что и обычная
 * человеческая негация в `requireConsent` (invalidate + аудит), `comment`
 * (если есть) записывается как `userReply`, дословно. */
async function decideOwnReject(manifestId: string, comment: string): Promise<DecideOutcome> {
  const row = await consentStoreAdapter.getManifest(manifestId, consentServerConfig.server);
  if (!row) return { status: 404, body: { ok: false, error: "not_found" } };
  if (row.status !== "AWAITING_CONSENT") return { status: 409, body: { ok: false, error: "already_decided" } };
  if (Date.now() > row.expiresAt) return { status: 410, body: { ok: false, error: "expired" } };
  await consentStoreAdapter.invalidateManifest(manifestId, consentServerConfig.server, comment);
  await consentStoreAdapter.appendConsentAudit({
    id: randomUUID(),
    ts: Date.now(),
    server: consentServerConfig.server,
    tool: row.tool,
    accountLabel: row.accountLabel,
    manifestId,
    objectHash: row.objectHash,
    userReply: comment,
    checks: { source: "web_hub" },
    outcome: "invalidated",
    refusalReason: "web_hub_reject",
    actor: "human",
  });
  return { status: 200, body: { ok: true, outcome: "refused" } };
}

/** Фетчит `/pending-consents` соседнего сервиса. Никогда не бросает — сбой
 * (сеть/таймаут/не-200/не-JSON) возвращается как `null`, чтобы агрегатор мог
 * деградировать (ТЗ: недоступность одного сервиса не роняет остальные). */
async function fetchNeighborPending(
  service: string,
  baseUrl: string,
  secret: string,
): Promise<{ service: string; items: PendingConsentItem[] } | null> {
  try {
    const res = await undiciFetch(`${baseUrl.replace(/\/+$/, "")}/pending-consents`, {
      headers: { "X-Consent-Hub-Secret": secret },
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return null;
    const json = (await res.json()) as { service?: string; items?: PendingConsentItem[] };
    if (!Array.isArray(json.items)) return null;
    return { service: json.service ?? service, items: json.items };
  } catch {
    return null;
  }
}

/** Проксирует `decide` соседнему сервису, добавляя `X-Consent-Hub-Secret`
 * заголовком — браузер секрета соседей не видит вообще (ТЗ). */
async function proxyNeighborDecide(
  baseUrl: string,
  secret: string,
  body: { manifestId: string; decision: "confirm" | "reject"; comment?: string },
): Promise<{ status: number; json: unknown }> {
  try {
    const res = await undiciFetch(`${baseUrl.replace(/\/+$/, "")}/pending-consents/decide`, {
      method: "POST",
      headers: { "content-type": "application/json", "X-Consent-Hub-Secret": secret },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
  } catch (err) {
    return { status: 502, json: { ok: false, error: "unreachable", detail: (err as Error).message } };
  }
}

export async function startHttpServer(config: Config): Promise<void> {
  const app = express();
  // Railway (and most PaaS) terminate TLS behind a reverse proxy; trust its
  // X-Forwarded-For so express-rate-limit (used by the SDK's auth handlers)
  // keys correctly per real client IP instead of the proxy's.
  app.set("trust proxy", 1);
  app.use(express.json({ limit: "10mb" }));
  // Dashboard forms POST application/x-www-form-urlencoded.
  app.use(express.urlencoded({ extended: false }));

  app.get("/", (_req, res) => {
    res.json({ status: "ok", endpoint: "/mcp" });
  });
  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // ---- Optional Telegram-approval webhook (plan-tg-approval.md) ----
  // Deliberately OUTSIDE the normal /mcp auth -- Telegram itself calls this,
  // not an MCP client. Protected by the secret_token Telegram echoes back on
  // every request (set via registerWebhook's setWebhook call below), checked
  // constant-time. Mounted unconditionally (cheap route, no-op body) so
  // toggling TG_APPROVAL_ENABLED never needs a redeploy of routing -- when
  // disabled, tgApprovalConfig.webhookSecret is "" and secretTokenMatches
  // rejects every request (empty expected secret never matches).
  app.post("/tg/webhook", async (req: Request, res: Response) => {
    // Route-level gate on TG_WEBHOOK_OWNER -- checked FIRST, before reading
    // the secret header or the body. Defense-in-depth alongside
    // registerWebhook's own self-guard (tg_approval.ts): since
    // consumeTgDecisionAnyServer made webhook consume server-agnostic across
    // all 6 MCP servers that will eventually share one Telegram bot token
    // (gmail/sheets/calendar/docs/drive-mcp + ticktick-mcp), a
    // TG_APPROVAL_WEBHOOK_SECRET leak on ANY single one of them would
    // otherwise let an attacker decide approvals for every other server too
    // -- including gmail_send, the most dangerous one. A server that isn't
    // the designated owner must never process this route at all, even with a
    // technically-correct secret, and must never depend on whoever ports this
    // file to the other 5 repos remembering to not mount the route --
    // 404 (not 401) so a non-owner server doesn't even reveal the route exists.
    //
    // `|| tgApprovalConfig.ownBot` (TG_BOT_TOKEN_OVERRIDE, config.ts): a
    // server running its OWN Telegram bot owns ITS OWN webhook by
    // definition -- there is no "shared token, one owner" ambiguity to
    // guard against for it, so it must accept the route even with
    // TG_WEBHOOK_OWNER unset/false. Both flags being true on the SAME
    // process (gmail-mcp keeping its legacy TG_WEBHOOK_OWNER=true while ALSO
    // getting its own TG_BOT_TOKEN_OVERRIDE one day) does not double-mount
    // this route -- it's the same single `app.post` handler either way, the
    // OR just widens which servers pass the gate. That combination is a
    // real config hazard, but a different one, and it lives one level down:
    // `cfg.botToken` (this whole process's Telegram identity) switches to
    // the override, so registerWebhook's `setWebhook` call below registers
    // THIS server's own bot at this URL, not the shared one anymore --
    // registerWebhook logs a loud warning for exactly that case (see its
    // own doc comment in tg_approval.ts) so a deployer catches it in logs
    // instead of silently losing the shared webhook for the other 5 servers.
    if (!tgApprovalConfig.webhookOwner && !tgApprovalConfig.ownBot) {
      res.status(404).end();
      return;
    }
    const provided = req.header("x-telegram-bot-api-secret-token") ?? "";
    if (!secretTokenMatches(provided, tgApprovalConfig.webhookSecret)) {
      res.status(401).end();
      return;
    }
    try {
      // automation_key hub (docs/TZ_automation_key_hub.md) — обрабатывается
      // ПЕРВЫМ и СВОИМИ, ОТДЕЛЬНЫМИ обработчиками:
      //  • текстовые `/automation_key*` — до этого момента вебхук видел
      //    только `callback_query` (allowed_updates), теперь ещё и `message`
      //    (см. `registerWebhook`'s комментарий в tg_approval.ts);
      //  • нажатия кнопок с `callback_data`, начинающимся на `ak:` — заведомо
      //    НЕ пересекаются с обычным гейтом подтверждения (тот матчит только
      //    ОДНОБУКВЕННЫЙ префикс `a:`/`r:` — `handleAutomationKeyCallback`
      //    возвращает `false` и ничего не делает для любых других данных, так
      //    что `handleWebhook` ниже по-прежнему получает шанс их обработать).
      const msg = req.body?.message;
      const text = typeof msg?.text === "string" ? msg.text : "";
      const isAutomationKeyMessage = !!msg && /^\/automation_key\b/.test(text.trim());
      // Пункт открытия веб-хаба подтверждений (docs/TZ_consent_web_hub.md
      // часть 2, "добавь пункт рядом с уже сделанной для automation_key — не
      // ломай её") — РЯДОМ с automation_key-веткой, СВОЯ команда, ничего в
      // существующей ветке не меняет.
      const isConsentHubMessage = !!msg && /^\/consent_hub\b/.test(text.trim());
      const cqData = req.body?.callback_query?.data;
      const isAutomationKeyCallback = typeof cqData === "string" && cqData.startsWith("ak:");

      if (isConsentHubMessage) {
        const fromId = String(msg.from?.id ?? "");
        if (fromId && fromId === tgApprovalConfig.ownerChatId && consentHubSecret) {
          const hubBaseUrl = config.onboarding.publicBaseUrl || tgApprovalConfig.publicBaseUrl || "";
          const url = `${hubBaseUrl.replace(/\/+$/, "")}/consent-hub/${consentHubSecret}`;
          await tgCall(tgApprovalConfig, "sendMessage", {
            chat_id: msg.chat?.id,
            text: "Подтверждения — веб-хаб",
            reply_markup: { inline_keyboard: [[{ text: "Открыть хаб", web_app: { url } }]] },
          }).catch((err) => console.error("consent_hub message: sendMessage failed:", err));
        }
      } else if (isAutomationKeyMessage) {
        await handleAutomationKeyMessage(tgApprovalConfig, automationWindowStoreAdapter, {
          chatId: msg.chat?.id,
          fromId: msg.from?.id,
          text,
        });
      } else if (isAutomationKeyCallback) {
        const cq = req.body.callback_query;
        await handleAutomationKeyCallback(tgApprovalConfig, automationKeyConfig, automationWindowStoreAdapter, {
          id: cq.id,
          fromId: cq.from?.id,
          data: cq.data,
          chatId: cq.message?.chat?.id,
          messageId: cq.message?.message_id,
        });
      } else {
        // 4-й аргумент — хук немедленного исполнения (Максим, 2026-08-06:
        // «исполнять прямо в обработчике нажатия, не дожидаясь опроса»).
        // Намеренно СИНХРОННЫЙ по отношению к этому обработчику: он лишь
        // ЗАПУСКАЕТ фоновую работу и тут же возвращает управление, поэтому ни
        // снятие кнопок, ни `answerCallbackQuery`, ни ответ 200 её не ждут —
        // Telegram получает подтверждение доставки сразу, как и раньше.
        await handleWebhook(tgApprovalConfig, tgApprovalStoreAdapter, req.body, (row) => {
          // Чужой сервер (общий бот на 6 MCP-серверов) — не наш манифест, его
          // исполнит поллер того сервера. См. `executeApprovedNow`.
          if (row.server !== consentServerConfig.server) return;
          void executeApprovedNow(config, row.manifestId).catch((err) =>
            console.error(`TG auto-execute: немедленное исполнение ${row.manifestId} упало:`, err),
          );
        });
      }
    } catch (err) {
      console.error("TG approval webhook error:", err);
    }
    // Always 200 -- Telegram retries on non-2xx, and every failure mode here
    // (wrong from.id, replay, unknown callback_data) is intentionally a no-op,
    // not an error Telegram should retry.
    res.status(200).end();
  });

  // ---- automation_key Mini App (docs/TZ_automation_key_miniapp.md,
  // docs/TZ_automation_key_method_catalog.md) ----
  // Второй, более удобный способ выбрать сервисы/методы для automation_key
  // поверх уже рабочей кнопочной версии (src/automation_key.ts) — не
  // заменяет её. GET отдаёт статическую разметку БЕЗ авторизации (сама
  // разметка не секрет, ТЗ раздел 1/8); POST — единственное место, где
  // что-то реально происходит, и оно ОБЯЗАНО проверить initData на
  // подлинность/свежесть/владельца (ТЗ раздел 4) прежде чем звать ту же
  // `generateAndDeliverKeyForScope`, что и кнопочный `ak:gen` (через
  // `generateAndDeliverKey`'s mask→scope обёртку) — сырой токен уходит
  // только сообщением в чат с 10с-самоудалением, никогда в этом HTTP-ответе
  // (ТЗ раздел 5).
  app.get("/automation-key-app", (_req: Request, res: Response) => {
    res.type("html").send(renderAutomationKeyMiniAppPage(externalCatalogUrls));
  });

  // ---- Автосправочник гейтированных методов (docs/
  // TZ_automation_key_method_catalog.md раздел 2) ----
  // БЕЗ авторизации (список ИМЁН методов не секрет — тот же принцип, что и
  // сам `tools/list` по факту доступен любому, кто прошёл MCP-авторизацию;
  // здесь даже без неё, т.к. имена методов не являются чувствительными
  // данными). Собственный каталог ЭТОГО сервера (gmail) — фетчится своим же
  // мини-аппом БЕЗ сети (same-origin), четыре соседних сервиса (calendar/
  // drive/sheets/docs) фетчат свой такой же роут по `externalCatalogUrls`.
  app.get("/automation-key-catalog", async (_req: Request, res: Response) => {
    try {
      const tools = await buildGatedToolsCatalog();
      res.json({ service: consentServerConfig.server, tools });
    } catch (err) {
      console.error("automation-key-catalog error:", err);
      res.status(500).json({ error: "internal" });
    }
  });

  /**
   * Разбирает и валидирует `scopeTokens` из тела POST (docs/
   * TZ_automation_key_method_catalog.md раздел "Мини-апп" п.4): непустой
   * массив строк вида `<service>` или `<service>:<tool>`, каждая ≤ разумного
   * потолка count. Backend НЕ проверяет, что токен реально существует в
   * каком-то каталоге (сознательно вне рамок — ТЗ раздел "Явно НЕ входит"),
   * только формат — защита от мусора/DoS. Пишет 400 и возвращает `null` при
   * первом же провале валидации; вызывающий роут просто `return`-ится.
   */
  function parseScopeTokens(req: Request, res: Response): string[] | null {
    const raw = Array.isArray(req.body?.scopeTokens) ? (req.body.scopeTokens as unknown[]) : [];
    const tokens = raw.filter((t): t is string => typeof t === "string" && t.length > 0);
    if (tokens.length === 0) {
      res.status(400).json({ error: "empty_selection" });
      return null;
    }
    if (tokens.length > MAX_SCOPE_TOKENS) {
      res.status(400).json({ error: "too_many_tokens" });
      return null;
    }
    if (!tokens.every((t) => SCOPE_TOKEN_RE.test(t))) {
      res.status(400).json({ error: "invalid_scope_token" });
      return null;
    }
    return tokens;
  }

  app.post("/automation-key-app/generate", async (req: Request, res: Response) => {
    const initData = typeof req.body?.initData === "string" ? req.body.initData : "";
    const verified = verifyTelegramInitData(tgApprovalConfig.botToken, initData);
    if (!verified.ok) {
      res.status(403).json({ error: "invalid_init_data" });
      return;
    }
    // Тот же owner-only принцип, что и везде в automation_key.ts — только
    // другой источник личности (подписанные Telegram-данные вместо
    // callback_query.from.id).
    if (verified.userId !== tgApprovalConfig.ownerChatId) {
      res.status(403).json({ error: "forbidden" });
      return;
    }

    const tokens = parseScopeTokens(req, res);
    if (!tokens) return; // 400 уже отправлен parseScopeTokens

    // durationMs: null (бессрочно) — валиден как есть; иначе обязано пройти
    // isValidDurationMs (положительное, конечное, разумных размеров) — любая
    // другая ерунда с фронтенда (отсутствует, строка, 0, отрицательное,
    // NaN/Infinity) отклоняется явным 400, backend НЕ подставляет тихий
    // дефолт (ТЗ раздел 1).
    const rawDuration: unknown = req.body?.durationMs;
    if (rawDuration !== null && !isValidDurationMs(rawDuration)) {
      res.status(400).json({ error: "invalid_duration" });
      return;
    }
    const durationMs: number | null = rawDuration === null ? null : (rawDuration as number);

    // label: пустая/отсутствующая строка → null (ТЗ раздел 2), иначе как есть
    // (обрезано до разумной длины, чтобы не раздувать хранилище/сообщение).
    const rawLabel = req.body?.label;
    const trimmedLabel = typeof rawLabel === "string" ? rawLabel.trim() : "";
    const label: string | null = trimmedLabel === "" ? null : trimmedLabel.slice(0, 200);

    let result: Awaited<ReturnType<typeof generateAndDeliverKeyForScope>>;
    try {
      result = await generateAndDeliverKeyForScope(
        tgApprovalConfig,
        automationKeyConfig,
        automationWindowStoreAdapter,
        tgApprovalConfig.ownerChatId,
        normalizeScopeTokens(tokens),
        durationMs,
        label,
      );
    } catch (err) {
      console.error("automation-key-app/generate error:", err);
      res.status(500).json({ error: "internal" });
      return;
    }
    if (!result) {
      res.status(400).json({ error: "empty_selection" });
      return;
    }
    // `noteLink` — ссылка на self-destruct-заметку с зашифрованным ключом
    // (docs/TZ_automation_key_note_delivery_and_buttons.md раздел 1); `null`
    // только если сам сервис self-destroyed-notes оказался недоступен
    // (generateAndDeliverKeyForScope уже сообщила об этом отдельным
    // сообщением в чат). Страница показывает её напрямую (см.
    // automation_key_miniapp.ts) — ключ ТАКЖЕ продублирован сообщением в чат
    // (та же функция, осознанное решение — см. финальный отчёт задачи, ТЗ
    // раздел "Где показывается" явно разрешает дублирование).
    res.json({ ok: true, noteLink: result.noteLink });
  });

  // ---- Менеджер ключей в мини-аппе (второй таб «Мои ключи») ----
  // Три новых owner-only роута, ВСЕ проверяют initData тем же способом, что
  // и /generate выше (не новый механизм авторизации). Общий хелпер вместо
  // копипасты этой проверки в каждом роуте по отдельности.
  function requireOwnerInitData(req: Request, res: Response): string | null {
    const initData = typeof req.body?.initData === "string" ? req.body.initData : "";
    const verified = verifyTelegramInitData(tgApprovalConfig.botToken, initData);
    if (!verified.ok) {
      res.status(403).json({ error: "invalid_init_data" });
      return null;
    }
    if (verified.userId !== tgApprovalConfig.ownerChatId) {
      res.status(403).json({ error: "forbidden" });
      return null;
    }
    return verified.userId;
  }

  // Список ВСЕХ когда-либо выданных окон (docs п.1 задачи «менеджер ключей»)
  // — та же выборка/лимит/логика статуса, что и текстовый `/automation_key
  // list` в боте (`windowStatus`/`humanScope`, переиспользованы из
  // automation_key.ts, не задублированы). `hasStoredToken` — единственный
  // сигнал фронтенду, показывать ли кнопку «Ещё раз показать» у конкретного
  // окна (истинно только если мастер-секрет БЫЛ задан на момент создания
  // ИМЕННО этого окна — окна старше этой возможности его не имеют).
  app.post("/automation-key-app/list", async (req: Request, res: Response) => {
    if (!requireOwnerInitData(req, res)) return;
    try {
      const nowMs = Date.now();
      const { windows, total } = await automationWindowStoreAdapter.listAllWindows(AUTOMATION_KEY_LIST_LIMIT);
      res.json({
        ok: true,
        total,
        windows: windows.map((w) => ({
          windowId: w.windowId,
          label: w.label,
          scope: w.scope,
          scopeHuman: humanScope(w.scope),
          status: windowStatus(w, nowMs),
          createdAt: w.createdAt,
          expiresAt: w.expiresAt,
          revokedAt: w.revokedAt,
          hasStoredToken: w.tokenEncrypted !== null,
        })),
      });
    } catch (err) {
      console.error("automation-key-app/list error:", err);
      res.status(500).json({ error: "internal" });
    }
  });

  app.post("/automation-key-app/revoke", async (req: Request, res: Response) => {
    if (!requireOwnerInitData(req, res)) return;
    const windowId = typeof req.body?.windowId === "string" ? req.body.windowId : "";
    if (!windowId) {
      res.status(400).json({ error: "missing_window_id" });
      return;
    }
    try {
      const revoked = await automationWindowStoreAdapter.revokeWindow(windowId, Date.now());
      res.json({ ok: true, revoked });
    } catch (err) {
      console.error("automation-key-app/revoke error:", err);
      res.status(500).json({ error: "internal" });
    }
  });

  // Перевыпуск self-destruct-заметки для уже созданного окна (возможность 2
  // задачи «менеджер ключей») — расшифровывает `token_encrypted` мастер-
  // секретом и собирает ту же инструктивную заметку заново
  // (`reissueNoteForWindow`, automation_key.ts). Отказ — понятный 400 с
  // машиночитаемым `error` (окно не найдено/отозвано/истекло/нет сохранённого
  // токена/мастер-секрет не настроен/сбой self-destroyed-notes), НИКОГДА 500
  // на предсказуемых причинах отказа — 500 остаётся только на неожиданное
  // исключение.
  app.post("/automation-key-app/reissue-note", async (req: Request, res: Response) => {
    if (!requireOwnerInitData(req, res)) return;
    const windowId = typeof req.body?.windowId === "string" ? req.body.windowId : "";
    if (!windowId) {
      res.status(400).json({ error: "missing_window_id" });
      return;
    }
    try {
      const result = await reissueNoteForWindow(automationKeyConfig, automationWindowStoreAdapter, windowId);
      if (!result.ok) {
        res.status(400).json({ error: result.reason });
        return;
      }
      res.json({ ok: true, noteLink: result.noteLink });
    } catch (err) {
      console.error("automation-key-app/reissue-note error:", err);
      res.status(500).json({ error: "internal" });
    }
  });

  // Смена scope уже выпущенного окна (возможность 3 задачи «менеджер
  // ключей») — ТОТ ЖЕ переиспользуемый компонент-дерево «сервис → методы»,
  // что и экран генерации (docs/TZ_automation_key_method_catalog.md), шлёт
  // то же тело `{scopeTokens: [...]}`, backend строит `scope` тем же
  // `parseScopeTokens`/`normalizeScopeTokens`, что и /generate (одна
  // валидация на оба роута, не два расходящихся формата). Пустой выбор
  // отклоняется тем же fail-closed принципом, что и генерация — нельзя
  // случайно обнулить scope окна до "ничего не покрывает".
  app.post("/automation-key-app/update-scope", async (req: Request, res: Response) => {
    if (!requireOwnerInitData(req, res)) return;
    const windowId = typeof req.body?.windowId === "string" ? req.body.windowId : "";
    if (!windowId) {
      res.status(400).json({ error: "missing_window_id" });
      return;
    }
    const tokens = parseScopeTokens(req, res);
    if (!tokens) return; // 400 уже отправлен parseScopeTokens
    const scope = normalizeScopeTokens(tokens);
    try {
      const updated = await automationWindowStoreAdapter.updateScope(windowId, scope);
      if (!updated) {
        res.status(404).json({ error: "window_not_found" });
        return;
      }
      res.json({ ok: true, scope });
    } catch (err) {
      console.error("automation-key-app/update-scope error:", err);
      res.status(500).json({ error: "internal" });
    }
  });

  initDownloads(config.onboarding.publicBaseUrl);

  // ---- Temporary attachment links minted by gmail_get_download_url ----
  // Deliberately unauthenticated: the unguessable, expiring token in the path
  // IS the credential, and it authorises exactly one attachment. See downloads.ts.
  app.get("/dl/:token", async (req: Request, res: Response) => {
    const target = await resolveDownloadLink(String(req.params.token));
    if (!target) {
      res.status(404).type("text/plain").send("This download link is invalid or has expired.");
      return;
    }
    // Safety headers are set HERE — as soon as the token resolves, before any
    // outbound call — so they hold on every exit path below, not just the
    // happy one. All four depend only on `target`, never on the bytes.
    //
    // `Content-Disposition: attachment` already stops the browser from
    // rendering an HTML attachment when the link is opened directly. `nosniff`
    // closes what it does NOT cover: nothing stops a third-party page from
    // pulling this URL in as a SUBRESOURCE (<script src>, <object>, <embed>),
    // where the browser is free to sniff the bytes and execute them as the
    // type it guessed — on this server's own origin. Second line of defence
    // (an attacker needs the secret link first), but it is one header.
    res.setHeader("Content-Type", target.mimeType);
    res.setHeader("Content-Disposition", contentDisposition(target.name));
    res.setHeader("X-Content-Type-Options", "nosniff");
    // The link is a secret; keep proxies and shared caches out of it.
    res.setHeader("Cache-Control", "private, no-store");

    const user = (await userFromGoogleAccounts(config)) ?? config.users[0] ?? null;
    if (!user) {
      res.status(503).type("text/plain").send("No Google account is linked to this server any more.");
      return;
    }
    try {
      const g = buildUserClients(user).resolve(target.account);
      // Gmail has no streaming download — the API hands back base64 in JSON,
      // so the whole attachment necessarily passes through memory here.
      const att = await g.gmail.users.messages.attachments.get({
        userId: "me",
        messageId: target.messageId,
        id: target.attachmentId,
      });
      const buf = Buffer.from(att.data.data ?? "", "base64url");
      res.setHeader("Content-Length", String(buf.length));
      res.end(buf);
    } catch (err) {
      console.error("Attachment download error:", err);
      if (!res.headersSent) {
        res.status(502).type("text/plain").send("Could not fetch this attachment from Gmail.");
      } else {
        res.destroy();
      }
    }
  });

  // ---- Веб-хаб подтверждений, часть 2 backend (docs/TZ_consent_web_hub.md) ----
  // Смонтировано БЕЗУСЛОВНО (не гейтуется onboarding/DATABASE_URL на уровне
  // роутинга) — `consentHubGuard` сам отвечает 404, когда CONSENT_HUB_SECRET
  // не задан (ТЗ тест 8: "остальной сервис работает").

  // 1. GET /pending-consents — свои AWAITING_CONSENT манифесты.
  app.get("/pending-consents", async (req: Request, res: Response) => {
    if (!consentHubGuard(req, res)) return;
    if (!storeReady()) {
      res.json({ service: consentServerConfig.server, items: [] });
      return;
    }
    const rows = await listPendingConsents(consentServerConfig.server, Date.now());
    res.json({ service: consentServerConfig.server, items: rows.map(summarizePendingManifest) });
  });

  // 2. POST /pending-consents/decide — confirm идёт РОВНО тем же путём, что
  //    нажатие кнопки в Telegram (см. decideOwnConfirm выше); reject — тот же
  //    путь отказа, что и обычная человеческая негация.
  app.post("/pending-consents/decide", async (req: Request, res: Response) => {
    if (!consentHubGuard(req, res)) return;
    const manifestId = String(req.body?.manifestId ?? "");
    const decision = req.body?.decision;
    if (!manifestId || (decision !== "confirm" && decision !== "reject")) {
      res.status(400).json({ ok: false, error: "bad_request" });
      return;
    }
    if (!storeReady()) {
      res.status(503).json({ ok: false, error: "store_unavailable" });
      return;
    }
    const outcome =
      decision === "confirm"
        ? await decideOwnConfirm(config, manifestId)
        : await decideOwnReject(manifestId, String(req.body?.comment ?? ""));
    res.status(outcome.status).json(outcome.body);
  });

  // 3. GET /consent-hub-api/pending — агрегатор: свои + 4 соседа параллельно,
  //    недоступность одного НЕ роняет остальных (та же деградация, что у
  //    каталога методов мини-аппа).
  app.get("/consent-hub-api/pending", async (req: Request, res: Response) => {
    if (!consentHubGuard(req, res)) return;
    if (!consentHubSecret) return; // недостижимо (guard уже проверил), для TS
    const ownItems = storeReady()
      ? (await listPendingConsents(consentServerConfig.server, Date.now())).map(summarizePendingManifest)
      : [];
    const neighbors = Object.entries(externalCatalogUrls) as [string, string][];
    const results = await Promise.all(
      neighbors.map(([service, url]) => fetchNeighborPending(service, url, consentHubSecret!)),
    );
    const items: (PendingConsentItem & { service: string })[] = ownItems.map((it) => ({
      ...it,
      service: consentServerConfig.server,
    }));
    const unavailable: string[] = [];
    neighbors.forEach(([service], i) => {
      const r = results[i];
      if (r) items.push(...r.items.map((it) => ({ ...it, service: r.service })));
      else unavailable.push(service);
    });
    res.json({ items, unavailable });
  });

  // 4. POST /consent-hub-api/decide — прокси на нужный сервис по `service`
  //    (или само исполняет, если service === свой), добавляя секрет заголовком.
  app.post("/consent-hub-api/decide", async (req: Request, res: Response) => {
    if (!consentHubGuard(req, res)) return;
    const service = String(req.body?.service ?? "");
    const manifestId = String(req.body?.manifestId ?? "");
    const decision = req.body?.decision;
    if (!manifestId || (decision !== "confirm" && decision !== "reject")) {
      res.status(400).json({ ok: false, error: "bad_request" });
      return;
    }
    if (service === consentServerConfig.server) {
      if (!storeReady()) {
        res.status(503).json({ ok: false, error: "store_unavailable" });
        return;
      }
      const outcome =
        decision === "confirm"
          ? await decideOwnConfirm(config, manifestId)
          : await decideOwnReject(manifestId, String(req.body?.comment ?? ""));
      res.status(outcome.status).json(outcome.body);
      return;
    }
    const neighborUrl = (externalCatalogUrls as unknown as Record<string, string>)[service];
    if (!neighborUrl) {
      res.status(400).json({ ok: false, error: "unknown_service" });
      return;
    }
    const { status, json } = await proxyNeighborDecide(neighborUrl, consentHubSecret!, {
      manifestId,
      decision,
      comment: typeof req.body?.comment === "string" ? req.body.comment : undefined,
    });
    res.status(status).json(json);
  });

  // 5. GET /consent-hub/:secret — сама страница (только gmail-mcp, ТЗ). Тот
  //    же приём, что у /dashboard/:secret — секрет в пути, 403 на несовпадение
  //    (существование дашборд-роута и так очевидно из самого пути, в отличие
  //    от /pending-consents выше, которые обязаны отвечать 404).
  if (consentHubSecret) {
    app.get("/consent-hub/:secret", (req: Request, res: Response) => {
      if (!secretMatches(String(req.params.secret ?? ""), consentHubSecret)) {
        res.status(403).send("Forbidden");
        return;
      }
      res.type("html").send(renderConsentHubPage());
    });
    const hubBaseUrl = config.onboarding.publicBaseUrl || tgApprovalConfig.publicBaseUrl || "";
    // #119: секрет НЕ печатаем — тот же приём, что у logDashboardLocation.
    logConsentHubLocation(hubBaseUrl, `/consent-hub/${consentHubSecret}`, consentHubSecret);
  }

  let provider: GoogleFederatedProvider | null = null;

  if (config.onboarding.enabled) {
    const baseUrl = config.onboarding.publicBaseUrl!;
    provider = new GoogleFederatedProvider({
      googleClientId: config.onboarding.googleClientId!,
      googleClientSecret: config.onboarding.googleClientSecret!,
      baseUrl,
      relayUrl: config.onboarding.relayUrl,
      relaySecret: config.onboarding.relaySecret,
      ownerEmails: config.onboarding.ownerEmails,
    });

    const issuerUrl = new URL(baseUrl);
    const resourceServerUrl = new URL(`${baseUrl}/mcp`);

    app.use(mcpAuthRouter({
      provider,
      issuerUrl,
      resourceServerUrl,
      scopesSupported: ["sheets", "drive", "docs", "gmail", "calendar"],
    }));

    // Google (via the relay) redirects here after the user grants consent.
    app.get("/oauth/google/callback", async (req: Request, res: Response) => {
      const { code, state, error } = req.query as Record<string, string>;
      if (error) {
        res.status(400).send(`Google returned an error: ${error}. <a href="javascript:history.back()">Go back</a>`);
        return;
      }
      if (!code || !state) {
        res.status(400).send("Missing code or state.");
        return;
      }
      try {
        const result = await provider!.handleGoogleCallback(code, state);
        res.redirect(result.redirectUrl);
      } catch (err) {
        console.error("Google callback error:", err);
        res.status(400).send((err as Error).message);
      }
    });

    // ---- Account-management dashboard (guarded by an unguessable path secret) ----
    const dashSecret = config.onboarding.dashboardSecret;
    if (dashSecret) {
      const base = `/dashboard/${dashSecret}`;
      const guard = (req: Request, res: Response): boolean => {
        if (secretMatches(String(req.params.secret ?? ""), dashSecret)) return true;
        res.status(403).send("Forbidden");
        return false;
      };

      app.get("/dashboard/:secret", async (req: Request, res: Response) => {
        if (!guard(req, res)) return;
        const accounts = await listGoogleAccounts();
        const msg = typeof req.query.msg === "string" ? req.query.msg : undefined;
        res.type("html").send(renderDashboard(base, accounts, msg));
      });

      // Start "add another account" — bounce to Google via the relay.
      app.get("/dashboard/:secret/add", async (req: Request, res: Response) => {
        if (!guard(req, res)) return;
        try {
          const url = await provider!.startAddAccount(baseUrl);
          res.redirect(url);
        } catch (err) {
          console.error("add-account error:", err);
          res.status(400).send((err as Error).message);
        }
      });

      app.post("/dashboard/:secret/remove", async (req: Request, res: Response) => {
        if (!guard(req, res)) return;
        await removeGoogleAccount(String(req.body?.email ?? ""));
        res.redirect(`${base}?msg=removed`);
      });

      app.post("/dashboard/:secret/default", async (req: Request, res: Response) => {
        if (!guard(req, res)) return;
        await setDefaultAccount(String(req.body?.email ?? ""));
        res.redirect(`${base}?msg=default`);
      });

      app.post("/dashboard/:secret/rename", async (req: Request, res: Response) => {
        if (!guard(req, res)) return;
        const ok = await renameAccount(String(req.body?.email ?? ""), String(req.body?.label ?? ""));
        res.redirect(`${base}?msg=${ok ? "renamed" : "rename_failed"}`);
      });

      // #119: НЕ печатать сам секрет — он же пароль от дашборда, а логи
      // Railway видит каждый, у кого есть доступ к проекту.
      logDashboardLocation(baseUrl, base, dashSecret);
    }

    console.error(`Native MCP OAuth enabled — clients connect and authorize directly at ${baseUrl}/mcp`);
  }

  const bearerMiddleware = provider
    ? requireBearerAuth({
        verifier: provider,
        resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(`${config.onboarding.publicBaseUrl}/mcp`)),
      })
    : null;

  const handleMcp = async (req: Request, res: Response) => {
    let user: User | null = null;

    if (req.auth) {
      // Bearer token validated by requireBearerAuth; resolve the linked Google accounts.
      user = await userFromGoogleAccounts(config);
    } else if (!config.requireAuth) {
      // No auth is configured at all -- fail closed by default (package S5).
      if (!allowUnauthenticated()) {
        res.status(503).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: NO_AUTH_CONFIGURED_MESSAGE },
          id: null,
        });
        return;
      }
      user = config.users[0] ?? null;
    } else {
      const legacyUser = resolveLegacyUser(req, config);
      user = legacyUser
        ? await selectLegacyOrOnboardingUser(legacyUser, config.onboarding.enabled, () =>
            userFromGoogleAccounts(config),
          )
        : null;
    }

    if (!user) {
      res.status(401).json(JSONRPC_UNAUTHORIZED);
      return;
    }
    const server = buildMcpServer(user);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { transport.close(); server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("MCP error:", err);
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      }
    }
  };

  if (bearerMiddleware) {
    // Legacy ?key=/x-api-key links (from before native OAuth) keep working by
    // resolving directly against the static env-configured users. Everything
    // else — including requests with NO Authorization header at all — goes
    // through requireBearerAuth, so first-contact discovery requests get a
    // proper 401 + WWW-Authenticate pointing at the protected-resource metadata.
    app.post("/mcp", (req, res, next) => {
      if (resolveLegacyUser(req, config)) return next();
      return bearerMiddleware(req, res, next);
    }, handleMcp);
  } else {
    app.post("/mcp", handleMcp);
  }

  const methodNotAllowed = (_req: Request, res: Response) => {
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  if (tgApprovalConfig.enabled) {
    await registerWebhook(tgApprovalConfig);
    // `/automation_key` в автодополнении команд + постоянная кнопка меню
    // чата → мини-апп (docs/TZ_automation_key_note_delivery_and_buttons.md
    // раздел 2). Best-effort, как и registerWebhook — своих ошибок наружу
    // не бросает (см. doc-comment самой функции), поэтому без try/catch
    // здесь: сбой одного из двух вызовов внутри неё не должен и не может
    // остановить запуск сервера.
    await registerBotUiEntryPoints(tgApprovalConfig);
    // Чистка чата бота (Максим, 2026-08-05): снять кнопку у просроченных
    // PENDING, удалить сообщение у решённых после того же TTL — см.
    // runApprovalSweep's own doc-comment. Гейтуется webhookOwner ВНУТРИ
    // самой функции (то же defense-in-depth, что у registerWebhook) —
    // безопасно звать здесь безусловно. Раз в 5 минут — редко ловит
    // "истекло только что", но окно в 1 час TTL этого не требует.
    const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
    setInterval(() => {
      runApprovalSweep(tgApprovalConfig, tgApprovalStoreAdapter).catch((err) =>
        console.error("TG sweep: unhandled error", err),
      );
    }, SWEEP_INTERVAL_MS).unref();

    // Авто-исполнение — отдельный, более частый цикл (отзывчивость важнее
    // для UX: нажал кнопку, ждёшь секунды, а не минуты). Работает на КАЖДОМ
    // сервере без гейта webhookOwner — см. runAutoExecutePoller's doc-comment.
    const AUTO_EXECUTE_INTERVAL_MS = 10 * 1000;
    setInterval(() => {
      runAutoExecutePoller(config).catch((err) =>
        console.error("TG auto-execute poller: unhandled error", err),
      );
    }, AUTO_EXECUTE_INTERVAL_MS).unref();
  }

  await new Promise<void>((resolve) => {
    app.listen(config.port, () => {
      console.error(`MCP listening on :${config.port}  auth=${config.requireAuth ? "on" : "OFF"}  instance=${randomUUID().slice(0, 8)}`);
      if (!config.requireAuth) {
        if (allowUnauthenticated()) {
          console.warn(
            "WARNING: MCP_ALLOW_UNAUTHENTICATED=true — /mcp is serving EVERY request with ZERO " +
              "authentication, including the 4 consent-gated send tools. Local development ONLY " +
              "— never deploy this way.",
          );
        } else {
          console.error(
            "No MCP_AUTH_TOKEN and no onboarding OAuth configured — /mcp will refuse every " +
              "request with 503 (fail-closed, package S5). Set MCP_AUTH_TOKEN or enable onboarding " +
              "to serve requests, or MCP_ALLOW_UNAUTHENTICATED=true for local development only.",
          );
        }
      }
      resolve();
    });
  });
}
