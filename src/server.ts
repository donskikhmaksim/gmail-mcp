import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { User } from "./config.js";
import { loadConsentGateConfig, loadTgApprovalConfig } from "./config.js";
import { buildUserClients, registerAccountTools } from "./accounts.js";
import { registerGmailTools } from "./tools/gmail.js";
import type { ConsentStore, ConsentConfig, TgApprovalGate } from "./consent.js";
import type { TgApprovalStore } from "./tg_approval.js";
import { createTgApprovalGate } from "./tg_approval.js";
import {
  storeReady,
  addSnooze,
  addScheduledSend,
  listScheduledSends,
  countScheduledSends,
  cancelScheduledSend,
  createManifest,
  getManifest,
  consumeManifest,
  invalidateManifest,
  markTgNotified,
  appendConsentAudit,
  updateConsentAuditOutcome,
  listConsentAudit,
  countConsentAudit,
  createTgApproval,
  getTgApproval,
  consumeTgDecision,
  consumeTgDecisionAnyServer,
  claimExpiredPendingApprovals,
  claimStaleDecidedApprovals,
} from "./store.js";

/** Adapts store.ts's module functions to the shape gmail.ts's tools expect.
 * Exported (2026-08-05, auto-execute package) so `http.ts`'s poller can pass
 * the SAME real adapter into `AutoExecutorCtx.store` for gmail_snooze/
 * gmail_schedule_send's auto-executors — one adapter, both paths, instead of
 * a second module-level copy hardwired inside `tools/gmail.ts`. */
export const pgStoreAdapter = {
  addSnooze: (args: { userToken: string | null; accountName: string; messageId: string; subject?: string; unsnoozeAt: Date }) =>
    addSnooze({
      userToken: args.userToken,
      accountLabel: args.accountName,
      messageId: args.messageId,
      subject: args.subject,
      wakeAt: args.unsnoozeAt,
    }),
  addScheduledSend: (args: {
    userToken: string | null;
    accountName: string;
    rawMessage: string;
    toPreview: string;
    subjectPreview: string;
    sendAt: Date;
  }) =>
    addScheduledSend({
      userToken: args.userToken,
      accountLabel: args.accountName,
      rawMessage: args.rawMessage,
      toPreview: args.toPreview,
      subjectPreview: args.subjectPreview,
      sendAt: args.sendAt,
    }),
  listScheduledSends: (accountName: string, status?: string) =>
    listScheduledSends(accountName, (status as import("./store.js").ScheduledSendStatus) ?? "pending"),
  countScheduledSends: (accountName: string, status: string) => countScheduledSends(accountName, status),
  cancelScheduledSend: (id: number, accountName: string) => cancelScheduledSend(id, accountName),
};

/**
 * store.ts's consent-gate functions (package A1), typed against consent.ts's
 * `ConsentStore` here — signature-for-signature by construction, but the
 * `: ConsentStore` annotation means a drift fails THIS build, not A3's.
 */
export const consentStoreAdapter: ConsentStore = {
  createManifest,
  getManifest,
  consumeManifest,
  invalidateManifest,
  markTgNotified,
  appendConsentAudit,
  updateConsentAuditOutcome,
};

/**
 * Read-only adapter for package A4's `gmail_consent_audit` — separate from
 * `consentStoreAdapter` above (the plan/execute gate contract from A2) since
 * this is a different, purely-reading surface: "разбор инцидента без ssh"
 * (limits-audit.md §11). gmail.ts's `AuditStore` type mirrors this
 * structurally, same convention as `PgStore`/`pgStoreAdapter` above.
 */
export const auditStoreAdapter = { listConsentAudit, countConsentAudit };

/** This server's identity ($self) in the shared consent_manifests/consent_audit
 * tables, plus the gate's TTL/anti-doublet/batch-cap knobs — env-driven, see
 * `loadConsentGateConfig` in config.ts. `now` is left unset here (real
 * `Date.now`); consent.ts's `now` injection exists for OFFLINE UNIT TESTS only. */
const consentGateEnv = loadConsentGateConfig();
export const consentServerConfig: ConsentConfig = {
  server: consentGateEnv.server,
  consentTtlMs: consentGateEnv.consentTtlMs,
  minConsentGapMs: consentGateEnv.minConsentGapMs,
  sendBatchMax: consentGateEnv.sendBatchMax,
};

/**
 * Optional Telegram-approval layer (plan-tg-approval.md). Loaded once at
 * module scope, same as `consentGateEnv`/`consentServerConfig` above — this
 * throws loudly at process start if TG_APPROVAL_ENABLED=true but misconfigured
 * (package P0), rather than silently degrading. Exported so http.ts can mount
 * `/tg/webhook` and call `registerWebhook()` at startup without re-deriving it.
 */
export const tgApprovalConfig = loadTgApprovalConfig(consentGateEnv.server);

/** store.ts's tg_approvals functions (package P1), typed against
 * tg_approval.ts's `TgApprovalStore` here — signature-for-signature by
 * construction, same discipline as `consentStoreAdapter` above. */
export const tgApprovalStoreAdapter: TgApprovalStore = {
  createTgApproval,
  getTgApproval,
  consumeTgDecision,
  consumeTgDecisionAnyServer,
  claimExpiredPendingApprovals,
  claimStaleDecidedApprovals,
};

/**
 * The gate object wired into every gated tool's `requireConsent({ tg })`.
 * Always constructed (even when TG_APPROVAL_ENABLED=false) so call sites never
 * branch on its presence — `enabledFor()` is simply false for every tool in
 * that case, which is the whole compatibility invariant (plan §0): a fork
 * without a configured Telegram bot behaves byte-for-byte as before this
 * feature existed, because this gate never calls into `tgApprovalStoreAdapter`
 * unless `enabledFor(tool)` says so, and that itself is always false when
 * disabled — regardless of whether Postgres is configured at all.
 */
export const tgApprovalGate: TgApprovalGate = createTgApprovalGate(tgApprovalConfig, tgApprovalStoreAdapter);

export function buildMcpServer(user: User): McpServer {
  const clients = buildUserClients(user);
  const accountsHint = clients.multi
    ? `Multiple Google accounts available: ${clients.names.join(", ")} (default: ${clients.defaultName}). Pass \`account\` to select.`
    : `One Google account ("${clients.defaultName}") is configured.`;

  const server = new McpServer(
    { name: "gmail-mcp", version: "1.0.0" },
    { instructions: "Tools to manage Gmail: read, search, send, reply, archive, delete, labels. " + accountsHint },
  );
  // Package A3 landed: `GmailSnoozeContext` (gmail.ts) now declares
  // `consentStore`/`consentCfg` and all 15 gated write tools wire `requireConsent`
  // through them. Honest degradation (gate.md §3.5): `consentStore` is null
  // exactly when `store` is — without Postgres there's nowhere to persist a
  // manifest, so the gated tools refuse outright rather than send unconfirmed.
  const snoozeCtx = {
    store: storeReady() ? pgStoreAdapter : null,
    userToken: user.token ?? null,
    consentStore: storeReady() ? consentStoreAdapter : null,
    consentCfg: consentServerConfig,
    auditStore: storeReady() ? auditStoreAdapter : null,
    tg: tgApprovalGate,
  };
  registerAccountTools(server, clients);
  registerGmailTools(server, clients, snoozeCtx);
  return server;
}
