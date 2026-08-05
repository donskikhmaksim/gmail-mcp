import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { User } from "./config.js";
import { loadConsentGateConfig } from "./config.js";
import { buildUserClients, registerAccountTools } from "./accounts.js";
import { registerGmailTools } from "./tools/gmail.js";
import type { ConsentStore, ConsentConfig } from "./consent.js";
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
  appendConsentAudit,
  updateConsentAuditOutcome,
} from "./store.js";

/** Adapts store.ts's module functions to the shape gmail.ts's tools expect. */
const pgStoreAdapter = {
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
  appendConsentAudit,
  updateConsentAuditOutcome,
};

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

export function buildMcpServer(user: User): McpServer {
  const clients = buildUserClients(user);
  const accountsHint = clients.multi
    ? `Multiple Google accounts available: ${clients.names.join(", ")} (default: ${clients.defaultName}). Pass \`account\` to select.`
    : `One Google account ("${clients.defaultName}") is configured.`;

  const server = new McpServer(
    { name: "gmail-mcp", version: "1.0.0" },
    { instructions: "Tools to manage Gmail: read, search, send, reply, archive, delete, labels. " + accountsHint },
  );
  // No explicit `: GmailSnoozeContext` annotation here on purpose: the two
  // consent-gate fields below aren't declared on that type yet (A3 adds them
  // in gmail.ts when it wires `requireConsent` into the 4 send tools). TS
  // only excess-property-checks object LITERALS assigned to an annotated
  // type; passing this inferred (wider) object as a plain argument to
  // `registerGmailTools` below is fine either way, and needs no change here
  // once A3 lands. Honest degradation (gate.md §3.5): `consentStore` is null
  // exactly when `store` is — without Postgres there's nowhere to persist a
  // manifest, so the gated tools must refuse outright, never send unconfirmed.
  const snoozeCtx = {
    store: storeReady() ? pgStoreAdapter : null,
    userToken: user.token ?? null,
    consentStore: storeReady() ? consentStoreAdapter : null,
    consentCfg: consentServerConfig,
  };
  registerAccountTools(server, clients);
  registerGmailTools(server, clients, snoozeCtx);
  return server;
}
