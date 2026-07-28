import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { User } from "./config.js";
import { buildUserClients, registerAccountTools } from "./accounts.js";
import { registerGmailTools, type GmailSnoozeContext } from "./tools/gmail.js";
import {
  storeReady,
  addSnooze,
  addScheduledSend,
  listScheduledSends,
  cancelScheduledSend,
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
  listScheduledSends: (accountName: string) => listScheduledSends(accountName),
  cancelScheduledSend: (id: number, accountName: string) => cancelScheduledSend(id, accountName),
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
  const snoozeCtx: GmailSnoozeContext = {
    store: storeReady() ? pgStoreAdapter : null,
    userToken: user.token ?? null,
  };
  registerAccountTools(server, clients);
  registerGmailTools(server, clients, snoozeCtx);
  return server;
}
