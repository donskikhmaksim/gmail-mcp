import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { User } from "./config.js";
import { buildUserClients, registerAccountTools } from "./accounts.js";
import { registerGmailTools } from "./tools/gmail.js";

export function buildMcpServer(user: User): McpServer {
  const clients = buildUserClients(user);
  const accountsHint = clients.multi
    ? `Multiple Google accounts available: ${clients.names.join(", ")} (default: ${clients.defaultName}). Pass \`account\` to select.`
    : `One Google account ("${clients.defaultName}") is configured.`;

  const server = new McpServer(
    { name: "gmail-mcp", version: "1.0.0" },
    { instructions: "Tools to manage Gmail: read, search, send, reply, archive, delete, labels. " + accountsHint },
  );
  registerAccountTools(server, clients);
  registerGmailTools(server, clients, { store: null, userToken: user.token ?? null });
  return server;
}
