/**
 * Per-user account resolution. A user can have several named Google accounts;
 * each tool call picks one via the optional `account` argument.
 */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { User } from "./config.js";
import { createGoogleClients, type GoogleClients } from "./google.js";

export interface UserClients {
  names: string[];
  defaultName: string;
  multi: boolean;
  /** Returns clients for the named account, or the default when name is omitted. */
  resolve(name?: string): GoogleClients;
  /** Base Gmail search fragment configured for the named account (or ""). */
  baseGmailQuery(name?: string): string;
}

export function buildUserClients(user: User): UserClients {
  const map = new Map<string, GoogleClients>();
  const queries = new Map<string, string>();
  for (const acc of user.accounts) {
    map.set(acc.name, createGoogleClients(acc.auth));
    queries.set(acc.name, acc.gmailQuery ?? "");
  }
  const names = user.accounts.map((a) => a.name);
  const keyFor = (name?: string) =>
    name && name.trim() ? name.trim() : user.defaultAccount;
  return {
    names,
    defaultName: user.defaultAccount,
    multi: names.length > 1,
    resolve(name?: string): GoogleClients {
      const key = keyFor(name);
      const clients = map.get(key);
      if (!clients) {
        throw new Error(
          `Unknown account "${key}". Available accounts: ${names.join(", ")}.`,
        );
      }
      return clients;
    },
    baseGmailQuery(name?: string): string {
      return queries.get(keyFor(name)) ?? "";
    },
  };
}

/** A reusable zod field describing the `account` selector for a user. */
export function accountField(clients: UserClients) {
  const desc = clients.multi
    ? `Which Google account to act on: ${clients.names.join(", ")}. ` +
      `Defaults to "${clients.defaultName}" if omitted.`
    : `Google account to use (only "${clients.defaultName}" is configured).`;
  return z.string().optional().describe(desc);
}

/**
 * Registers a read-only `list_accounts` tool so the model (and user) can see
 * which Google accounts are available and which is the default before choosing
 * an `account` for other tools.
 */
export function registerAccountTools(server: McpServer, clients: UserClients): void {
  server.registerTool(
    "list_accounts",
    {
      description:
        "List the Google accounts available to this server. Use the returned name " +
        "as the `account` argument on other tools to act on a specific account.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const lines = clients.names.map(
        (n) => `- ${n}${n === clients.defaultName ? " (default)" : ""}`,
      );
      return {
        content: [
          {
            type: "text",
            text:
              (lines.length ? lines.join("\n") : "No accounts configured.") +
              `\n\nPass \`account\` with one of these names to pick an account; omitted uses "${clients.defaultName}".`,
          },
        ],
      };
    },
  );
}
