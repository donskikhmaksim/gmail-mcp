/**
 * Per-user account resolution. A user can have several named Google accounts;
 * each tool call picks one via the optional `account` argument.
 */
import { z } from "zod";
import { createGoogleClients } from "./google.js";
export function buildUserClients(user) {
    const map = new Map();
    const queries = new Map();
    for (const acc of user.accounts) {
        map.set(acc.name, createGoogleClients(acc.auth));
        queries.set(acc.name, acc.gmailQuery ?? "");
    }
    const names = user.accounts.map((a) => a.name);
    const keyFor = (name) => name && name.trim() ? name.trim() : user.defaultAccount;
    return {
        names,
        defaultName: user.defaultAccount,
        multi: names.length > 1,
        resolve(name) {
            const key = keyFor(name);
            const clients = map.get(key);
            if (!clients) {
                throw new Error(`Unknown account "${key}". Available accounts: ${names.join(", ")}.`);
            }
            return clients;
        },
        baseGmailQuery(name) {
            return queries.get(keyFor(name)) ?? "";
        },
    };
}
/** A reusable zod field describing the `account` selector for a user. */
export function accountField(clients) {
    const desc = clients.multi
        ? `Which Google account to act on: ${clients.names.join(", ")}. ` +
            `Defaults to "${clients.defaultName}" if omitted.`
        : `Google account to use (only "${clients.defaultName}" is configured).`;
    return z.string().optional().describe(desc);
}
