/**
 * Short-lived links for downloading one attachment.
 *
 * Gmail has nothing like a presigned URL: `users.messages.attachments.get` is
 * the only way to reach the bytes, it always needs an OAuth token, and it
 * answers with base64 inside JSON — the API has no media-download protocol at
 * all. Handing a client that OAuth token would give it the whole mailbox.
 *
 * So this server mints its own capability URL instead: an unguessable token
 * that expires, stored server-side, redeemed at `GET /dl/<token>` where the
 * server fetches the attachment and writes the bytes out. The link is the
 * credential — anyone holding it can fetch that one attachment until it
 * expires, which is the presigned-URL trade-off, scoped to a single file.
 *
 * Tokens live in Postgres when one is configured, and in memory otherwise, so
 * links survive a restart wherever a database exists.
 */
import { randomBytes } from "node:crypto";
import {
  storeReady,
  saveDownloadToken,
  getDownloadToken,
  type DownloadTarget,
} from "./store.js";

export type { DownloadTarget };

/** Public base URL of this server; set at startup. Links are impossible without it. */
let baseUrl: string | undefined;

/** Fallback store for deployments running without a database. */
const memory = new Map<string, DownloadTarget>();

// Attachment links are shorter-lived than Drive's: they tend to be pasted into
// a chat, and a mailbox is a more sensitive place to leak a capability into.
export const DEFAULT_TTL_MINUTES = 30;
export const MAX_TTL_MINUTES = 12 * 60;

export function initDownloads(publicBaseUrl: string | undefined): void {
  baseUrl = publicBaseUrl?.replace(/\/+$/, "");
}

/** False when the server does not know its own public URL — no link can be built. */
export function downloadsAvailable(): boolean {
  return !!baseUrl;
}

/**
 * Mints a link for one attachment. `ttlMinutes` is clamped to MAX_TTL_MINUTES
 * so a caller cannot ask for a link that effectively never expires.
 */
export async function issueDownloadLink(
  target: Omit<DownloadTarget, "expiresAt">,
  ttlMinutes = DEFAULT_TTL_MINUTES,
): Promise<{ url: string; expiresAt: string }> {
  if (!baseUrl) {
    throw new Error(
      "This server does not know its public URL, so it cannot hand out download links. " +
        "Set PUBLIC_BASE_URL (Railway sets RAILWAY_PUBLIC_DOMAIN automatically once public networking is on).",
    );
  }
  const ttl = Math.min(Math.max(ttlMinutes, 1), MAX_TTL_MINUTES);
  const token = randomBytes(32).toString("base64url");
  const record: DownloadTarget = { ...target, expiresAt: Date.now() + ttl * 60_000 };

  if (storeReady()) {
    await saveDownloadToken(token, record);
  } else {
    for (const [k, v] of memory) if (v.expiresAt < Date.now()) memory.delete(k);
    memory.set(token, record);
  }
  return { url: `${baseUrl}/dl/${token}`, expiresAt: new Date(record.expiresAt).toISOString() };
}

/** Looks up a token. Returns null when unknown or expired. Links stay usable
 *  until they expire — one-shot links would break ordinary retries. */
export async function resolveDownloadLink(token: string): Promise<DownloadTarget | null> {
  if (storeReady()) return getDownloadToken(token);
  const rec = memory.get(token);
  if (!rec) return null;
  if (rec.expiresAt < Date.now()) {
    memory.delete(token);
    return null;
  }
  return rec;
}
