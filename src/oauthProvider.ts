/**
 * Google account-linking helper for the browser dashboard.
 *
 * Design B (single-tenant): this server does NOT run a native MCP OAuth
 * authorization server anymore. Its only job here is the "add another of MY
 * Google accounts" flow driven from /dashboard/<secret>: bounce the browser to
 * Google, then on the callback exchange the code, verify the email, and store
 * the encrypted refresh token in Postgres (google_accounts). /mcp itself is
 * gated by a single static secret (see http.ts), not by tokens minted here.
 */
import { randomBytes, createHmac } from "node:crypto";
import { google } from "googleapis";
import * as store from "./store.js";

const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/spreadsheets",
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/documents",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/calendar",
  "openid",
  "email",
];

export interface FederatedProviderOptions {
  googleClientId: string;
  googleClientSecret: string;
  baseUrl: string; // e.g. https://gmail-mcp-production.up.railway.app (no trailing slash)
  /** When set, Google redirects to `${relayUrl}/relay/callback` instead of our own. */
  relayUrl?: string;
  /** Shared HMAC secret the relay uses to verify the `state` we sign. */
  relaySecret?: string;
}

function b64url(input: Buffer): string {
  return input.toString("base64url");
}

/** Outcome of the Google redirect round-trip (dashboard add-account flow). */
export interface GoogleCallbackResult {
  /** Where to send the browser next (back to the dashboard). */
  redirectUrl: string;
  /** The account that was just linked. */
  account: store.GoogleAccountMeta;
}

export class GoogleFederatedProvider {
  private opts: FederatedProviderOptions;

  constructor(opts: FederatedProviderOptions) {
    this.opts = opts;
  }

  /** redirect_uri sent to Google: the shared relay when configured, else our own. */
  private googleRedirectUri(): string {
    return this.opts.relayUrl
      ? `${this.opts.relayUrl}/relay/callback`
      : `${this.opts.baseUrl}/oauth/google/callback`;
  }

  private googleClient(): InstanceType<typeof google.auth.OAuth2> {
    return new google.auth.OAuth2(
      this.opts.googleClientId,
      this.opts.googleClientSecret,
      this.googleRedirectUri(),
    );
  }

  /**
   * The `state` Google echoes back. With a relay it must carry our return URL so
   * the relay knows where to forward, HMAC-signed so the relay isn't an open
   * redirector. Without a relay, plain nonce (Google returns to us directly).
   */
  private buildState(nonce: string): string {
    if (!this.opts.relayUrl || !this.opts.relaySecret) return nonce;
    const payload = b64url(Buffer.from(JSON.stringify({ r: this.opts.baseUrl, n: nonce })));
    const sig = createHmac("sha256", this.opts.relaySecret).update(payload).digest("base64url");
    return `${payload}.${sig}`;
  }

  private buildGoogleAuthUrl(nonce: string): string {
    return this.googleClient().generateAuthUrl({
      access_type: "offline",
      // Adding an account always forces the chooser + consent: the chooser is the
      // only way to reach an account we have not seen, and `consent` guarantees
      // the refresh token that account still needs.
      prompt: "select_account consent",
      scope: GOOGLE_SCOPES,
      state: this.buildState(nonce),
    });
  }

  /**
   * Dashboard "add another account" flow. Stashes the return URL keyed by a
   * nonce, then returns the Google consent URL to redirect the browser to.
   */
  async startAddAccount(returnTo: string): Promise<string> {
    const nonce = b64url(randomBytes(24));
    await store.savePendingAuth({ nonce, redirectUri: returnTo });
    return this.buildGoogleAuthUrl(nonce);
  }

  /** Google (via the relay) redirects to /oauth/google/callback -> here. */
  async handleGoogleCallback(code: string, nonce: string): Promise<GoogleCallbackResult> {
    const pending = await store.takePendingAuth(nonce);
    if (!pending) throw new Error("Expired or unknown authorization request. Please try connecting again.");

    const oauth = this.googleClient();
    const { tokens } = await oauth.getToken(code);
    oauth.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: "v2", auth: oauth });
    const { data } = await oauth2.userinfo.get();
    const email = data.email ?? "unknown";

    // Google only issues a refresh token on the first grant. Reuse the stored
    // token for this email if none came back: userinfo above came from a token
    // Google just minted, so the account is verified.
    let refreshToken = tokens.refresh_token ?? undefined;
    if (!refreshToken) refreshToken = await store.getRefreshTokenByEmail(email);
    if (!refreshToken) {
      throw new Error(
        `Google did not return a refresh token for ${email} and none is stored. ` +
          "Revoke this app's access at https://myaccount.google.com/permissions and try again.",
      );
    }
    const account = await store.addGoogleAccount(email, refreshToken);
    return { redirectUrl: pending.redirectUri, account };
  }
}
