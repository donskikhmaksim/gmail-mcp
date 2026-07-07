/**
 * MCP OAuth 2.1 authorization server that federates login to Google.
 *
 * This server issues its OWN opaque access/refresh tokens to MCP clients
 * (Claude, etc). The Google refresh token never leaves this server — it is
 * fetched once during the /oauth/google/callback round trip and stored
 * server-side (single-tenant: one Google account per deployed instance).
 */
import { randomUUID, randomBytes } from "node:crypto";
import type { Response } from "express";
import { google } from "googleapis";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
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
  baseUrl: string; // e.g. https://sheets-mcp-production.up.railway.app (no trailing slash)
}

function b64url(input: Buffer): string {
  return input.toString("base64url");
}

class PgClientsStore implements OAuthRegisteredClientsStore {
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    const c = await store.getClient(clientId);
    return c as unknown as OAuthClientInformationFull | undefined;
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ): Promise<OAuthClientInformationFull> {
    const isPublicClient = client.token_endpoint_auth_method === "none";
    const client_id = randomUUID();
    const client_secret = isPublicClient ? undefined : randomBytes(32).toString("hex");
    const client_id_issued_at = Math.floor(Date.now() / 1000);
    // No expiry: registered clients (Claude) should stay valid indefinitely.
    const client_secret_expires_at = 0;
    const full = { ...client, client_id, client_secret, client_id_issued_at, client_secret_expires_at } as OAuthClientInformationFull;
    await store.saveClient(full as unknown as store.StoredClient);
    return full;
  }
}

export class GoogleFederatedProvider implements OAuthServerProvider {
  readonly clientsStore = new PgClientsStore();
  readonly skipLocalPkceValidation = false;

  private opts: FederatedProviderOptions;

  constructor(opts: FederatedProviderOptions) {
    this.opts = opts;
  }

  private googleClient(): InstanceType<typeof google.auth.OAuth2> {
    return new google.auth.OAuth2(
      this.opts.googleClientId,
      this.opts.googleClientSecret,
      `${this.opts.baseUrl}/oauth/google/callback`,
    );
  }

  /** Step 1: MCP client hits /authorize on us. We stash the request and bounce to Google. */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const nonce = b64url(randomBytes(24));
    await store.savePendingAuth({
      nonce,
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      scopes: params.scopes ?? GOOGLE_SCOPES,
      state: params.state,
      resource: params.resource?.toString(),
    });

    const oauth = this.googleClient();
    const url = oauth.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: GOOGLE_SCOPES,
      state: nonce,
    });
    res.redirect(url);
  }

  /** Step 2: Google redirects to /oauth/google/callback (wired in http.ts), which calls this. */
  async handleGoogleCallback(code: string, nonce: string): Promise<{ redirectUrl: string }> {
    const pending = await store.takePendingAuth(nonce);
    if (!pending) throw new Error("Expired or unknown authorization request. Please try connecting again.");

    const oauth = this.googleClient();
    const { tokens } = await oauth.getToken(code);
    if (!tokens.refresh_token) {
      throw new Error(
        "Google did not return a refresh token. Revoke this app's access at https://myaccount.google.com/permissions and try again.",
      );
    }
    oauth.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: "v2", auth: oauth });
    const { data } = await oauth2.userinfo.get();
    await store.setGoogleAccount(data.email ?? "unknown", tokens.refresh_token);

    const mcpCode = await store.issueCode({
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      scopes: pending.scopes,
      resource: pending.resource,
    });

    const redirect = new URL(pending.redirectUri);
    redirect.searchParams.set("code", mcpCode);
    if (pending.state) redirect.searchParams.set("state", pending.state);
    return { redirectUrl: redirect.toString() };
  }

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const challenge = await store.peekCodeChallenge(authorizationCode);
    if (!challenge) throw new Error("Invalid or expired authorization code");
    return challenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const issued = await store.consumeCode(authorizationCode);
    if (!issued) throw new Error("Invalid, expired, or already-used authorization code");
    if (issued.clientId !== client.client_id) throw new Error("Authorization code was issued to a different client");
    if (redirectUri && issued.redirectUri !== redirectUri) throw new Error("redirect_uri mismatch");

    const tokens = await store.issueTokens(client.client_id, issued.scopes, resource?.toString() ?? issued.resource);
    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      token_type: "Bearer",
      expires_in: tokens.expiresAt - Math.floor(Date.now() / 1000),
      scope: tokens.scopes.join(" "),
    };
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const existing = await store.findByRefreshToken(refreshToken);
    if (!existing) throw new Error("Invalid refresh token");
    if (existing.clientId !== client.client_id) throw new Error("Refresh token was issued to a different client");

    await store.deleteTokenByRefresh(refreshToken);
    const tokens = await store.issueTokens(client.client_id, scopes ?? existing.scopes, resource?.toString() ?? existing.resource);
    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      token_type: "Bearer",
      expires_in: tokens.expiresAt - Math.floor(Date.now() / 1000),
      scope: tokens.scopes.join(" "),
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const issued = await store.findByAccessToken(token);
    if (!issued) throw new Error("Invalid access token");
    if (issued.expiresAt < Math.floor(Date.now() / 1000)) throw new Error("Access token expired");
    return {
      token,
      clientId: issued.clientId,
      scopes: issued.scopes,
      expiresAt: issued.expiresAt,
      resource: issued.resource ? new URL(issued.resource) : undefined,
    };
  }

  async revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    await store.deleteTokenByAccess(request.token);
    await store.deleteTokenByRefresh(request.token);
  }
}
