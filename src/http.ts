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
} from "./store.js";
import { renderDashboard } from "./dashboard.js";
import { initDownloads, resolveDownloadLink } from "./downloads.js";
import { buildUserClients } from "./accounts.js";

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
      res.setHeader("Content-Type", target.mimeType);
      res.setHeader("Content-Disposition", contentDisposition(target.name));
      res.setHeader("Content-Length", String(buf.length));
      // The link is a secret; keep proxies and shared caches out of it.
      res.setHeader("Cache-Control", "private, no-store");
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

      console.error(`Account dashboard at ${baseUrl}${base}`);
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
