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

/** Builds the User from ALL Google accounts linked to this instance via onboarding. */
async function userFromGoogleAccounts(config: Config): Promise<User | null> {
  const accounts = await getGoogleAccounts();
  if (!accounts.length) return null;
  const clientId = config.onboarding.googleClientId!;
  const clientSecret = config.onboarding.googleClientSecret!;
  const mapped: Account[] = accounts.map((a) => ({
    name: a.label,
    auth: { mode: "oauth", clientId, clientSecret, refreshToken: a.refreshToken },
  }));
  const def = accounts.find((a) => a.isDefault) ?? accounts[0];
  return {
    name: def.email,
    accounts: mapped,
    defaultAccount: def.label,
  };
}

/** Constant-time compare for the dashboard path secret. */
function secretMatches(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

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

  let provider: GoogleFederatedProvider | null = null;

  if (config.onboarding.enabled) {
    const baseUrl = config.onboarding.publicBaseUrl!;
    provider = new GoogleFederatedProvider({
      googleClientId: config.onboarding.googleClientId!,
      googleClientSecret: config.onboarding.googleClientSecret!,
      baseUrl,
      relayUrl: config.onboarding.relayUrl,
      relaySecret: config.onboarding.relaySecret,
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
      user = config.users[0] ?? null;
    } else {
      user = resolveLegacyUser(req, config);
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
      if (!config.requireAuth && !config.onboarding.enabled) console.error("WARNING: no MCP_AUTH_TOKEN — endpoint is PUBLIC");
      resolve();
    });
  });
}
