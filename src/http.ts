import express, { type Request, type Response } from "express";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
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

/** Pulls the presented bearer from Authorization / x-api-key / ?key= / ?token=. */
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

/**
 * Builds the owner User from ALL Google accounts the owner has linked through the
 * browser dashboard (Postgres google_accounts). Single-tenant: there is exactly
 * one owner, so this returns every stored account — no per-token selection.
 * Returns null when onboarding/store is inactive or no accounts are linked yet.
 */
async function ownerFromStore(config: Config): Promise<User | null> {
  if (!config.onboarding.enabled) return null;
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
  // Fail CLOSED: an HTTP deployment without a gate would expose the owner's
  // Google accounts to the whole internet. Refuse to start rather than run open.
  if (!config.mcpSecret) {
    throw new Error(
      "Refusing to start in HTTP mode without a gate: set MCP_SECRET (or the legacy " +
        "MCP_AUTH_TOKEN) to a long random string. Every POST /mcp must send it as " +
        "`Authorization: Bearer <secret>`.",
    );
  }
  const mcpSecret = config.mcpSecret;

  const app = express();
  // Railway (and most PaaS) terminate TLS behind a reverse proxy; trust its
  // X-Forwarded-For so per-IP logic keys on the real client, not the proxy.
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

    // Google (via the relay) redirects here after the owner grants consent for
    // an account added from the dashboard.
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
  }

  const handleMcp = async (req: Request, res: Response) => {
    // Single static gate: every /mcp request must present the shared secret.
    const provided = extractLegacyToken(req);
    if (!provided || !tokensEqual(provided, mcpSecret)) {
      res.status(401).json(JSONRPC_UNAUTHORIZED);
      return;
    }

    // Serve the owner's accounts: browser-linked ones (Postgres) if any, else the
    // env-configured owner.
    const owner = (await ownerFromStore(config)) ?? config.owner;

    const server = buildMcpServer(owner);
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

  app.post("/mcp", handleMcp);

  const methodNotAllowed = (_req: Request, res: Response) => {
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  await new Promise<void>((resolve) => {
    app.listen(config.port, () => {
      console.error(`MCP listening on :${config.port}  auth=on (static secret)  instance=${randomUUID().slice(0, 8)}`);
      resolve();
    });
  });
}
