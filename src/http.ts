import express, { type Request, type Response } from "express";
import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Config, User } from "./config.js";
import { buildMcpServer } from "./server.js";

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

function extractToken(req: Request): string {
  const header = req.header("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match?.[1]) return match[1];
  const apiKey = req.header("x-api-key");
  if (apiKey) return apiKey;
  const q = req.query?.key ?? req.query?.token;
  if (typeof q === "string") return q;
  return "";
}

function resolveUser(req: Request, config: Config): User | null {
  if (!config.requireAuth) return config.users[0] ?? null;
  const provided = extractToken(req);
  if (!provided) return null;
  for (const user of config.users) {
    if (user.token && tokensEqual(provided, user.token)) return user;
  }
  return null;
}

export async function startHttpServer(config: Config): Promise<void> {
  const app = express();
  app.use(express.json({ limit: "10mb" }));

  app.get("/", (_req, res) => {
    res.json({ status: "ok", endpoint: "/mcp" });
  });
  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  const handleMcp = async (req: Request, res: Response) => {
    const user = resolveUser(req, config);
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

  app.post("/mcp", handleMcp);
  const methodNotAllowed = (_req: Request, res: Response) => {
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  await new Promise<void>((resolve) => {
    app.listen(config.port, () => {
      console.error(`MCP listening on :${config.port}  auth=${config.requireAuth ? "on" : "OFF"}  instance=${randomUUID().slice(0, 8)}`);
      if (!config.requireAuth) console.error("WARNING: no MCP_AUTH_TOKEN — endpoint is PUBLIC");
      resolve();
    });
  });
}
