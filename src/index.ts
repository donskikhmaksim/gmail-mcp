import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { buildMcpServer } from "./server.js";
import { startHttpServer } from "./http.js";
import { initStore, ensureSchema } from "./store.js";

async function main() {
  const config = loadConfig();

  if (config.onboarding.enabled && config.onboarding.databaseUrl) {
    initStore(config.onboarding.databaseUrl, process.env.TOKEN_ENC_KEY!);
    await ensureSchema();
  }

  if (config.transport === "stdio") {
    const server = buildMcpServer(config.owner);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    return;
  }

  await startHttpServer(config);
}

main().catch((err) => {
  console.error("Fatal:", err instanceof Error ? err.message : err);
  process.exit(1);
});
