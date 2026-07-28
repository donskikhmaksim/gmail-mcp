import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { buildMcpServer } from "./server.js";
import { startHttpServer } from "./http.js";
import { initStore, ensureSchema } from "./store.js";
import { startScheduler } from "./scheduler.js";

async function main() {
  const config = loadConfig();

  let hasStore = false;
  if (config.onboarding.enabled && config.onboarding.databaseUrl) {
    initStore(config.onboarding.databaseUrl, process.env.TOKEN_ENC_KEY!);
    await ensureSchema();
    hasStore = true;
  }

  if (config.transport === "stdio") {
    const user = config.users[0];
    const server = buildMcpServer(user);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    return;
  }

  // stdio mode is a one-shot process per call — no persistent process to poll
  // with, so gmail_snooze/gmail_schedule_send only fire in HTTP deployments.
  if (hasStore) startScheduler(config);

  await startHttpServer(config);
}

main().catch((err) => {
  console.error("Fatal:", err instanceof Error ? err.message : err);
  process.exit(1);
});
