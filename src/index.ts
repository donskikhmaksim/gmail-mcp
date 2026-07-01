import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { buildMcpServer } from "./server.js";
import { startHttpServer } from "./http.js";

async function main() {
  const config = loadConfig();

  if (config.transport === "stdio") {
    const user = config.users[0];
    const server = buildMcpServer(user);
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
