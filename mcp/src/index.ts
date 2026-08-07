#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { bridge } from "./bridge.js";
import { config } from "./config.js";
import { registerPrompts } from "./prompts.js";
import { registerTools, type XdrTool } from "./toolkit.js";
import { advancedTools } from "./tools/advanced.js";
import { alertTools } from "./tools/alerts.js";
import { authTools } from "./tools/auth.js";
import { entityTools } from "./tools/entities.js";
import { huntingTools } from "./tools/hunting.js";
import { incidentTools } from "./tools/incidents.js";
import { liveResponseTools } from "./tools/liveresponse.js";
import { responseTools } from "./tools/response.js";

const SERVER_NAME = "xdr";
const SERVER_VERSION = "0.1.0";

const allTools: XdrTool[] = [
  ...authTools,
  ...incidentTools,
  ...alertTools,
  ...huntingTools,
  ...entityTools,
  ...responseTools,
  ...liveResponseTools,
  ...advancedTools,
];

function log(message: string): void {
  process.stderr.write(`[xdr-mcp] ${message}\n`);
}

function createServer(): { server: McpServer; tools: string[]; prompts: string[] } {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    {
      instructions:
        "Microsoft Defender XDR access for security incident investigation, incident handling and threat hunting, " +
        "backed by the XDRInternals PowerShell module against the security.microsoft.com portal APIs.\n\n" +
        "Authentication: every tool shares one PowerShell session held by this server. If a tool reports that " +
        "there is no session, call xdr_auth_status, then xdr_auth_login_sso (reuses the operator's current " +
        "sign-in), xdr_auth_login_browser (interactive, for MFA/passkey/TAP), or xdr_auth_connect_with_token " +
        "(an sccauth or ESTSAUTH cookie the operator supplies). The login, status, use-token and logout prompts " +
        "drive the same flow for the operator.\n\n" +
        "Working style: keep queries bounded (tight time windows, page sizes, KQL limits) because portal " +
        "responses are large; markdown responses are summaries, so request response_format 'json' when you need " +
        "complete records. Read-only investigation is safe to run freely. Tools that change tenant state - " +
        "merging incidents, moving alerts, device response actions, Live Response - must be confirmed with the " +
        "operator first, and isolation in particular cuts a production endpoint off the network.",
    },
  );

  const tools = registerTools(server, allTools);
  const prompts = registerPrompts(server);
  return { server, tools, prompts };
}

async function autoConnect(): Promise<void> {
  if (!config.autoConnect) return;
  if (!config.sccauth && !config.estsauth) {
    log("XDR_MCP_AUTO_CONNECT is set but neither XDR_SCCAUTH nor XDR_ESTSAUTH is present; skipping.");
    return;
  }

  try {
    if (config.estsauth) {
      await bridge.invoke({
        command: "Connect-XdrByEstsCookie",
        params: { EstsAuthCookieValue: config.estsauth, ...(config.tenantId ? { TenantId: config.tenantId } : {}) },
        timeoutSeconds: 180,
        maxItems: 1,
      });
      bridge.markConnected("ESTSAUTH cookie from the environment");
    } else {
      await bridge.invoke({
        command: "Set-XdrConnectionSettings",
        params: {
          SccAuth: config.sccauth!,
          ...(config.xsrf ? { Xsrf: config.xsrf } : {}),
          ...(config.tenantId ? { TenantId: config.tenantId } : {}),
        },
        timeoutSeconds: 180,
        maxItems: 1,
      });
      bridge.markConnected("sccauth cookie from the environment");
    }
    log("Connected to Defender XDR using the cookie from the environment.");
  } catch (error) {
    log(`Auto-connect failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** `--smoke-test` verifies the PowerShell bridge and tool wiring without speaking MCP. */
async function smokeTest(): Promise<number> {
  const { tools, prompts } = createServer();
  log(`Module path: ${config.modulePath}`);
  log(`Registered ${tools.length} tool(s): ${tools.join(", ")}`);
  log(`Registered ${prompts.length} prompt(s): ${prompts.join(", ")}`);

  try {
    const ping = await bridge.ping();
    log(`PowerShell ${ping.pwshVersion} reachable, runspace ready: ${ping.runspaceReady}`);
    const inventory = await bridge.listCommands();
    log(`Imported ${inventory.module} with ${inventory.totalCount} cmdlet(s).`);
    const help = await bridge.help("Get-XdrIncident");
    const synopsis = (help.items[0] as { synopsis?: string } | undefined)?.synopsis ?? "unknown";
    log(`Help probe: Get-XdrIncident - ${synopsis}`);
    log("Smoke test passed.");
    return 0;
  } catch (error) {
    log(`Smoke test failed: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  } finally {
    bridge.restart();
  }
}

async function main(): Promise<void> {
  if (process.argv.includes("--smoke-test")) {
    process.exitCode = await smokeTest();
    return;
  }

  const { server, tools, prompts } = createServer();

  const shutdown = () => {
    bridge.restart();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await autoConnect();
  await server.connect(new StdioServerTransport());

  log(
    `Ready. ${tools.length} tool(s), ${prompts.length} prompt(s), module ${config.modulePath}` +
      `${config.readOnly ? ", read-only mode" : ""}.`,
  );
}

main().catch((error) => {
  log(`Fatal: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
  process.exit(1);
});
