import { z } from "zod";
import { bridge } from "../bridge.js";
import { config } from "../config.js";
import { renderResult } from "../format.js";
import {
  maxItemsField,
  params,
  propertiesField,
  responseFormatField,
  runQuery,
  textResult,
  toolError,
  type XdrTool,
} from "../toolkit.js";

/** Cmdlets the generic runner may execute: read-only data retrieval plus hunting/validation. */
const READ_ONLY_EXTRAS = new Set([
  "convertto-xdrencodedadvancedhuntingquery",
  "invoke-xdrhuntingqueryvalidation",
  "invoke-xdrmtoadvancedhunting",
  "invoke-xdrxspmhuntingquery",
]);

function isReadOnlyCmdlet(name: string): boolean {
  const lower = name.trim().toLowerCase();
  return lower.startsWith("get-xdr") || READ_ONLY_EXTRAS.has(lower);
}

const ALLOWED_HOSTS = /(^|\.)security\.microsoft\.com$/i;

export const advancedTools: XdrTool[] = [
  {
    name: "xdr_get_threat_analytics_outbreaks",
    title: "Get threat analytics outbreaks",
    description:
      "Returns Microsoft Threat Analytics outbreaks and campaigns tracked for the tenant, including " +
      "which ones the tenant is exposed to. Use it for threat context during an investigation and to " +
      "pick hunting targets that matter for this environment.",
    inputSchema: {
      top_threats: z.boolean().optional().describe("Return only the highest-impact threats."),
      change_count: z.boolean().optional().describe("Return only the count of changed threats."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      refresh: z.boolean().optional().describe("Bypass the cache."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ top_threats, change_count, response_format, max_items, refresh }) =>
      runQuery({
        command: "Get-XdrThreatAnalyticsOutbreaks",
        params: params({ TopThreats: top_threats, ChangeCount: change_count, Force: refresh }),
        title: "Threat analytics outbreaks",
        format: response_format,
        maxItems: max_items,
        summaryFields: ["id", "displayName", "severity", "tags", "lastUpdatedTime", "impactedAssets"],
        emptyMessage: "No threat analytics data was returned.",
      }),
  },
  {
    name: "xdr_get_attack_paths",
    title: "Get exposure attack paths",
    description:
      "Returns Defender XDR exposure management (XSPM) attack paths: the routes an attacker could take " +
      "from an entry point to a critical asset. Use it to judge how bad a compromised device or " +
      "account really is, and what it could reach next.",
    inputSchema: {
      top: z.number().int().min(1).max(500).optional().describe("Number of attack paths to return."),
      skip: z.number().int().min(0).optional().describe("Attack paths to skip, for paging."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      refresh: z.boolean().optional().describe("Bypass the cache."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ top, skip, response_format, max_items, refresh }) =>
      runQuery({
        command: "Get-XdrXspmAttackPath",
        params: params({ Top: top ?? 25, Skip: skip, Force: refresh }),
        title: "Exposure attack paths",
        format: response_format,
        maxItems: max_items,
        summaryFields: ["id", "displayName", "riskLevel", "entryPoint", "target", "chokePointCount"],
        emptyMessage: "No attack paths were returned. Exposure management may not be enabled for this tenant.",
      }),
  },
  {
    name: "xdr_list_cmdlets",
    title: "List XDRInternals cmdlets",
    description:
      "Lists every cmdlet the underlying XDRInternals module exposes, with its parameter names. The " +
      "curated tools cover incident, alert, hunting, entity and response work; use this listing when " +
      "an investigation needs a portal area those tools do not reach (vulnerability management, " +
      "configuration, exposure management, Cloud Apps policies), then run it with xdr_run_cmdlet.",
    inputSchema: {
      filter: z.string().optional().describe("Substring filter over cmdlet names, e.g. 'Vulnerability'."),
      read_only_only: z
        .boolean()
        .optional()
        .describe("List only the cmdlets xdr_run_cmdlet is allowed to execute. Defaults to true."),
      max_items: maxItemsField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    handler: async ({ filter, read_only_only, max_items }) => {
      try {
        const inventory = await bridge.listCommands();
        const readOnlyOnly = read_only_only ?? true;
        const matches = inventory.items
          .filter((item) => (readOnlyOnly ? isReadOnlyCmdlet(item.name) : true))
          .filter((item) => (filter ? item.name.toLowerCase().includes(filter.toLowerCase()) : true))
          .map((item) => ({ cmdlet: item.name, parameters: item.parameters.join(", ") }));

        const limit = max_items ?? 200;
        return {
          content: [
            {
              type: "text",
              text: renderResult({
                title: `${inventory.module} cmdlets${filter ? ` matching '${filter}'` : ""}`,
                result: {
                  items: matches.slice(0, limit),
                  totalCount: matches.length,
                  truncated: matches.length > limit,
                  warnings: [],
                  information: [],
                  errors: [],
                },
                format: "markdown",
                summaryFields: ["cmdlet", "parameters"],
                notes: [
                  "Read parameter documentation with xdr_get_cmdlet_help, then execute with xdr_run_cmdlet.",
                  readOnlyOnly
                    ? "Only read-only cmdlets are listed. State-changing cmdlets are exposed as dedicated tools instead."
                    : "State-changing cmdlets are listed but cannot be run through xdr_run_cmdlet.",
                ],
                emptyMessage: "No cmdlet matched the filter.",
              }),
            },
          ],
        };
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }
    },
  },
  {
    name: "xdr_get_cmdlet_help",
    title: "Get XDRInternals cmdlet help",
    description:
      "Returns the documentation for one XDRInternals cmdlet: synopsis, description, syntax, " +
      "parameters and examples. Call it before xdr_run_cmdlet so parameters are passed correctly.",
    inputSchema: {
      cmdlet: z.string().min(3).describe("Exact cmdlet name, e.g. Get-XdrVulnerabilityManagementVulnerabilities."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    handler: async ({ cmdlet }) => {
      try {
        const result = await bridge.help(cmdlet);
        return textResult(
          [`## Help: ${cmdlet}`, "", "```json", JSON.stringify(result.items[0] ?? {}, null, 2), "```"].join("\n"),
        );
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }
    },
  },
  {
    name: "xdr_run_cmdlet",
    title: "Run a read-only XDRInternals cmdlet",
    description:
      "Runs any read-only XDRInternals cmdlet (Get-Xdr*, plus the hunting and validation cmdlets) with " +
      "arbitrary parameters. This is the escape hatch for portal areas without a dedicated tool: " +
      "vulnerability management, exposure recommendations, tenant configuration, Cloud Apps policies " +
      "and so on. Discover the cmdlet with xdr_list_cmdlets and its parameters with " +
      "xdr_get_cmdlet_help. Cmdlets that change state are rejected here; use the dedicated tools.",
    inputSchema: {
      cmdlet: z.string().min(3).describe("Read-only cmdlet name, e.g. Get-XdrEndpointLicenseReport."),
      parameters: z
        .record(z.unknown())
        .optional()
        .describe(
          "Parameter names exactly as PowerShell expects them, e.g. { \"PageSize\": 50, \"Force\": true }. " +
            "Switches take true. Dates take ISO 8601 strings.",
        ),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
      timeout_seconds: z.number().int().min(30).max(3600).optional(),
    },
    annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: true },
    handler: async ({ cmdlet, parameters, response_format, max_items, properties, timeout_seconds }) => {
      if (!isReadOnlyCmdlet(cmdlet)) {
        return toolError(
          `'${cmdlet}' is not a read-only cmdlet, so it cannot run through xdr_run_cmdlet. Use the dedicated tool for that operation (for example xdr_invoke_device_action for device response), or list the runnable cmdlets with xdr_list_cmdlets.`,
        );
      }

      return runQuery({
        command: cmdlet,
        params: (parameters ?? {}) as Record<string, unknown>,
        title: cmdlet,
        format: response_format,
        maxItems: max_items,
        properties,
        timeoutSeconds: timeout_seconds,
        depth: 8,
        emptyMessage: `${cmdlet} returned no records.`,
      });
    },
  },
  {
    name: "xdr_invoke_rest_method",
    title: "Call a Defender XDR portal API",
    description:
      "Calls a security.microsoft.com portal API directly using the authenticated session, for " +
      "endpoints no cmdlet covers yet. GET only unless the server is started with " +
      "XDR_MCP_ALLOW_REST_WRITE=1. Prefer the typed tools; reach for this when an investigation needs " +
      "an API surface the module has not wrapped.",
    inputSchema: {
      uri: z
        .string()
        .url()
        .describe(
          "Full URL on security.microsoft.com, e.g. https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/123.",
        ),
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET").describe("HTTP method."),
      body: z
        .union([z.string(), z.record(z.unknown())])
        .optional()
        .describe("Request body. Objects are serialized to JSON."),
      response_format: responseFormatField.default("json"),
      max_items: maxItemsField,
      timeout_seconds: z.number().int().min(30).max(1800).optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    handler: async ({ uri, method, body, response_format, max_items, timeout_seconds }) => {
      let parsed: URL;
      try {
        parsed = new URL(uri);
      } catch {
        return toolError(`'${uri}' is not a valid URL.`);
      }

      if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.test(parsed.hostname)) {
        return toolError(
          `Only https requests to security.microsoft.com (and its subdomains) are allowed; '${parsed.hostname}' is not.`,
        );
      }

      const verb = (method ?? "GET").toUpperCase();
      if (verb !== "GET" && (config.readOnly || !config.allowRestWrite)) {
        return toolError(
          `${verb} requests are disabled. Start the server with XDR_MCP_ALLOW_REST_WRITE=1 (and without XDR_MCP_READONLY) to allow them, or use a dedicated tool for this change.`,
        );
      }

      const payload = typeof body === "object" && body !== null ? JSON.stringify(body) : body;

      return runQuery({
        command: "Invoke-XdrRestMethod",
        params: params({ Uri: uri, Method: verb, ContentType: "application/json", Body: payload }),
        title: `${verb} ${parsed.pathname}`,
        format: response_format,
        maxItems: max_items ?? 10,
        timeoutSeconds: timeout_seconds,
        depth: 12,
        emptyMessage: "The API returned an empty response.",
      });
    },
  },
];
