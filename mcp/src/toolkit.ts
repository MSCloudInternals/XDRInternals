import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { bridge, XdrBridgeError, type InvokeResult } from "./bridge.js";
import { config } from "./config.js";
import { renderAction, renderResult, type ResponseFormat } from "./format.js";

export const LOGIN_HINT =
  "Sign in first: call xdr_auth_login_sso (reuses the account you are already signed in with), " +
  "xdr_auth_login_browser (interactive sign-in, supports MFA/passkey/TAP), or " +
  "xdr_auth_connect_with_token (paste an sccauth or ESTSAUTH cookie). " +
  "In Claude Code the /mcp__xdr__login prompt walks through the same flow.";

/** Shared input fields, so every read tool exposes the same knobs. */
export const responseFormatField = z
  .enum(["markdown", "json"])
  .default("markdown")
  .describe(
    "markdown returns a compact summary table (default, cheapest); json returns the complete records.",
  );

export const maxItemsField = z
  .number()
  .int()
  .min(1)
  .max(2000)
  .optional()
  .describe(`Maximum records to return. Defaults to ${config.defaultMaxItems}.`);

export const propertiesField = z
  .array(z.string())
  .optional()
  .describe(
    "Return only these properties from each record. Use it to keep large result sets readable.",
  );

export interface XdrTool {
  name: string;
  title: string;
  description: string;
  inputSchema: z.ZodRawShape;
  annotations?: ToolAnnotations;
  /** Tools that change tenant state are withheld when XDR_MCP_READONLY is set. */
  mutating?: boolean;
  handler: (args: any) => Promise<CallToolResult>;
}

export function registerTools(server: McpServer, tools: XdrTool[]): string[] {
  const registered: string[] = [];
  for (const tool of tools) {
    if (tool.mutating && config.readOnly) continue;
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: { title: tool.title, ...(tool.annotations ?? {}) },
      },
      tool.handler,
    );
    registered.push(tool.name);
  }
  return registered;
}

/** Drops empty values and false switches so PowerShell parameter sets bind predictably. */
export function params(source: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined || value === null) continue;
    if (value === false) continue;
    if (Array.isArray(value) && value.length === 0) continue;
    if (typeof value === "string" && value.trim() === "") continue;
    result[key] = value;
  }
  return result;
}

/** Rewrites raw PowerShell failures into something the model can act on. */
export function describeFailure(message: string): string {
  const text = message.trim();

  if (/not connected to xdr/i.test(text) || /Connect-XdrByEstsCookie or Set-XdrConnectionSettings/i.test(text)) {
    return `No authenticated Defender XDR session. ${LOGIN_HINT}`;
  }
  if (/\b401\b|unauthorized|forbidden|\b403\b/i.test(text)) {
    return `${text}\n\nThe portal session is missing, expired, or lacks permission for this action. Re-authenticate (${LOGIN_HINT}) or check your Defender XDR role assignments.`;
  }
  if (/xsrf/i.test(text)) {
    return `${text}\n\nThe XSRF token could not be refreshed. Re-authenticate and retry.`;
  }
  if (/timed out|timeout/i.test(text)) {
    return `${text}\n\nNarrow the time range, reduce the page size, or pass a larger timeout_seconds.`;
  }
  if (/Read-Host|prompt/i.test(text) && /host/i.test(text)) {
    return `${text}\n\nThe cmdlet tried to prompt for input, which is not possible here. Supply every required parameter explicitly (for example tenant_id).`;
  }
  return text;
}

export function toolError(message: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text: describeFailure(message) }] };
}

function failureFromResult(command: string, result: InvokeResult): CallToolResult {
  const message = result.errors.join(" | ") || `'${command}' returned no data and no error.`;
  const warnings = result.warnings.length > 0 ? `\n\nWarnings: ${result.warnings.join(" | ")}` : "";
  return toolError(`${message}${warnings}`);
}

export interface QueryOptions {
  command: string;
  params?: Record<string, unknown>;
  title: string;
  format?: ResponseFormat;
  summaryFields?: string[];
  maxItems?: number;
  properties?: string[];
  timeoutSeconds?: number;
  depth?: number;
  notes?: string[];
  emptyMessage?: string;
}

/** Runs a read-only cmdlet and formats the records. */
export async function runQuery(options: QueryOptions): Promise<CallToolResult> {
  try {
    const result = await bridge.invoke({
      command: options.command,
      params: options.params ?? {},
      maxItems: options.maxItems ?? config.defaultMaxItems,
      properties: options.properties,
      timeoutSeconds: options.timeoutSeconds,
      depth: options.depth,
    });

    if (result.items.length === 0 && result.errors.length > 0) {
      return failureFromResult(options.command, result);
    }

    const notes = [...(options.notes ?? [])];
    if (result.errors.length > 0) {
      notes.push(`Partial result. The cmdlet reported: ${result.errors.join(" | ")}`);
    }

    return {
      content: [
        {
          type: "text",
          text: renderResult({
            title: options.title,
            result,
            format: options.format ?? "markdown",
            summaryFields: options.summaryFields,
            notes,
            emptyMessage: options.emptyMessage,
          }),
        },
      ],
    };
  } catch (error) {
    return toolError(error instanceof XdrBridgeError || error instanceof Error ? error.message : String(error));
  }
}

export interface ActionOptions {
  command: string;
  params?: Record<string, unknown>;
  title: string;
  summary: string;
  timeoutSeconds?: number;
  notes?: string[];
  maxItems?: number;
  onSuccess?: (result: InvokeResult) => void;
}

/** Runs a state-changing cmdlet and formats a short confirmation. */
export async function runAction(options: ActionOptions): Promise<CallToolResult> {
  try {
    const result = await bridge.invoke({
      command: options.command,
      params: options.params ?? {},
      maxItems: options.maxItems ?? 25,
      timeoutSeconds: options.timeoutSeconds,
      depth: 6,
    });

    if (result.errors.length > 0) {
      return failureFromResult(options.command, result);
    }

    options.onSuccess?.(result);
    return {
      content: [{ type: "text", text: renderAction(options.title, options.summary, result, options.notes ?? []) }],
    };
  } catch (error) {
    return toolError(error instanceof XdrBridgeError || error instanceof Error ? error.message : String(error));
  }
}

export function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}
