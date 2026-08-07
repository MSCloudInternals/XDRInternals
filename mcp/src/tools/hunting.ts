import { z } from "zod";
import { bridge, type InvokeResult } from "../bridge.js";
import { config } from "../config.js";
import { renderResult } from "../format.js";
import {
  maxItemsField,
  params,
  propertiesField,
  responseFormatField,
  runQuery,
  toolError,
  type XdrTool,
} from "../toolkit.js";

const MTO_ENDPOINT_HINT = /mto|fanout|404|not found|405|400/i;
const SINGLE_TENANT_QUERY_URI = "https://security.microsoft.com/apiproxy/mtp/huntingService/queryExecutor";

interface TimeRange {
  start: Date;
  end: Date;
  label: string;
}

function resolveTimeRange(args: {
  minutes_ago?: number;
  days_ago?: number;
  start_time?: string;
  end_time?: string;
}): TimeRange {
  const end = args.end_time ? new Date(args.end_time) : new Date();
  if (Number.isNaN(end.getTime())) {
    throw new Error(`end_time '${args.end_time}' is not a valid ISO 8601 timestamp.`);
  }

  if (args.start_time) {
    const start = new Date(args.start_time);
    if (Number.isNaN(start.getTime())) {
      throw new Error(`start_time '${args.start_time}' is not a valid ISO 8601 timestamp.`);
    }
    return { start, end, label: `${start.toISOString()} to ${end.toISOString()}` };
  }

  if (args.minutes_ago) {
    return {
      start: new Date(end.getTime() - args.minutes_ago * 60_000),
      end,
      label: `last ${args.minutes_ago} minute(s)`,
    };
  }

  const days = args.days_ago ?? 7;
  return { start: new Date(end.getTime() - days * 86_400_000), end, label: `last ${days} day(s)` };
}

/** Extracts rows from the single-tenant hunting endpoint, which nests them differently per route. */
function extractRows(payload: unknown): unknown[] {
  const root = payload as Record<string, any> | null;
  if (!root) return [];
  if (Array.isArray(root.Results)) return root.Results;
  if (Array.isArray(root.results)) return root.results;
  if (Array.isArray(root.result?.Results)) return root.result.Results;
  if (Array.isArray(root.result?.results)) return root.result.results;
  return [];
}

export const huntingTools: XdrTool[] = [
  {
    name: "xdr_run_hunting_query",
    title: "Run an advanced hunting query",
    description:
      "Runs a KQL Advanced Hunting query against the Defender XDR data (DeviceProcessEvents, " +
      "DeviceNetworkEvents, IdentityLogonEvents, EmailEvents, CloudAppEvents, AlertEvidence and the " +
      "rest). This is the main threat hunting and evidence-gathering tool: use it to pivot on a hash, " +
      "IP, account or device, to test a hunting hypothesis, and to reconstruct what happened. Always " +
      "bound the query with a time range and a 'limit' or summarize clause. Call " +
      "xdr_get_hunting_schema first when unsure about table or column names.",
    inputSchema: {
      query: z
        .string()
        .min(3)
        .describe(
          "KQL query, e.g. 'DeviceProcessEvents | where FileName =~ \"powershell.exe\" | take 50'. " +
            "The time range is applied by the service, so do not depend on ago() alone.",
        ),
      days_ago: z.number().int().min(1).max(365).optional().describe("Look back this many days. Defaults to 7."),
      minutes_ago: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("Look back this many minutes. Takes precedence over days_ago."),
      start_time: z.string().optional().describe("ISO 8601 start time, e.g. 2026-07-30T00:00:00Z."),
      end_time: z.string().optional().describe("ISO 8601 end time. Defaults to now."),
      max_record_count: z
        .number()
        .int()
        .min(1)
        .max(100_000)
        .optional()
        .describe("Service-side record cap for the query."),
      tenant_ids: z
        .array(z.string())
        .optional()
        .describe("Tenant GUIDs to fan the query out to. Defaults to the signed-in tenant."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
      timeout_seconds: z
        .number()
        .int()
        .min(30)
        .max(3600)
        .optional()
        .describe(`Query timeout. Defaults to ${config.longTimeoutSeconds}.`),
    },
    annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: true },
    handler: async (args) => {
      let range: TimeRange;
      try {
        range = resolveTimeRange(args);
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }

      const timeoutSeconds = args.timeout_seconds ?? config.longTimeoutSeconds;
      const maxItems = args.max_items ?? config.defaultMaxItems;
      const notes = [`Time range: ${range.label}.`];

      let result: InvokeResult;
      try {
        result = await bridge.invoke({
          command: "Invoke-XdrMtoAdvancedHunting",
          params: params({
            QueryText: args.query,
            TenantIds: args.tenant_ids,
            MinutesAgo: args.minutes_ago,
            DaysAgo: args.minutes_ago || args.start_time ? undefined : args.days_ago,
            StartTime: args.start_time,
            EndTime: args.end_time,
            MaxRecordCount: args.max_record_count,
          }),
          maxItems,
          properties: args.properties,
          timeoutSeconds,
          depth: 8,
        });
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }

      const mtoFailed = result.items.length === 0 && result.errors.length > 0;
      if (!mtoFailed) {
        if (result.errors.length > 0) notes.push(`Service reported: ${result.errors.join(" | ")}`);
        return {
          content: [
            {
              type: "text",
              text: renderResult({
                title: "Advanced hunting results",
                result,
                format: args.response_format ?? "markdown",
                notes,
                emptyMessage:
                  "The query ran and returned no rows. Widen the time range, relax the filters, or confirm the table is onboarded in this tenant.",
              }),
            },
          ],
        };
      }

      const mtoError = result.errors.join(" | ");
      if (!MTO_ENDPOINT_HINT.test(mtoError)) {
        return toolError(`Advanced hunting failed: ${mtoError}`);
      }

      // The module routes hunting through the multi-tenant endpoint, which is not enabled for every
      // tenant. Fall back to the single-tenant hunting route before giving up.
      try {
        const body = JSON.stringify({
          QueryText: args.query,
          EncodedQueryText: args.query,
          StartTime: range.start.toISOString(),
          EndTime: range.end.toISOString(),
          MaxRecordCount: args.max_record_count ?? null,
        });

        const fallback = await bridge.invoke({
          command: "Invoke-XdrRestMethod",
          params: { Uri: SINGLE_TENANT_QUERY_URI, Method: "Post", ContentType: "application/json", Body: body },
          maxItems: 1,
          timeoutSeconds,
          depth: 10,
        });

        if (fallback.errors.length > 0 && fallback.items.length === 0) {
          return toolError(
            `Advanced hunting failed on both routes.\nMulti-tenant route: ${mtoError}\nSingle-tenant route: ${fallback.errors.join(" | ")}`,
          );
        }

        const rows = extractRows(fallback.items[0]);
        const trimmed = rows.slice(0, maxItems);
        return {
          content: [
            {
              type: "text",
              text: renderResult({
                title: "Advanced hunting results",
                result: {
                  items: trimmed,
                  totalCount: rows.length,
                  truncated: rows.length > trimmed.length,
                  warnings: fallback.warnings,
                  information: fallback.information,
                  errors: [],
                },
                format: args.response_format ?? "markdown",
                notes: [
                  ...notes,
                  `The multi-tenant hunting route was unavailable (${mtoError}); the single-tenant route was used instead.`,
                ],
                emptyMessage: "The query ran and returned no rows.",
              }),
            },
          ],
        };
      } catch (error) {
        return toolError(
          `Advanced hunting failed on both routes.\nMulti-tenant route: ${mtoError}\nSingle-tenant route: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    },
  },
  {
    name: "xdr_get_hunting_schema",
    title: "Get advanced hunting schema",
    description:
      "Returns the Advanced Hunting table schema: table names, and the columns and types of each " +
      "table. Use it before writing a query to confirm column names, or to discover which tables the " +
      "tenant has data for. Filter with table_name to keep the response small.",
    inputSchema: {
      table_name: z
        .string()
        .optional()
        .describe("Return only tables whose name contains this text, e.g. 'DeviceProcess'."),
      names_only: z
        .boolean()
        .optional()
        .describe("Return table names without their columns. Best for a first look."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      refresh: z.boolean().optional().describe("Bypass the cache."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ table_name, names_only, response_format, max_items, refresh }) => {
      try {
        const result = await bridge.invoke({
          command: "Get-XdrAdvancedHuntingTableSchema",
          params: params({ Force: refresh }),
          maxItems: 0,
          timeoutSeconds: config.timeoutSeconds,
          depth: 6,
        });

        if (result.items.length === 0) {
          return toolError(
            result.errors.join(" | ") || "The hunting schema could not be retrieved.",
          );
        }

        const tables = result.items
          .map((item) => item as Record<string, any>)
          .filter((item) => {
            if (!table_name) return true;
            const name = String(item.Name ?? item.name ?? item.tableName ?? "");
            return name.toLowerCase().includes(table_name.toLowerCase());
          })
          .map((item) => {
            const name = item.Name ?? item.name ?? item.tableName ?? "unknown";
            if (names_only) return { table: name };
            const columns = (item.Columns ?? item.columns ?? []) as Record<string, any>[];
            return {
              table: name,
              columnCount: Array.isArray(columns) ? columns.length : 0,
              columns: Array.isArray(columns)
                ? columns.map((column) => `${column.Name ?? column.name}:${column.Type ?? column.type ?? "?"}`)
                : [],
            };
          });

        const limit = max_items ?? (names_only ? 500 : 20);
        return {
          content: [
            {
              type: "text",
              text: renderResult({
                title: table_name ? `Hunting schema matching '${table_name}'` : "Hunting schema",
                result: {
                  items: tables.slice(0, limit),
                  totalCount: tables.length,
                  truncated: tables.length > limit,
                  warnings: result.warnings,
                  information: [],
                  errors: [],
                },
                format: response_format ?? "markdown",
                summaryFields: names_only ? ["table"] : ["table", "columnCount"],
                notes: names_only
                  ? ["Call again with table_name to see the columns of a specific table."]
                  : ["Set names_only for a compact list of every table."],
                emptyMessage: table_name
                  ? `No hunting table name contains '${table_name}'.`
                  : "The schema response was empty.",
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
    name: "xdr_validate_hunting_query",
    title: "Validate a hunting query",
    description:
      "Validates a KQL query against the Defender XDR hunting service without running it, including " +
      "the extra constraints custom detection rules must satisfy. Use it to check syntax and column " +
      "references before a long-running hunt or before proposing a detection rule.",
    inputSchema: {
      query: z.string().min(3).describe("KQL query to validate."),
      response_format: responseFormatField.default("json"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ query, response_format }) =>
      runQuery({
        command: "Invoke-XdrHuntingQueryValidation",
        params: { QueryText: query },
        title: "Query validation",
        format: response_format,
        maxItems: 5,
        depth: 8,
        emptyMessage: "The validation service returned no findings, which usually means the query is valid.",
      }),
  },
  {
    name: "xdr_list_hunting_functions",
    title: "List saved hunting functions",
    description:
      "Lists the saved Advanced Hunting functions in the tenant, optionally one by ID. Saved " +
      "functions often encode local naming conventions and reusable hunting logic worth reusing in " +
      "new queries.",
    inputSchema: {
      function_id: z.number().int().optional().describe("Return only this saved function."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      refresh: z.boolean().optional().describe("Bypass the cache."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ function_id, response_format, max_items, refresh }) =>
      runQuery({
        command: "Get-XdrAdvancedHuntingFunction",
        params: params({ Id: function_id, Force: refresh }),
        title: "Saved hunting functions",
        format: response_format,
        maxItems: max_items,
        summaryFields: ["id", "name", "displayName", "description", "createdBy", "lastUpdatedTime"],
        emptyMessage: "No saved hunting functions were returned.",
      }),
  },
];
