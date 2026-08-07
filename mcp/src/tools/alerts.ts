import { z } from "zod";
import { config } from "../config.js";
import {
  maxItemsField,
  params,
  propertiesField,
  responseFormatField,
  runQuery,
  type XdrTool,
} from "../toolkit.js";

export const alertTools: XdrTool[] = [
  {
    name: "xdr_list_alerts",
    title: "List alerts",
    description:
      "Lists Microsoft Defender XDR alerts across workloads, filtered by severity, status and age. " +
      "Use it for queue triage ('what new high severity alerts are open'), and to find the incident " +
      "an alert belongs to. For the alerts of one incident use xdr_get_incident_alerts instead.",
    inputSchema: {
      days_ago: z.number().int().min(1).max(365).optional().describe("Look-back window in days."),
      severity: z
        .array(z.enum(["Informational", "Low", "Medium", "High"]))
        .optional()
        .describe("Keep only these severities."),
      status: z
        .array(z.enum(["New", "InProgress", "Resolved"]))
        .optional()
        .describe("Keep only these statuses. Use [\"New\",\"InProgress\"] for the open queue."),
      order: z.enum(["desc", "asc"]).optional().describe("Sort direction by time. Defaults to desc."),
      page_size: z.number().int().min(1).max(1000).optional().describe("Records per API page."),
      page_number: z.number().int().min(1).optional().describe("1-based page number."),
      all_pages: z.boolean().optional().describe("Page through every result. Slow on busy tenants."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Get-XdrAlert",
        params: params({
          DaysAgo: args.days_ago,
          Severity: args.severity,
          Status: args.status,
          Order: args.order,
          PageSize: args.page_size,
          PageNumber: args.page_number,
          All: args.all_pages,
        }),
        title: "Defender XDR alerts",
        format: args.response_format,
        maxItems: args.max_items,
        properties: args.properties,
        timeoutSeconds: args.all_pages ? config.longTimeoutSeconds : config.timeoutSeconds,
        summaryFields: [
          "alertId",
          "alertDisplayName",
          "severity",
          "status",
          "providerName",
          "category",
          "assignedTo",
          "incidentId",
          "startTimeUtc",
        ],
        emptyMessage: "No alerts matched the filters.",
      }),
  },
  {
    name: "xdr_list_suppression_rules",
    title: "List alert suppression rules",
    description:
      "Lists Defender XDR alert suppression rules. Use it when triaging a suspicious gap in " +
      "detections, when an expected alert never fired, or when reviewing tuning decisions.",
    inputSchema: {
      response_format: responseFormatField,
      max_items: maxItemsField,
      refresh: z.boolean().optional().describe("Bypass the cache."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ response_format, max_items, refresh }) =>
      runQuery({
        command: "Get-XdrSuppressionRule",
        params: params({ Force: refresh }),
        title: "Alert suppression rules",
        format: response_format,
        maxItems: max_items,
        summaryFields: ["ruleId", "name", "action", "status", "scope", "createdBy", "lastUpdatedTime"],
        emptyMessage: "No suppression rules are configured.",
      }),
  },
  {
    name: "xdr_list_detection_rules",
    title: "List custom detection rules",
    description:
      "Lists the unified detection rules (custom detections) defined in Advanced Hunting, including " +
      "their queries, frequency and response actions. Use it to check whether a hunting hypothesis is " +
      "already covered by a detection, or to review coverage during an investigation.",
    inputSchema: {
      response_format: responseFormatField,
      max_items: maxItemsField,
      refresh: z.boolean().optional().describe("Bypass the cache."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ response_format, max_items, refresh }) =>
      runQuery({
        command: "Get-XdrAdvancedHuntingUnifiedDetectionRules",
        params: params({ Force: refresh }),
        title: "Custom detection rules",
        format: response_format,
        maxItems: max_items,
        summaryFields: ["id", "displayName", "severity", "isEnabled", "frequency", "lastRunTime", "createdBy"],
        emptyMessage: "No custom detection rules were returned.",
      }),
  },
];
