import { z } from "zod";
import { config } from "../config.js";
import {
  maxItemsField,
  params,
  propertiesField,
  responseFormatField,
  runAction,
  runQuery,
  type XdrTool,
} from "../toolkit.js";

const INCIDENT_FIELDS = [
  "IncidentId",
  "Title",
  "SeverityName",
  "Status",
  "AlertCount",
  "Classification",
  "Determination",
  "DetectionSourceNames",
  "CreatedTime",
  "LastUpdateTime",
];

const ALERT_FIELDS = [
  "alertId",
  "alertDisplayName",
  "severity",
  "status",
  "providerName",
  "category",
  "assignedTo",
  "incidentId",
  "startTimeUtc",
];

export const incidentTools: XdrTool[] = [
  {
    name: "xdr_list_incidents",
    title: "List incidents",
    description:
      "Lists Microsoft Defender XDR incidents for triage, newest risk first by default. Supports " +
      "title search, a look-back window, sorting and paging. Severity and detection sources are " +
      "returned as friendly names. Start here when asked what is happening in the tenant, what needs " +
      "triage, or to find an incident by name.",
    inputSchema: {
      title_search_terms: z
        .array(z.string())
        .optional()
        .describe("Match incidents whose title contains any of these terms, e.g. [\"ransomware\"]."),
      look_back_days: z
        .number()
        .int()
        .min(1)
        .max(365)
        .optional()
        .describe("Days of history to include. Defaults to 30."),
      sort_by: z
        .enum(["TopRisk", "CreatedDate", "LastUpdatedDate", "Status", "severity", "name"])
        .optional()
        .describe("Sort field. Defaults to TopRisk."),
      sort_order: z.enum(["Ascending", "Descending"]).optional().describe("Defaults to Descending."),
      page_size: z.number().int().min(1).max(1000).optional().describe("Records per API page. Defaults to 40."),
      page_index: z.number().int().min(1).optional().describe("1-based page number. Defaults to 1."),
      all_pages: z
        .boolean()
        .optional()
        .describe("Page through every result. Slow on large tenants; prefer paging explicitly."),
      defender_experts_licensed: z
        .boolean()
        .optional()
        .describe("Set when the tenant has Defender Experts for XDR, so its columns are returned."),
      refresh: z.boolean().optional().describe("Bypass the 10-minute cache."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Get-XdrIncident",
        params: params({
          TitleSearchTerms: args.title_search_terms,
          LookBackInDays: args.look_back_days,
          SortByField: args.sort_by,
          SortOrder: args.sort_order,
          PageSize: args.page_size,
          PageIndex: args.page_index,
          All: args.all_pages,
          DefenderExpertsLicensed: args.defender_experts_licensed,
          Force: args.refresh,
        }),
        title: "Defender XDR incidents",
        format: args.response_format,
        maxItems: args.max_items,
        properties: args.properties,
        summaryFields: INCIDENT_FIELDS,
        timeoutSeconds: args.all_pages ? config.longTimeoutSeconds : config.timeoutSeconds,
        emptyMessage: "No incidents matched. Widen look_back_days or drop title_search_terms.",
        notes: ["Use xdr_get_incident_alerts with an IncidentId to pull the alerts that make up an incident."],
      }),
  },
  {
    name: "xdr_get_incident",
    title: "Get one incident",
    description:
      "Retrieves the full record for a single Defender XDR incident by numeric ID, including " +
      "classification, determination, impacted entities and status metadata.",
    inputSchema: {
      incident_id: z.number().int().min(1).describe("Numeric incident ID, e.g. 2823."),
      response_format: responseFormatField.default("json"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ incident_id, response_format }) =>
      runQuery({
        command: "Get-XdrIncident",
        params: { IncidentId: incident_id },
        title: `Incident ${incident_id}`,
        format: response_format,
        maxItems: 1,
        depth: 10,
        summaryFields: INCIDENT_FIELDS,
        emptyMessage: `Incident ${incident_id} was not found, or it is outside the roles granted to this account.`,
      }),
  },
  {
    name: "xdr_get_incident_alerts",
    title: "Get incident alerts",
    description:
      "Lists every alert associated with a Defender XDR incident. Use it to understand what an " +
      "incident is built from, which detection sources fired, and which entities are involved.",
    inputSchema: {
      incident_id: z.number().int().min(1).describe("Numeric incident ID."),
      refresh: z.boolean().optional().describe("Bypass the cache."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ incident_id, refresh, response_format, max_items, properties }) =>
      runQuery({
        command: "Get-XdrIncidentAssociatedAlert",
        params: params({ IncidentId: incident_id, Force: refresh }),
        title: `Alerts in incident ${incident_id}`,
        format: response_format,
        maxItems: max_items,
        properties,
        summaryFields: ALERT_FIELDS,
        emptyMessage: `No alerts were returned for incident ${incident_id}.`,
      }),
  },
  {
    name: "xdr_merge_incidents",
    title: "Merge incidents",
    description:
      "Merges several Defender XDR incidents into one. Merging cannot be undone from the API: the " +
      "source incidents are absorbed into the surviving incident. Confirm the incident IDs with the " +
      "operator before calling this.",
    mutating: true,
    inputSchema: {
      incident_ids: z
        .array(z.number().int().min(1))
        .min(2)
        .describe("Incident IDs to merge. All incidents are merged into one."),
      comment: z.string().min(1).describe("Audit comment recorded with the merge."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    handler: async ({ incident_ids, comment }) =>
      runAction({
        command: "Merge-XdrIncident",
        params: { IncidentIds: incident_ids, Comment: comment },
        title: "Merge incidents",
        summary: `Merged incidents ${incident_ids.join(", ")}.`,
        notes: ["Re-read the surviving incident with xdr_get_incident to confirm the new alert set."],
      }),
  },
  {
    name: "xdr_move_alerts_to_incident",
    title: "Move alerts between incidents",
    description:
      "Moves alerts to a different Defender XDR incident, or into a brand new incident when no " +
      "target is given. Use it to split unrelated activity out of an over-grouped incident, or to " +
      "pull a stray alert into the incident it belongs to.",
    mutating: true,
    inputSchema: {
      alert_ids: z.array(z.string().min(1)).min(1).describe("Alert IDs to move."),
      target_incident_id: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("Destination incident ID. Omit to create a new incident from these alerts."),
      comment: z.string().optional().describe("Audit comment recorded with the change."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    handler: async ({ alert_ids, target_incident_id, comment }) =>
      runAction({
        command: "Move-XdrAlertToIncident",
        params: params({ AlertIds: alert_ids, TargetIncidentId: target_incident_id, Comment: comment }),
        title: "Move alerts",
        summary: target_incident_id
          ? `Moved ${alert_ids.length} alert(s) to incident ${target_incident_id}.`
          : `Moved ${alert_ids.length} alert(s) into a new incident.`,
      }),
  },
];
