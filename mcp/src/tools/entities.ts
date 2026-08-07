import { z } from "zod";
import { config } from "../config.js";
import {
  maxItemsField,
  params,
  propertiesField,
  responseFormatField,
  runQuery,
  toolError,
  type XdrTool,
} from "../toolkit.js";

const EVENT_GROUPS = [
  "AlertsRelatedEvents",
  "AntiVirus",
  "AppGuard",
  "AppControl",
  "ExploitGuard",
  "Files",
  "Firewall",
  "Network",
  "Processes",
  "Registry",
  "ResponseActions",
  "ScheduledTask",
  "SmartScreen",
  "Other",
  "UserActivity",
] as const;

export const entityTools: XdrTool[] = [
  {
    name: "xdr_list_devices",
    title: "List endpoint devices",
    description:
      "Lists Defender for Endpoint devices, optionally filtered by a device name prefix and a " +
      "last-seen window. Use it to resolve a hostname to a device ID (needed by the timeline and " +
      "response tools) and to review risk, exposure and health during an investigation.",
    inputSchema: {
      name_prefix: z.string().optional().describe("Match devices whose name starts with this text."),
      look_back_days: z.number().int().min(1).max(365).optional().describe("Only devices seen in this window."),
      page_size: z.number().int().min(1).max(1000).optional().describe("Records per API page."),
      page_index: z.number().int().min(1).optional().describe("1-based page number."),
      sort_by: z.string().optional().describe("API sort field, e.g. RiskScore or LastSeen."),
      sort_order: z.enum(["Ascending", "Descending"]).optional(),
      hide_low_fidelity_devices: z
        .boolean()
        .optional()
        .describe("Exclude low-fidelity/duplicate device records."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Get-XdrEndpointDevice",
        params: params({
          MachineSearchPrefix: args.name_prefix,
          LookingBackInDays: args.look_back_days,
          PageSize: args.page_size,
          PageIndex: args.page_index,
          SortByField: args.sort_by,
          SortOrder: args.sort_order,
          HideLowFidelityDevices: args.hide_low_fidelity_devices,
        }),
        title: "Endpoint devices",
        format: args.response_format,
        maxItems: args.max_items,
        properties: args.properties,
        summaryFields: [
          "id",
          "ComputerDnsName",
          "LastIpAddress",
          "RiskScore",
          "ExposureScore",
          "CriticalityLevel",
          "HealthStatus",
          "OsPlatform",
          "LastSeen",
        ],
        emptyMessage: "No devices matched. Check the name prefix or widen look_back_days.",
      }),
  },
  {
    name: "xdr_get_device",
    title: "Get one endpoint device",
    description:
      "Retrieves the full Defender for Endpoint record for one device by device ID, including risk, " +
      "exposure, onboarding state, tags and network identifiers.",
    inputSchema: {
      device_id: z.string().min(1).describe("Defender for Endpoint device ID (machine ID)."),
      refresh: z.boolean().optional().describe("Bypass the cache."),
      response_format: responseFormatField.default("json"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ device_id, refresh, response_format }) =>
      runQuery({
        command: "Get-XdrEndpointDevice",
        params: params({ DeviceId: device_id, Force: refresh }),
        title: `Device ${device_id}`,
        format: response_format,
        maxItems: 1,
        depth: 8,
        emptyMessage: `Device '${device_id}' was not found. Resolve the name with xdr_list_devices first.`,
      }),
  },
  {
    name: "xdr_get_device_timeline",
    title: "Get device timeline",
    description:
      "Pulls the Defender for Endpoint device timeline: process, file, network, registry, logon and " +
      "response-action events for one device. This is the core endpoint forensic view for an " +
      "investigation. Keep the window tight (hours to a few days) and filter with event_groups, " +
      "because a busy device produces very large volumes.",
    inputSchema: {
      device_id: z.string().optional().describe("Device ID. Provide this or device_dns_name."),
      device_dns_name: z.string().optional().describe("Device DNS name, when the ID is unknown."),
      last_n_days: z.number().int().min(1).max(30).optional().describe("Look-back window. Defaults to 1."),
      from_date: z.string().optional().describe("ISO 8601 start time. Use with to_date instead of last_n_days."),
      to_date: z.string().optional().describe("ISO 8601 end time."),
      event_groups: z
        .array(z.enum(EVENT_GROUPS))
        .optional()
        .describe("Restrict to these event groups, e.g. [\"Processes\",\"Network\"]."),
      event_type: z.string().optional().describe("Free-text filter applied to the event type."),
      source_providers: z
        .array(z.enum(["MDE", "MDI"]))
        .optional()
        .describe("Restrict to endpoint (MDE) or identity (MDI) sourced events."),
      marked_events_only: z.boolean().optional().describe("Return only events flagged as notable."),
      include_sentinel_events: z.boolean().optional().describe("Include Microsoft Sentinel events."),
      page_size: z.number().int().min(1).max(5000).optional().describe("Records per API page."),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
      timeout_seconds: z.number().int().min(60).max(3600).optional(),
    },
    annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: true },
    handler: async (args) => {
      if (!args.device_id && !args.device_dns_name) {
        return toolError("Provide device_id or device_dns_name. Use xdr_list_devices to resolve a hostname.");
      }
      const useDateRange = Boolean(args.from_date || args.to_date);
      return runQuery({
        command: "Get-XdrEndpointDeviceTimeline",
        params: params({
          DeviceId: args.device_id,
          MachineDnsName: args.device_id ? undefined : args.device_dns_name,
          LastNDays: useDateRange ? undefined : args.last_n_days ?? 1,
          FromDate: args.from_date,
          ToDate: args.to_date,
          EventsGroups: args.event_groups,
          EventType: args.event_type,
          SourceProviders: args.source_providers,
          MarkedEventsOnly: args.marked_events_only,
          IncludeSentinelEvents: args.include_sentinel_events,
          PageSize: args.page_size,
        }),
        title: `Device timeline (${args.device_id ?? args.device_dns_name})`,
        format: args.response_format,
        maxItems: args.max_items,
        properties: args.properties,
        timeoutSeconds: args.timeout_seconds ?? config.longTimeoutSeconds,
        summaryFields: ["Timestamp", "EventType", "ActionType", "FileName", "ProcessCommandLine", "RemoteUrl", "RemoteIP", "AccountName"],
        emptyMessage: "No timeline events were returned for this window.",
        notes: [
          "Only the first page of events is summarized. Narrow the window or use event_groups for depth over breadth.",
        ],
      });
    },
  },
  {
    name: "xdr_list_identities",
    title: "List identities",
    description:
      "Searches Defender for Identity identities across Active Directory, Entra ID and hybrid " +
      "environments. Use it to resolve a display name to a UPN, SID or object ID before pulling an " +
      "identity timeline.",
    inputSchema: {
      search_text: z.string().optional().describe("Free-text search over name, UPN and SAM account name."),
      identity_provider: z
        .array(z.enum(["ActiveDirectory", "EntraID", "Hybrid"]))
        .optional()
        .describe("Restrict to these identity providers."),
      page_size: z.number().int().min(1).max(1000).optional(),
      skip: z.number().int().min(0).optional().describe("Records to skip, for paging."),
      sort_by: z.enum(["RepresentableName", "AccountDomain", "CreatedDateTime"]).optional(),
      sort_direction: z.enum(["Asc", "Dsc"]).optional(),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Get-XdrIdentityIdentity",
        params: params({
          SearchText: args.search_text,
          IdentityProvider: args.identity_provider,
          PageSize: args.page_size,
          Skip: args.skip,
          SortByField: args.sort_by,
          SortDirection: args.sort_direction,
        }),
        title: "Identities",
        format: args.response_format,
        maxItems: args.max_items,
        properties: args.properties,
        summaryFields: [
          "representableName",
          "userPrincipalName",
          "accountDomain",
          "sid",
          "objectId",
          "identityEnvironment",
          "criticalityLevel",
          "accountStatus",
        ],
        emptyMessage: "No identities matched the search.",
      }),
  },
  {
    name: "xdr_get_identity",
    title: "Get one identity",
    description:
      "Retrieves the detailed Defender for Identity record for a user by UPN, Entra object ID or SID, " +
      "including risk level, account state and directory attributes.",
    inputSchema: {
      upn: z.string().optional().describe("User principal name, e.g. user@contoso.com."),
      aad_id: z.string().optional().describe("Entra ID object ID."),
      sid: z.string().optional().describe("On-premises security identifier."),
      refresh: z.boolean().optional().describe("Bypass the cache."),
      response_format: responseFormatField.default("json"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ upn, aad_id, sid, refresh, response_format }) => {
      if (!upn && !aad_id && !sid) {
        return toolError("Provide upn, aad_id or sid. Use xdr_list_identities to resolve a display name.");
      }
      return runQuery({
        command: "Get-XdrIdentityUser",
        params: params({ Upn: upn, AadId: upn ? undefined : aad_id, Sid: upn || aad_id ? undefined : sid, Force: refresh }),
        title: `Identity ${upn ?? aad_id ?? sid}`,
        format: response_format,
        maxItems: 1,
        depth: 8,
        emptyMessage: "That identity was not found in Defender for Identity.",
      });
    },
  },
  {
    name: "xdr_get_identity_timeline",
    title: "Get identity timeline",
    description:
      "Pulls the Defender for Identity timeline for one user: sign-ins, directory activity, cloud app " +
      "events and identity alerts. Use it to trace account compromise, lateral movement and " +
      "suspicious authentication patterns. Keep the window tight for busy accounts.",
    inputSchema: {
      upn: z.string().optional().describe("User principal name."),
      aad_id: z.string().optional().describe("Entra ID object ID."),
      sid: z.string().optional().describe("On-premises SID."),
      last_n_days: z.number().int().min(1).max(90).optional().describe("Look-back window. Defaults to 7."),
      from_date: z.string().optional().describe("ISO 8601 start time. Use with to_date instead of last_n_days."),
      to_date: z.string().optional().describe("ISO 8601 end time."),
      event_types: z.array(z.string()).optional().describe("Restrict to these event types."),
      list_event_types: z
        .boolean()
        .optional()
        .describe("Return the available event types for the window instead of events."),
      page_size: z.number().int().min(1).max(5000).optional(),
      include_sentinel_events: z.boolean().optional(),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
      timeout_seconds: z.number().int().min(60).max(3600).optional(),
    },
    annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: true },
    handler: async (args) => {
      const hasSelector = Boolean(args.upn || args.aad_id || args.sid || args.list_event_types);
      if (!hasSelector) {
        return toolError("Provide upn, aad_id or sid (or set list_event_types to enumerate event types).");
      }
      const useDateRange = Boolean(args.from_date || args.to_date);
      return runQuery({
        command: "Get-XdrIdentityUserTimeline",
        params: params({
          Upn: args.upn,
          AadId: args.upn ? undefined : args.aad_id,
          Sid: args.upn || args.aad_id ? undefined : args.sid,
          LastNDays: useDateRange ? undefined : args.last_n_days ?? 7,
          FromDate: args.from_date,
          ToDate: args.to_date,
          EventType: args.event_types,
          ListEventTypes: args.list_event_types,
          PageSize: args.page_size,
          IncludeSentinelEvents: args.include_sentinel_events,
        }),
        title: `Identity timeline (${args.upn ?? args.aad_id ?? args.sid ?? "event types"})`,
        format: args.response_format,
        maxItems: args.max_items,
        properties: args.properties,
        timeoutSeconds: args.timeout_seconds ?? config.longTimeoutSeconds,
        summaryFields: ["Timestamp", "ActionType", "Application", "SourceTable", "DeviceName", "Ip", "Location"],
        emptyMessage: "No identity events were returned for this window.",
      });
    },
  },
  {
    name: "xdr_get_cloudapps_activity",
    title: "Get Cloud Apps activity timeline",
    description:
      "Pulls the Microsoft Defender for Cloud Apps activity timeline: SaaS sign-ins, file and admin " +
      "activity, and the IPs and locations behind them. Use it for business email compromise, OAuth " +
      "abuse and data exfiltration investigations. Optionally filter with the API's native filter " +
      "object and include threat scores.",
    inputSchema: {
      last_n_days: z.number().int().min(1).max(90).optional().describe("Look-back window. Defaults to 1."),
      from_date: z.string().optional().describe("ISO 8601 start time."),
      to_date: z.string().optional().describe("ISO 8601 end time."),
      filters: z
        .record(z.unknown())
        .optional()
        .describe("Native Cloud Apps filter object, passed through to the API unchanged."),
      include_threat_scores: z.boolean().optional().describe("Enrich activities with threat scores."),
      count_only: z.boolean().optional().describe("Return only the matching activity count."),
      page_size: z.number().int().min(1).max(5000).optional(),
      response_format: responseFormatField,
      max_items: maxItemsField,
      properties: propertiesField,
      timeout_seconds: z.number().int().min(60).max(3600).optional(),
    },
    annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: true },
    handler: async (args) => {
      const useDateRange = Boolean(args.from_date || args.to_date);
      return runQuery({
        command: "Get-XdrCloudAppsActivityTimeline",
        params: params({
          LastNDays: useDateRange ? undefined : args.last_n_days ?? 1,
          FromDate: args.from_date,
          ToDate: args.to_date,
          Filters: args.filters,
          IncludeThreatScores: args.include_threat_scores,
          CountOnly: args.count_only,
          PageSize: args.page_size,
        }),
        title: "Cloud Apps activity",
        format: args.response_format,
        maxItems: args.max_items,
        properties: args.properties,
        timeoutSeconds: args.timeout_seconds ?? config.longTimeoutSeconds,
        summaryFields: ["Time", "User", "App", "Activity", "IP", "Location", "ThreatScore"],
        emptyMessage: "No Cloud Apps activity was returned for this window.",
      });
    },
  },
];
