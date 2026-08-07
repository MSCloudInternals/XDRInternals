import { z } from "zod";
import {
  maxItemsField,
  params,
  responseFormatField,
  runAction,
  runQuery,
  toolError,
  type XdrTool,
} from "../toolkit.js";

const DEVICE_ACTIONS = {
  IsolateFull: { param: { Isolate: "Full" }, summary: "Full network isolation requested" },
  IsolateSelective: { param: { Isolate: "Selective" }, summary: "Selective isolation requested" },
  ReleaseFromIsolation: { param: { ReleaseFromIsolation: true }, summary: "Release from isolation requested" },
  RestrictAppExecution: { param: { RestrictAppExecution: true }, summary: "App execution restriction requested" },
  RemoveAppExecutionRestriction: {
    param: { RemoveAppExecutionRestriction: true },
    summary: "Removal of app execution restriction requested",
  },
  ScanQuick: { param: { Scan: "Quick" }, summary: "Quick antivirus scan requested" },
  ScanFull: { param: { Scan: "Full" }, summary: "Full antivirus scan requested" },
  CollectInvestigationPackage: {
    param: { CollectInvestigationPackage: true },
    summary: "Investigation package collection requested",
  },
  CollectSupportLogs: { param: { CollectSupportLogs: true }, summary: "Support log collection requested" },
  ForceSync: { param: { ForceSync: true }, summary: "Policy/telemetry sync requested" },
  StartInvestigation: { param: { StartInvestigation: true }, summary: "Automated investigation requested" },
} as const;

type DeviceActionName = keyof typeof DEVICE_ACTIONS;

export const responseTools: XdrTool[] = [
  {
    name: "xdr_invoke_device_action",
    title: "Run a device response action",
    description:
      "Runs a Defender for Endpoint response action on one device: network isolation, release from " +
      "isolation, app execution restriction, antivirus scan, investigation package collection, " +
      "support log collection, telemetry sync, or automated investigation. These actions affect a " +
      "production endpoint and are visible to its user - isolation cuts the device off the network. " +
      "Confirm the device and the action with the operator before calling this, and record why in the " +
      "comment.",
    mutating: true,
    inputSchema: {
      device_id: z.string().min(1).describe("Defender for Endpoint device ID."),
      action: z
        .enum(Object.keys(DEVICE_ACTIONS) as [DeviceActionName, ...DeviceActionName[]])
        .describe(
          "IsolateFull cuts all network access except Defender; IsolateSelective keeps Outlook/Teams/Skype. " +
            "ScanQuick/ScanFull start an antivirus scan. CollectInvestigationPackage gathers forensic data.",
        ),
      comment: z.string().min(1).describe("Audit comment stored with the action, e.g. the incident ID and reason."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    handler: async ({ device_id, action, comment }) => {
      const selected = DEVICE_ACTIONS[action as DeviceActionName];
      if (!selected) return toolError(`Unknown action '${action}'.`);

      return runAction({
        command: "Invoke-XdrEndpointDeviceAction",
        params: { DeviceId: device_id, Comment: comment, ...selected.param },
        title: `Device action: ${action}`,
        summary: `${selected.summary} on device ${device_id}.`,
        notes: [
          "Track completion with xdr_get_device_action_results; the action is queued, not instant.",
          "Downloads for investigation packages and support logs are returned as URIs by that tool.",
        ],
      });
    },
  },
  {
    name: "xdr_start_automated_investigation",
    title: "Start an automated investigation",
    description:
      "Starts Defender for Endpoint automated investigation on a device, letting the service " +
      "triage and remediate on its own. Use it when a device needs broad automated triage rather than " +
      "a specific containment action.",
    mutating: true,
    inputSchema: {
      device_id: z.string().min(1).describe("Defender for Endpoint device ID."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    handler: async ({ device_id }) =>
      runAction({
        command: "Invoke-XdrEndpointDeviceAutomatedInvestigation",
        params: { DeviceId: device_id },
        title: "Automated investigation",
        summary: `Automated investigation started on device ${device_id}.`,
        notes: ["Approvals it raises appear in xdr_list_pending_actions."],
      }),
  },
  {
    name: "xdr_get_device_action_results",
    title: "Get device action results",
    description:
      "Lists the response actions queued or completed for a device and their status, and returns the " +
      "download URI for a collected investigation package or support log bundle. Use it to confirm " +
      "whether an isolation or collection actually landed.",
    inputSchema: {
      device_id: z.string().optional().describe("List every action for this device."),
      request_guid: z.string().optional().describe("Look up one specific action request."),
      download_investigation_package: z
        .boolean()
        .optional()
        .describe("Return the download URI for the collected investigation package."),
      download_support_logs: z
        .boolean()
        .optional()
        .describe("Return the download URI for the collected support logs."),
      response_format: responseFormatField,
      max_items: maxItemsField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async (args) => {
      if (!args.device_id && !args.request_guid) {
        return toolError("Provide device_id or request_guid.");
      }
      return runQuery({
        command: "Get-XdrEndpointDeviceActionResult",
        params: params({
          DeviceId: args.device_id,
          RequestGuid: args.request_guid,
          DownloadInvestigationPackage: args.download_investigation_package,
          DownloadSupportLogs: args.download_support_logs,
        }),
        title: "Device action results",
        format: args.response_format,
        maxItems: args.max_items,
        summaryFields: ["Type", "DeviceId", "Status", "Id", "RequestorComment", "CreationDateTimeUtc"],
        emptyMessage: "No matching device actions were found.",
      });
    },
  },
  {
    name: "xdr_cancel_device_action",
    title: "Cancel a pending device action",
    description:
      "Cancels a device response action that has not run yet, identified by its request GUID. Use it " +
      "to withdraw an action that was queued in error.",
    mutating: true,
    inputSchema: {
      request_guid: z.string().min(1).describe("Request GUID from xdr_get_device_action_results."),
      comment: z.string().optional().describe("Audit comment for the cancellation."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ request_guid, comment }) =>
      runAction({
        command: "Stop-XdrEndpointDeviceAction",
        params: params({ RequestGuid: request_guid, Comment: comment }),
        title: "Cancel device action",
        summary: `Cancellation requested for action ${request_guid}.`,
      }),
  },
  {
    name: "xdr_list_pending_actions",
    title: "List pending Action Center approvals",
    description:
      "Lists the actions waiting for approval in the Defender XDR Action Center, with the asset, " +
      "action type and originating investigation. Use it to see what automated remediation is blocked " +
      "on a human decision.",
    inputSchema: {
      sort_by: z
        .enum([
          "InvestigationId",
          "ApprovalId",
          "ActionType",
          "EntityType",
          "Asset",
          "Decision",
          "DecidedBy",
          "ActionSource",
          "Status",
          "ActionUpdateTime",
        ])
        .optional(),
      sort_order: z.enum(["Ascending", "Descending"]).optional(),
      page_size: z.number().int().min(1).max(1000).optional(),
      page_index: z.number().int().min(1).optional(),
      response_format: responseFormatField,
      max_items: maxItemsField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Get-XdrActionsCenterPending",
        params: params({
          SortByField: args.sort_by,
          SortOrder: args.sort_order,
          PageSize: args.page_size,
          PageIndex: args.page_index,
        }),
        title: "Pending Action Center approvals",
        format: args.response_format,
        maxItems: args.max_items,
        summaryFields: ["ApprovalId", "InvestigationId", "ActionType", "EntityType", "Asset", "Status", "ActionUpdateTime"],
        emptyMessage: "Nothing is waiting for approval.",
      }),
  },
  {
    name: "xdr_list_action_history",
    title: "List Action Center history",
    description:
      "Lists completed Defender XDR Action Center entries: what was remediated, by whom or by which " +
      "automation, and when. Use it to reconstruct the response timeline for an incident report.",
    inputSchema: {
      months: z.number().int().min(1).max(24).optional().describe("Months of history to include."),
      from_date: z.string().optional().describe("ISO 8601 start time. Use instead of months."),
      to_date: z.string().optional().describe("ISO 8601 end time."),
      sort_by: z
        .enum([
          "InvestigationId",
          "ApprovalId",
          "ActionType",
          "EntityType",
          "Asset",
          "Decision",
          "DecidedBy",
          "ActionSource",
          "Status",
          "ActionUpdateTime",
        ])
        .optional(),
      sort_order: z.enum(["Ascending", "Descending"]).optional(),
      page_size: z.number().int().min(1).max(1000).optional(),
      page_index: z.number().int().min(1).optional(),
      response_format: responseFormatField,
      max_items: maxItemsField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Get-XdrActionsCenterHistory",
        params: params({
          Months: args.from_date ? undefined : args.months,
          FromDate: args.from_date,
          ToDate: args.to_date,
          SortByField: args.sort_by,
          SortOrder: args.sort_order,
          PageSize: args.page_size,
          PageIndex: args.page_index,
        }),
        title: "Action Center history",
        format: args.response_format,
        maxItems: args.max_items,
        summaryFields: ["ApprovalId", "ActionType", "EntityType", "Asset", "Decision", "DecidedBy", "Status", "ActionUpdateTime"],
        emptyMessage: "No historical actions were returned for this window.",
      }),
  },
];
