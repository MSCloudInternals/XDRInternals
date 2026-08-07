import { z } from "zod";
import { config } from "../config.js";
import { maxItemsField, params, responseFormatField, runAction, runQuery, type XdrTool } from "../toolkit.js";

export const liveResponseTools: XdrTool[] = [
  {
    name: "xdr_liveresponse_connect",
    title: "Open a Live Response session",
    description:
      "Opens a non-interactive Defender for Endpoint Live Response session to a device and returns the " +
      "session ID used by the command tool. Live Response runs code on a production endpoint and is " +
      "audited; only one session per device is allowed at a time. Close it with " +
      "xdr_liveresponse_disconnect when the investigation step is done.",
    mutating: true,
    inputSchema: {
      device_id: z.string().min(1).describe("Defender for Endpoint device ID."),
      device_name: z.string().optional().describe("Device name, used only for nicer output."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    handler: async ({ device_id, device_name }) =>
      runAction({
        command: "Connect-XdrEndpointDeviceLiveResponse",
        params: params({
          DeviceId: device_id,
          DeviceName: device_name,
          NonInteractive: true,
          NoStatusTable: true,
        }),
        title: "Live Response session",
        summary: `Live Response session requested for device ${device_name ?? device_id}.`,
        timeoutSeconds: config.longTimeoutSeconds,
        notes: [
          "Use the SessionId with xdr_liveresponse_run_command.",
          "Sessions consume a device slot until disconnected.",
        ],
      }),
  },
  {
    name: "xdr_liveresponse_run_command",
    title: "Run a Live Response command",
    description:
      "Runs one Live Response command in an open session and returns its output. Read-only commands " +
      "(processes, services, drivers, connections, dir, persistence, fileinfo, registry) are the " +
      "backbone of live endpoint triage; commands such as remediate, putfile and run execute changes " +
      "or scripts on the endpoint, so confirm those with the operator first. Table-style output is " +
      "expanded into rows by default.",
    mutating: true,
    inputSchema: {
      session_id: z.string().min(1).describe("Session ID from xdr_liveresponse_connect."),
      command: z
        .string()
        .min(1)
        .describe("Live Response command line, e.g. 'processes', 'dir C:\\\\Users', 'fileinfo C:\\\\a.exe'."),
      current_directory: z.string().optional().describe("Working directory for the command."),
      device_id: z.string().optional().describe("Device ID, used for output labelling."),
      device_name: z.string().optional().describe("Device name, used for output labelling."),
      raw_output: z
        .boolean()
        .optional()
        .describe("Return the raw API command result instead of expanded table rows."),
      timeout_seconds: z.number().int().min(30).max(1800).optional().describe("Command timeout."),
      response_format: responseFormatField,
      max_items: maxItemsField,
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Invoke-XdrEndpointDeviceLiveResponseCommand",
        params: params({
          SessionId: args.session_id,
          Command: args.command,
          CurrentDirectory: args.current_directory,
          DeviceId: args.device_id,
          DeviceName: args.device_name,
          RawCommandResult: args.raw_output,
          ExpandTableOutput: !args.raw_output,
          TimeoutSeconds: args.timeout_seconds,
        }),
        title: `Live Response: ${args.command}`,
        format: args.response_format,
        maxItems: args.max_items,
        timeoutSeconds: (args.timeout_seconds ?? 300) + 120,
        depth: 8,
        emptyMessage: "The command produced no output.",
      }),
  },
  {
    name: "xdr_liveresponse_disconnect",
    title: "Close a Live Response session",
    description:
      "Closes an open Live Response session and frees the device slot. Always call this when the live " +
      "triage step is finished.",
    mutating: true,
    inputSchema: {
      session_id: z.string().min(1).describe("Session ID to close."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    handler: async ({ session_id }) =>
      runAction({
        command: "Disconnect-XdrEndpointDeviceLiveResponse",
        params: { SessionId: session_id },
        title: "Live Response session closed",
        summary: `Session ${session_id} disconnected.`,
      }),
  },

  // ── Library management ────────────────────────────────────────────────────

  {
    name: "xdr_liveresponse_library_list",
    title: "List Live Response library files",
    description:
      "Lists all script and binary files in the tenant's Live Response library. Results are cached for " +
      "15 minutes; pass force: true to bypass the cache after an upload or delete.",
    inputSchema: {
      force: z.boolean().optional().describe("Bypass the 15-minute cache and fetch fresh results."),
      response_format: responseFormatField,
      max_items: maxItemsField,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    handler: async (args) =>
      runQuery({
        command: "Get-XdrEndpointDeviceLiveResponseLibrary",
        params: params({ Force: args.force }),
        title: "Live Response library",
        format: args.response_format,
        maxItems: args.max_items,
        emptyMessage: "The Live Response library is empty.",
      }),
  },

  {
    name: "xdr_liveresponse_library_upload",
    title: "Upload a file to the Live Response library",
    description:
      "Uploads a local script or binary file to the tenant's Live Response library. Once uploaded the " +
      "file can be pushed to endpoints with the 'putfile' command or executed with 'run' inside a Live " +
      "Response session. file_path must be a path on the machine running the MCP server. Use " +
      "override_if_exists to replace an existing file with the same name.",
    mutating: true,
    inputSchema: {
      file_path: z.string().min(1).describe("Full path to the local file to upload (on the MCP server machine)."),
      description: z.string().optional().describe("Short description shown in the library listing."),
      has_parameters: z
        .boolean()
        .optional()
        .describe("Set to true when the script accepts parameters during 'run' execution."),
      parameters_description: z
        .string()
        .optional()
        .describe("Description of the parameters the script accepts, e.g. '-TargetProcess <string>'."),
      override_if_exists: z
        .boolean()
        .optional()
        .describe("Overwrite the existing library file if one with the same name already exists."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    handler: async (args) =>
      runAction({
        command: "New-XdrEndpointDeviceLiveResponseLibraryFile",
        params: params({
          FilePath: args.file_path,
          Description: args.description,
          HasParameters: args.has_parameters,
          ParametersDescription: args.parameters_description,
          OverrideIfExists: args.override_if_exists,
        }),
        title: "Library file uploaded",
        summary: `File uploaded to the Live Response library from ${args.file_path}.`,
        notes: [
          "Use xdr_liveresponse_library_list (with force: true) to confirm the file appears.",
          "Push it to a device with: putfile <filename> inside a Live Response session.",
        ],
      }),
  },

  {
    name: "xdr_liveresponse_library_delete",
    title: "Delete a file from the Live Response library",
    description:
      "Permanently removes a file from the tenant's Live Response library by name. This cannot be undone; " +
      "confirm the file name with xdr_liveresponse_library_list before proceeding.",
    mutating: true,
    inputSchema: {
      file_name: z.string().min(1).describe("Exact file name as shown in the library listing, e.g. 'Remediate.ps1'."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    handler: async ({ file_name }) =>
      runAction({
        command: "Remove-XdrEndpointDeviceLiveResponseLibraryFile",
        params: { FileName: file_name, Confirm: false },
        title: "Library file deleted",
        summary: `${file_name} removed from the Live Response library.`,
      }),
  },
];
