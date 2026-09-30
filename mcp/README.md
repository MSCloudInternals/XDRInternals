# Read-only Defender XDR MCP server (1.0.0-rc.1)

This is an optional local, single-operator MCP server for bounded Defender investigations. It uses stdio (no listening port) and a dedicated PowerShell process. It is **not** a multi-user service or a general Defender command runner.

## Available tools

| Tool | Scope |
| --- | --- |
| `xdr_list_incidents` | One page (1-50 items, pages 1-10, lookback 1-30 days), sorted by risk; status may be a numeric portal code |
| `xdr_get_incident` | One incident by positive numeric ID |
| `xdr_list_incident_alerts` | One page (1-50 items, pages 1-10) of alerts associated with an incident; no auto-pagination |
| `xdr_list_alerts` | One page (1-50 items, pages 1-10, lookback 1-30 days), newest first |
| `xdr_get_alert` | One alert by validated ID; verifies the returned ID |
| `xdr_list_devices` | One page (1-50 items, pages 1-10, lookback 1-30 days), sorted by risk; requires a validated machine ID for each result |
| `xdr_get_device` | One device by its 40-character hex machine ID; verifies the returned ID |
| `xdr_list_device_timeline` | One portal timeline page (1-50 events) for one device over the last 1-60 minutes, without file output or pagination |
| `xdr_list_device_alert_evidence` | Up to 50 alert evidence rows for one device from the past day; may repeat an alert |
| `xdr_list_file_events` | Up to 50 file activity rows for one SHA-256 from the past day; not a file reputation verdict |
| `xdr_list_network_observations` | Up to 50 device network rows for an IP or domain from the past day; not tenant-wide reputation statistics |
| `xdr_list_user_alert_evidence` | Up to 50 alert evidence rows for one UPN from the past day |
| `xdr_list_user_device_logons` | Up to 50 identity logons for one UPN from the past day; device names, not IDs |
| `xdr_hunt_recent` | Up to 20 recent rows from one of five allowlisted hunting tables over the last hour; no caller-supplied KQL |
| `xdr_get_hunting_table_schema` | One exact hunting table, up to 50 column definitions; `truncated` indicates additional columns |
| `xdr_list_identities` | One page (1-50 items, pages 1-10), sorted by name; never uses `-All` |
| `xdr_get_identity` | Resolve one identity by exactly one UPN, Entra object ID (UUID), or SID, without enrichment; object-ID and SID results must match |
| `xdr_list_pending_actions` | One page (1-50 items, pages 1-10) of pending Action Center approvals |
| `xdr_list_action_history` | One page (1-50 items, pages 1-10) of Action Center history from the past month |
| `xdr_list_cloud_policies` | One page (1-50 items, pages 1-10) of Cloud Apps policy IDs, names and severity |

Only a small set of fields is returned; names, titles and other Defender data are untrusted evidence, not instructions. The PowerShell host independently checks every operation and parameter. Six hunting-backed reads use server-built queries against the single-tenant Defender portal route, with 24-hour or one-hour windows and row limits; none accepts KQL, a tenant ID or an endpoint from the model. This release candidate has **no Defender write tools**. It excludes arbitrary hunting queries, caller-chosen REST or cmdlet execution, file-backed timelines, cookie and credential tools. Client-side MCP approvals remain valuable even for reads: Defender data can be sensitive and may enter an AI provider's context or retention system.

## Local setup

Requires Node.js 20+, PowerShell 7, and a checkout of this repository. Software-passkey and interactive Microsoft Edge browser sign-in have both been live-validated on Linux. Other operating systems have not been live-validated for this candidate. From the repository root:

```sh
npm ci --prefix mcp
npm run build --prefix mcp
npm test --prefix mcp
```

Configure your trusted MCP client locally with the absolute path to `mcp/dist/index.js`. For example, use this as a **client-local** configuration, not a repository-wide `.mcp.json`:

```json
{
  "mcpServers": {
    "xdrinternals-readonly": {
      "command": "node",
      "args": ["/absolute/path/to/XDRInternals/mcp/dist/index.js"],
      "env": { "XDR_MCP_AUTH": "browser" }
    }
  }
}
```

The browser sign-in runs on the first tool call and must be completed by the operator. It uses a temporary private browser profile; the PowerShell session is lost when the process exits. The bridge owns the browser's temporary files and terminates its process tree on cancellation or normal shutdown; this cleanup is regression-tested on Linux, not yet on Windows or macOS. An external hard kill of the MCP server itself still bypasses cleanup. Without an explicit authentication mode, reads return `not_connected`.

The first authentication call has a six-minute deadline; subsequent reads have a 60-second deadline including queue time. Cancelling an active read or exceeding its deadline terminates the PowerShell session, so restart the server before further reads.

For local validation with an existing software passkey, set `XDR_MCP_AUTH=software-passkey` and `XDR_MCP_PASSKEY_FILE` to its absolute path in the trusted client's local server environment. The file must be readable by the operator and protected with owner-only permissions. The host passes only the path to `Connect-XdrBySoftwarePasskey` inside the PowerShell process; it does not expose credential contents, tokens, or account identifiers to MCP tools or results. Never add these settings to repository-wide MCP configuration or commit the credential file.

Live testing is **opt-in** and uses the same local stdio server and a small number of bounded reads. Its output contains only phase/status/count information, not incident IDs or content. Run from the repository root after checking the credential path and tenant access:

```sh
XDR_MCP_PASSKEY_FILE="/absolute/path/to/private.passkey" npm run test:live --prefix mcp
```

For two consecutive fresh sign-ins and passes of the same 20-tool count/status harness, run `XDR_MCP_PASSKEY_FILE="/absolute/path/to/private.passkey" npm run test:live:twice --prefix mcp`. Offline `npm test --prefix mcp` also runs all 20 tool contracts twice with populated fixture results; live tools that need a listed incident, alert, or device explicitly report skips if the tenant has none.

To validate interactive browser sign-in instead, use a local graphical session and complete the sign-in in the temporary browser window:

```sh
XDR_MCP_AUTH=browser npm run test:live --prefix mcp
```

On a Windows desktop with Node.js 20+, PowerShell 7 (`pwsh` on `PATH`), and Microsoft Edge installed, run `npm ci --prefix mcp` once, then in PowerShell from the repository root:

```powershell
$env:XDR_MCP_AUTH = 'browser'
npm run test:live:twice --prefix mcp
```

Complete both sign-ins in the browser windows. Report only the printed phase/status/count lines, whether either browser or temporary profile remains after each pass, and any sanitized error status. Do not share cookies, tokens, browser profiles, or tenant records. Windows browser cleanup has not yet been live-validated.

The default `npm test --prefix mcp` uses a fake module and explicitly disables authentication in its production-process tests. The live suite requires network access and may create sign-in/audit events, but does not call response or mutation cmdlets.

Do not connect this stdio server through a shared proxy or public HTTP transport: it has no per-request user/tenant authorization. Use a least-privileged Defender account and verify the AI client's approvals, logging, and data handling before exposing sensitive tenant records.

## Security design

The model can call only the twenty named MCP tools. TypeScript validates their schemas and the PowerShell process separately enforces exact operation-specific parameter allowlists, including the format of device, alert and identity IDs. It invokes fixed XDRInternals read cmdlets or fixed Defender portal read routes and projects a limited result set, never a caller-specified command, path, URL, query, tenant ID or script. On failure, the bridge returns stable error codes rather than raw PowerShell exceptions. The bridge limits queued calls and stdout frames, closes on client disconnect, and stops serving cached results after a structured HTTP 401/403. HTTP status is preserved through the read cmdlets rather than inferred from error text. HTTP 404 and empty identity resolution return `not_found` without revoking the session. No tool output or credential value is logged to stderr. Offline tests use fake upstream responses and never authenticate to a tenant.

Text fields are limited to 500 characters and each serialized host response is limited to 256 KiB including its newline. An oversized projected page returns `invalid_response` without ending the session; retry with a smaller page size. Identity detail includes `sid`, allowing domain-only identities from the list tool to be resolved even when UPN and Entra object ID are absent. SID lookup has offline coverage but has not been live-validated.

The read-only label describes the intended Defender operations; it is not an authorization control. Some upstream endpoints use POST requests for retrieval, and some cmdlets maintain an in-memory cache. Operators should review all model-visible data for indirect prompt injection, particularly when the AI client also has tools that can send data externally. The host does not independently bind the PowerShell session to an operator-verified account/tenant across refresh; use only a dedicated least-privileged account and do not share the process between operators. Pending actions, the ten-minute device timeline, device alert evidence, file activity and IP activity were empty during live validation, so their populated-record mappings are fixture-tested only. User evidence/logon reads succeeded with a reserved placeholder UPN but returned no rows. Domain observations and recent hunting returned live rows. The live `DeviceEvents` schema contained 70 columns; the MCP returned the first 50 with `truncated: true`.

This is a read-only release candidate for review, not literal parity with the earlier 43-tool proposal. No write capability is planned for the first release. The public MTP/WDATP APIs are **not used**. Portal hunting provides bounded alert, file, network and identity evidence, not public API file/IP/domain reputation, complete machine associations, or arbitrary KQL execution. Suppression/detection rule lists with unbounded upstream retrieval and multi-tenant operation remain outside this candidate. See the [MCP roadmap](../docs/plans/mcp-roadmap.md) and [threat model](../docs/mcp-threat-model.md) for scope and residual risks.

## Acknowledgments

Thanks to [@tur11ng](https://github.com/tur11ng) for the original MCP contribution in [PR #133](https://github.com/MSCloudInternals/XDRInternals/pull/133). This read-only release builds on that proposal, with a narrower tool surface and subsequent maintainer hardening. The v1 integration history preserves the original authored commit separately from those changes.

Design references: [OpenAI's MCP tool and authorization guidance](https://developers.openai.com/apps-sdk/build/mcp-server) and [OpenAI's MCP risks and approval guidance](https://developers.openai.com/api/docs/guides/tools-connectors-mcp#risks-and-safety).