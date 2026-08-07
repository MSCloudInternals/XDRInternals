# XDRInternals MCP server

An MCP server that exposes Microsoft Defender XDR **security incident investigation, incident
handling and threat hunting** to an MCP client (Claude Code, Claude Desktop, or anything else that
speaks MCP), backed by the [XDRInternals](../README.md) PowerShell module.

Sign-in is interactive and reuses the person at the keyboard: `/mcp__xdr__login` signs in with the
account already signed in on the machine, and a manually supplied `sccauth` / `ESTSAUTH` cookie is
also accepted.

## How it works

```
MCP client  ──stdio/JSON-RPC──▶  node dist/index.js  ──JSON lines──▶  pwsh XdrMcpHost.ps1
                                 (40 tools, 7 prompts)                (one long-lived runspace
                                                                       with XDRInternals imported)
```

XDRInternals keeps its portal cookies, XSRF token and cache in PowerShell module scope, so the
server keeps **one** PowerShell runspace alive for its whole lifetime. Sign in once and every later
tool call reuses that session. Requests are serialized (the runspace runs one pipeline at a time)
and every PowerShell stream is captured per request, so `Write-Host` output from the module can
never corrupt the protocol.

## Requirements

- PowerShell 7.2+ (`pwsh` on `PATH`, or set `XDR_MCP_PWSH`)
- Node.js 20+
- The XDRInternals module: this checkout is used automatically, otherwise `Install-Module XDRInternals`

## Install

```bash
cd mcp && npm install && npm run build
```

Verify the bridge and tool wiring without an MCP client:

```bash
node dist/index.js --smoke-test
```

## Register with Claude Code

This repository ships a project-scoped [`.mcp.json`](../.mcp.json), so opening the repo in Claude
Code offers the server as `xdr` (approve it once when prompted).

To register it for every project instead:

```bash
claude mcp add xdr --scope user -- node "C:/path/to/XDRInternals/mcp/dist/index.js"
```

Claude Desktop / other clients use the same command:

```json
{
  "mcpServers": {
    "xdr": {
      "command": "node",
      "args": ["C:/path/to/XDRInternals/mcp/dist/index.js"]
    }
  }
}
```

## Signing in

The server holds no credentials of its own. Four paths, in order of preference:

| Path | Tool | Slash command | Notes |
| --- | --- | --- | --- |
| Single sign-on | `xdr_auth_login_sso` | `/mcp__xdr__login` | Reuses the account already signed in on this machine. Headless by default. Pass `tenant_id` for multi-tenant accounts. |
| Interactive browser | `xdr_auth_login_browser` | `/mcp__xdr__login` (fallback) | Opens a browser window for MFA, passkey or Temporary Access Pass. |
| Cookie you supply | `xdr_auth_connect_with_token` | `/mcp__xdr__use-token` | `sccauth` (default) or `estsauth`. Reads `XDR_SCCAUTH` / `XDR_ESTSAUTH` when no value is passed. |
| Environment, at startup | – | – | Set `XDR_MCP_AUTO_CONNECT=1` with `XDR_SCCAUTH` or `XDR_ESTSAUTH`. |

`/mcp__xdr__status` reports the account, tenant and how the session was established.
`/mcp__xdr__logout` recreates the runspace, which drops the cookies, cached tenant data and any open
Live Response sessions.

> A cookie passed as a tool or prompt argument is stored in the conversation transcript. Prefer SSO,
> or put the value in `XDR_SCCAUTH` so it never enters the conversation.

## Tools

**Session** — `xdr_auth_status`, `xdr_auth_login_sso`, `xdr_auth_login_browser`,
`xdr_auth_connect_with_token`, `xdr_auth_logout`, `xdr_list_tenants`

**Incidents** — `xdr_list_incidents`, `xdr_get_incident`, `xdr_get_incident_alerts`,
`xdr_merge_incidents`*, `xdr_move_alerts_to_incident`*

**Alerts and detections** — `xdr_list_alerts`, `xdr_list_suppression_rules`,
`xdr_list_detection_rules`

**Threat hunting** — `xdr_run_hunting_query`, `xdr_get_hunting_schema`,
`xdr_validate_hunting_query`, `xdr_list_hunting_functions`

**Entities and timelines** — `xdr_list_devices`, `xdr_get_device`, `xdr_get_device_timeline`,
`xdr_list_identities`, `xdr_get_identity`, `xdr_get_identity_timeline`,
`xdr_get_cloudapps_activity`

**Response handling** — `xdr_invoke_device_action`*, `xdr_start_automated_investigation`*,
`xdr_get_device_action_results`, `xdr_cancel_device_action`*, `xdr_list_pending_actions`,
`xdr_list_action_history`

**Live Response** — `xdr_liveresponse_connect`*, `xdr_liveresponse_run_command`*,
`xdr_liveresponse_disconnect`*

**Context and coverage** — `xdr_get_threat_analytics_outbreaks`, `xdr_get_attack_paths`,
`xdr_list_cmdlets`, `xdr_get_cmdlet_help`, `xdr_run_cmdlet`, `xdr_invoke_rest_method`

`*` changes tenant state. These are annotated `destructiveHint` where relevant and are **not
registered at all** when `XDR_MCP_READONLY=1`.

The 40 curated tools cover investigation, handling and hunting. Everything else the module can do
(vulnerability management, exposure recommendations, tenant configuration, Cloud Apps policies,
datalake schema, …) stays reachable through `xdr_list_cmdlets` → `xdr_get_cmdlet_help` →
`xdr_run_cmdlet`, which only accepts read-only cmdlets (`Get-Xdr*` plus the hunting and validation
cmdlets). `xdr_invoke_rest_method` is the last resort for portal APIs with no cmdlet; it is
restricted to `https://*.security.microsoft.com` and to `GET` unless
`XDR_MCP_ALLOW_REST_WRITE=1`.

## Prompts (slash commands)

| Prompt | Command | Purpose |
| --- | --- | --- |
| `login` | `/mcp__xdr__login [tenant_id]` | Sign in, SSO first with an interactive fallback |
| `use-token` | `/mcp__xdr__use-token [token] [token_type]` | Sign in with a cookie you provide |
| `status` | `/mcp__xdr__status` | Who am I signed in as |
| `logout` | `/mcp__xdr__logout` | Drop the session |
| `investigate-incident` | `/mcp__xdr__investigate-incident <incident_id>` | Full investigation workflow with a written assessment |
| `hunt` | `/mcp__xdr__hunt <hypothesis> [days]` | Structured hunt: schema check, validation, bounded queries, triage |
| `triage-queue` | `/mcp__xdr__triage-queue [days]` | Ranked triage of open incidents and alerts |

## Response shape and context budget

Every read tool takes `response_format`, `max_items` and usually `properties`:

- `markdown` (default) returns a compact summary table of the fields that matter for that record
  type — cheap to read, and enough to decide what to pull next.
- `json` returns the complete records.
- Records are dropped from the tail until the response fits `XDR_MCP_MAX_CHARS`, with an explicit
  note saying so, rather than flooding the context window.

Tools return text content only. Structured output (`structuredContent`) is deliberately not used:
it would duplicate large security payloads in the same response.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `XDR_MODULE_PATH` | this checkout, else `XDRInternals` | Module name or path to `XDRInternals.psd1` |
| `XDR_MCP_PWSH` | `pwsh` | PowerShell 7 executable |
| `XDR_MCP_READONLY` | off | Hide every state-changing tool |
| `XDR_MCP_ALLOW_REST_WRITE` | off | Allow non-`GET` in `xdr_invoke_rest_method` |
| `XDR_MCP_MAX_CHARS` | `45000` | Response character budget |
| `XDR_MCP_MAX_ITEMS` | `50` | Default records per call |
| `XDR_MCP_TIMEOUT_SECONDS` | `300` | Default cmdlet timeout |
| `XDR_MCP_LONG_TIMEOUT_SECONDS` | `900` | Timeout for hunts and timeline pulls |
| `XDR_MCP_LOGIN_TIMEOUT_SECONDS` | `600` | Timeout for interactive sign-in |
| `XDR_SCCAUTH`, `XDR_XSRF` | – | Portal cookie used by `xdr_auth_connect_with_token` |
| `XDR_ESTSAUTH` | – | Entra ID cookie used by `xdr_auth_connect_with_token` |
| `XDR_TENANT_ID` | – | Default tenant for cookie sign-in |
| `XDR_MCP_AUTO_CONNECT` | off | Connect at startup from the environment cookie |

Long operations can exceed a client's tool timeout. In Claude Code, raise `MCP_TOOL_TIMEOUT`
(milliseconds) for the session if a device timeline or a wide hunt is cut short.

## Safety notes

- The module talks to **undocumented** portal APIs. Everything inherits the parent project's
  disclaimer: unofficial, unsupported, and subject to change without notice.
- Tool calls run with the signed-in operator's Defender XDR permissions. RBAC still applies; a
  `403` means the role, not the server, is the limit.
- State-changing tools are described so the model asks first. Isolation cuts a production endpoint
  off the network, merges cannot be undone, and Live Response executes on a live endpoint — the
  server does not gate these on its own, so run with `XDR_MCP_READONLY=1` for
  investigation-only use.
- Cookies never appear in tool output or logs. The bridge writes only protocol JSON to stdout and
  diagnostics to stderr.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Could not start PowerShell ('pwsh')` | Install PowerShell 7 or set `XDR_MCP_PWSH` to its full path |
| `Failed to import the XDRInternals module` | Point `XDR_MODULE_PATH` at `XDRInternals.psd1`, or `Install-Module XDRInternals` |
| `No authenticated Defender XDR session` | Run `/mcp__xdr__login`, or `xdr_auth_status` to see the current state |
| Sign-in reports a tenant prompt | Pass `tenant_id`; console prompts cannot be answered from here |
| Everything returns `401` after a while | Portal cookies expired — sign in again |
| `The operation did not return within …` | Narrow the time window or page size, or raise `XDR_MCP_TIMEOUT_SECONDS` |

Run `npm run inspect` to drive the server from the MCP Inspector, or `node dist/index.js
--smoke-test` to check the PowerShell bridge in isolation.
