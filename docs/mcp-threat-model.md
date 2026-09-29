# Read-only MCP release candidate threat model

Status: review draft for `1.0.0-rc.1`. Applies only to the local stdio server with one operator, one dedicated Defender account, and the fourteen tools documented in [the MCP README](../mcp/README.md). Linux software-passkey and interactive Microsoft Edge browser sign-in have been live-tested. This is not a shared service or a multi-tenant authorization system.

## Boundaries

1. The MCP client and model are untrusted callers. They may choose only documented tool names and bounded scalar arguments. They cannot provide PowerShell commands, URLs, tenant IDs, file paths, queries, tokens, or cookies.
2. The Node bridge starts one persistent PowerShell process; each JSON-line request is serialized, has a deadline, and is checked again by the PowerShell dispatcher. The dispatcher calls fixed XDRInternals read cmdlets and projects a limited set of fields. Tool results are treated as untrusted evidence by the model.
3. The Defender portal and the local credential file are outside MCP. The passkey path is a trusted process-start environment setting, never a tool argument. Browser sign-in is opt-in and has been live-tested in a local graphical Linux session.
4. The operator's MCP client may send results to an AI provider or to other configured tools. Read-only does not mean non-sensitive: incident, identity, device and policy fields can disclose tenant information.

## Controls and evidence

| Threat | Control | Evidence |
| --- | --- | --- |
| Caller requests a write, raw REST call, file output, or arbitrary cmdlet | No such registered operation; exact operation and argument allowlists in the host | Offline dispatcher and MCP protocol denial tests |
| Upstream fetches more data than MCP returns | Data reads use explicit single-page paths; associated alerts use the new page mode, identity detail uses resolve-only mode; the fixed schema catalog is projected to one exact table and 50 columns | Focused Pester tests, fixture checks and sanitized live stdio calls |
| An upstream record includes a credential or nested payload | Fixed scalar projection, bounded string length, strict TypeScript output schemas and frame limit checked before host emission | Hidden-credential, malformed-result and oversized serialized-page tests |
| Error or authentication stream leaks secrets | Authentication streams suppressed; upstream failures mapped to stable error codes; stderr not forwarded as tool output | Fixture auth/error tests |
| Stale credentials continue serving cached data after known authorization failure | Structured HTTP 401/403 revokes the process session and clears the cache; error text cannot trigger revocation | Authorization-revocation fixtures and real-cmdlet status propagation tests for the original eleven read paths |
| Confused-deputy entity lookup | Device ID, identity object ID and SID checked against the result; UPN checked if present | Wrong-target fixture tests; live device and existing identity lookup checks; SID lookup is offline-tested only |
| A stalled read occupies the serialized bridge | Six-minute deadline only for initial sign-in, 60 seconds for subsequent reads including queue time, at most eight outstanding calls | Deadline and queue regression tests |
| Untrusted portal text becomes instructions | Tool descriptions mark results as evidence; no tool executes a command based on returned text | MCP inventory is read-only; operator must still configure client approvals and data handling |

## Residual risks and review questions

- The host does not independently verify the authenticated account and tenant after refresh. Restrict this release to a dedicated least-privileged operator account and local stdio; do not use it through a shared proxy. Multi-tenant use and all Defender mutations remain outside scope.
- Browser authentication was live-tested with Microsoft Edge on Linux; other browser and operating-system combinations have not received the candidate's live validation.
- The live pending-actions page was empty. Its populated-record mapping has fixture coverage but no live populated-page evidence.
- The live timeline window was empty. Its request succeeded, but the populated event projection is fixture-tested only. Schema lookup fetched 70 columns upstream for `DeviceEvents`, projected 50, and flagged truncation. Schema reads fetch the portal catalog before selecting one table; only the MCP output, not the upstream response, is column-bounded.
- The passkey establishes a Defender portal session, not an API-scoped OAuth token. Public MTP/WDATP file/IP/domain/user and device-alert API reads, as well as arbitrary hunting, are not claimed as implemented or live-tested.
- PowerShell cmdlets depend on portal APIs that can change shape, semantics, or permissions. Strict projections fail closed on wrong types, but absent optional fields can still return null. Monitor live checks before publishing a final release.
- Portal text can carry prompt injection even though the server cannot execute writes. An AI client with unrelated tools could exfiltrate read data. Review client approvals, logs, model-provider retention, local file permissions, and tenant policy before enabling access.
- The passkey file is a local secret whose permissions and rotation are managed by the operator. Never place its contents in MCP arguments, repository configuration, test output, or issue reports.

Release reviewers should confirm that the fixed tool inventory matches the documented fourteen reads, no exported operation calls a mutation or writes a local file, the focused Pester and MCP tests pass, and the live test emits only status/count data for a dedicated test account.