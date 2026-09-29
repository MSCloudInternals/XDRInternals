# XDRInternals MCP roadmap

Status: `1.0.0-rc.1` read-only release candidate for review. Twenty bounded reads cover incident/alert navigation, device/identity lookup, fixed portal hunting pivots, Action Center status, and Cloud Apps policies. Software-passkey and interactive Microsoft Edge browser sign-in have both been live-tested on Linux. PR #133's 43 tools are an inventory of possible workflows, not a release target.

## Release principle

The first release is **read-only**. An analyst can find an incident, follow its alerts, look up devices and identities, review response state, and inspect Cloud Apps policy summaries. There are no Defender write tools, arbitrary hunting queries, caller-chosen portal HTTP, arbitrary PowerShell commands, host-file tools, cookie strings, or Live Response commands. A workflow blocked by an unsafe underlying cmdlet needs a bounded implementation and tests, not an MCP-only wrapper that renames the risk.

We do **not** promise literal parity with every PR tool. Client approval UI and tool descriptions are useful defense in depth, never the sole permission check. Sources: [OpenAI MCP server guidance](https://developers.openai.com/apps-sdk/build/mcp-server), [OpenAI MCP risks and safety](https://developers.openai.com/api/docs/guides/tools-connectors-mcp#risks-and-safety).

## First release: read-only coverage

The candidate ships the following workflows; excluded capabilities are not counted as release blockers for this scoped read-only release.

| PR area | First-release workflows and gating | Deliberate exclusions |
| --- | --- | --- |
| Session | One local operator; opt-in passkey or browser startup; no model-supplied secrets. | No multi-tenant selection, session control tool, or per-request HTTP authentication. |
| Incidents and alerts | Bounded incident list/detail, alert list/detail, and one page of incident-associated alerts. | No merges, moves, or auto-pagination through MCP. |
| Entities | Bounded device list/detail and one-page, at-most-one-hour portal timeline; identity list/resolve-only detail; fixed portal alert, file, IP, domain and user evidence pivots. | No file-backed timelines, public API reputation verdicts or enrichment fan-out. |
| Response state | Pending approvals and one month of Action Center history, read-only. | No approval, isolation, cancellation, or other tenant mutations. |
| Cloud Apps | One page of policy metadata. | No policy edits, activity timelines, or unbounded governance lists. |
| Hunting and advanced | One exact table's schema, up to 50 columns with a truncation flag; recent rows from five allowlisted tables over one hour. | No arbitrary query execution, 10,000-record rule fetches, or attack-path calls that reset the session. |

The module exports many more commands than an analyst needs in one model session. Additional reads require direct bounds, result-shape tests and a single-tenant safety review.

## Release gates

1. **Command contract:** each tool maps to one fixed, documented host operation; allowlist operation **and** parameters at the PowerShell boundary. Reject unknown/missing fields, non-scalar values, paths, URLs, raw bodies, and command names. Bound upstream work (time, page, tenant, query cost), serialized bytes, rows, and errors. Count a tool as read-only only if its cmdlet cannot mutate the tenant or write local files under its allowed parameters. `Get-` naming and HTTP GET/POST are not proofs.
2. **Identity contract:** operator-initiated sign-in using a dedicated least-privileged account. No credentials/cookies as MCP arguments, resources, prompts, structured results, or logs. Stdio is a single-user transport; do not put it behind a shared HTTP server. Account/tenant re-verification across refresh is not implemented; multi-tenant and write access are therefore excluded.
3. **No-write contract:** neither the MCP manifest nor the PowerShell dispatcher has a Defender mutation operation. The host rejects unknown operations and extra parameters. No future write capability belongs in the first release, including a tool guarded only by a confirmation flag.
4. **Evidence contract:** project only necessary fields, mark Defender strings as untrusted content, cap output, preserve UTC timestamps, and redact raw errors. Read-only access can still leak confidential tenant information into an AI provider or through a different tool. Document client approval/data-retention settings and test prompt-injection text as inert data.
5. **Quality contract:** fixture tests for every mapping, policy denial, errors, paging, and output shape; protocol tests for advertised schemas and annotations. CI runs Node and PowerShell tests; lockfile/audit/Dependabot checks and opt-in sanitized live tests cover the supported configuration. Do not turn on writes merely to meet a tool count.

## Delivery sequence

1. **RC review:** twenty fixed bounded reads, fixture/protocol/PowerShell tests, Linux passkey and Edge browser live checks, CI and dependency audit. Several evidence pivots had empty live pages, so their populated projections are fixture-tested only. Other operating systems are not claimed as live-verified.
2. **Later reads:** stay with the project portal session; improve portal-only activity and identity pivots where upstream routes support direct bounds, and paginate detection and suppression rule retrieval upstream. Arbitrary hunting is not included: the current tools generate fixed single-tenant queries with explicit time, row and byte budgets.
3. **Later auth:** explicit operator-visible sign-in/status/logout lifecycle, verified account and tenant across refresh, isolated sessions and caches for each principal, and cross-tenant denial tests. No cookie-valued tool argument.
4. **Beyond first release:** only a separately designed, independently approved product could consider tenant writes or Live Response. Generic raw REST and exported-cmdlet runners remain non-goals.

Dependency notes: `Get-XdrIncidentAssociatedAlert` has a new single-page mode used by MCP; its default all-pages mode remains unchanged for existing PowerShell users. `Get-XdrIdentityUser -ResolveOnly` skips enrichment and its cache. `Get-XdrEndpointDeviceActionResult` can write forensic files; `Invoke-XdrMtoAdvancedHunting` may default to cached multiple tenant IDs; the detection-rule cmdlet requests 10,000 items; and XSPM attack-path calls reset the web session. None is exposed through this candidate.

Post-review hardening preserves HTTP status across the original eleven read paths, distinguishes not-found responses from authentication failures, restricts the extended deadline to sign-in, and rejects oversized serialized pages without losing the session. SID resolution completes the existing identity lookup tool without adding another operation or enrichment request; it has offline target-validation and single-request tests, not live evidence yet.

Live testing found that the portal rejects `Get-XdrIncident -SortByField LastUpdatedDate` despite the cmdlet's documented `ValidateSet`; the candidate fixes `TopRisk` descending. Incident status may be numeric. Device list results use `MachineId`, and identity list results contain a nested `ids.aad` rather than a top-level object ID. `Update-XdrConnectionSettings` uses cached tenant context but does not independently verify account and tenant after refresh. No tenant mutation or live write validation is part of this release.