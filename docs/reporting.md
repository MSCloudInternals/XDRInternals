# Defender Portal Reporting

`Get-XdrReportDefinition` lists discovered operations without connecting. `Get-XdrReport` executes a selected operation using the current Defender portal session. `Get-XdrEndpointDeviceControlReport` remains a dedicated entry point for Device Control summary, policy, and freshness reports.

## Examples

```powershell
Get-XdrReportDefinition | Select-Object Name, Family, Method, Source
Get-XdrReportDefinition -Family 'Email' -Name '*.Summary'
Get-XdrReport -Name 'DeviceHealth.healthStatus'
Get-XdrReport -Name 'VulnerableDevices.severityLevel' -FromDate (Get-Date).AddDays(-7) -ToDate (Get-Date)
Get-XdrReport -Name 'AttackSurfaceReduction.AsrDetections' -Top 100 -All
Get-XdrReport -Name 'WebContentFiltering.CategoryLookup' -Body @{ Url = 'https://www.microsoft.com' }
Get-XdrReport -Name 'Email.TopMalware.Summary' -Force
Get-XdrReport -Name 'Cloud.CoverageByPlan' -Top 100
Get-XdrReport -Name 'Cloud.SecureScore.Compute.Trend' -FromDate (Get-Date).AddDays(-7)
Get-XdrReport -Name 'Cloud.SecureScore.Category.Vulnerabilities.Trend'
Get-XdrReport -Name 'WebThreat.urls' -Parameters @{ id = '<domain-id-from-WebThreat.allDomains>' }
Get-XdrReport -Name 'Identity.Summary.Download' -OutFile './identity-summary.report'
```

Definitions expose `Path`, `Query`, `Body`, and provenance. `RequiredParameters`, `Binary`, and `ValidationPath` describe additional requirements where applicable. Query overrides must be keys declared by the selected definition. The `Body` parameter replaces the default JSON body of a read-only POST operation.

Date-based operations default to a 30-day range ending at the latest half-hour boundary. Supply `ToDate` explicitly for a range ending at the current time. Relative lookback operations use `LookbackInDays`; the dedicated Device Control summary retains its original 180-day default. Parameters not used by an operation do not change that operation's request.

Response envelopes are preserved. `-All` follows verified OData links and Device Control continuation tokens and returns each response page, not a flattened table. Relative links are resolved against the page that supplied them. It is not a universal pagination adapter: API-specific cursors such as Data Insights watermarks require explicit subsequent request bodies. Failed or incomplete multi-page reads are not cached. Cache entries are isolated by authenticated session, effective non-XSRF request headers (including tenant and scopes), URI, method, body, and pagination mode, with a 30-minute TTL; `-Force` refreshes only that entry. The dedicated Device Control cmdlet uses the same transport and cache isolation.

Binary exports require `OutFile`, refuse existing files, and are not cached. Downloads are staged beside the destination and published with an atomic, non-overwriting move. Failure cleanup removes only the staging file, never a competing destination. Identity exports first run the portal's availability validation. `NoResults` and `TooManyResults` produce explicit terminating errors before downloading; change the date range or override `isV2` if appropriate. The raw export format is determined by the service, not by the destination extension.

## Discovered Coverage

The September 30, 2026 inventory contains **183 operations across 18 families**, not 183 distinct user-facing reports. Counts include definitions, schemas, availability checks, and Advanced Hunting query helpers as well as report data. Discovery used the portal Reports index and its workload tabs, report navigation and drilldowns in authenticated Chrome, the supplied HAR and its client request builders, and nodoc Defender XDR specifications. Inspection of the loaded `mdc-defenders/dashboards-and-reports` bundle and its card registry established Cloud schema IDs, metric IDs, dimensions, paging, and request routes that were absent from the page's initial network traffic.

| Family | Operations | Surface |
|---|---:|---|
| UnifiedSecurity | 18 | Unified security summary, trends, coverage, incidents, email, disruption |
| Hunting | 3 | Query quota, resource usage, user history |
| DeviceHealth | 3 | Device health, platform, version |
| AntivirusHealth | 5 | Signature, engine, platform, scan, mode |
| VulnerableDevices | 4 | Severity, exploit availability, age, operating system |
| MonthlySecurity | 4 | Monthly summary providers |
| WebThreat | 5 | Summary, health, domains, URLs, exposed machines |
| WebContentFiltering | 5 | Categories, domains, machines, URL-category lookup |
| Firewall | 31 | Inbound/outbound/app blocks, rankings, hunting queries |
| DeviceControl | 5 | Summary, policies, freshness, event detail, hunting query |
| AttackSurfaceReduction | 3 | Detections, trend, top files |
| AttackSurfaceReductionConfiguration | 2 | Machine and rule configuration states |
| Email | 29 | Threat protection, ZAP, Safe Links, malware, spoofing, compromised users, latency, mailflow, submissions, downloadable-report and schedule lists |
| CloudApps | 3 | Exported-report metadata/list and discovery snapshot list |
| Identity | 14 | Password posture definitions/lists and four legacy report validations/exports |
| Cloud | 44 | Catalogs/definitions/schema, alerts, coverage, compliance, remediation, CVEs, recommendations, asset/workload counts, secure score tables and workload/category trends, CSPM aggregations |
| AttackSimulation | 4 | Repeat offenders, training completion/efficacy, user coverage |
| EndpointLicense | 1 | Endpoint SKU usage |

### Boundaries

This is the discovered and implemented read surface, **not a claim that every portal report is fully implemented**. Private APIs, feature flags, licensing, RBAC, tenant scope, and UI changes can alter availability.

- **Cloud data is implemented, but UI scope selection is not a separate cmdlet parameter.** All 44 Cloud operations passed live reads and cache checks, including 38 newly discovered data operations. Row-based charts require the client-observed `paging.pageSize`; secure-score tables use `/views/secureScore/items`, and top CVEs use `/views/vulnerabilities/topCloudCVEsItems`, not the general dashboard items route. Native-environment and horizontal-scope selections from the portal UI are not replayed automatically. Validation used the connection/default scope, not every possible subscription or environment.
- **External Exchange admin reports are not implemented.** The Reports index mailflow deep-link targets the Exchange admin center, outside the established Defender session transport. Defender's own mailflow summary/detail operations are included.
- **Report generation, scheduling, deletion, and feedback writes are excluded.** Existing downloadable/scheduled reports and Cloud Apps exports can be listed; no new jobs are created during discovery or validation. Download links for existing jobs require a populated job and a separately verified download contract; those job-file downloads are not implemented.
- **Target-dependent drilldowns need real targets.** Web-threat URL/machine reads require an ID from the domain report. An empty parent report cannot validate a populated drilldown.
- **Empty HTTP-success responses are not populated coverage.** Live results record envelope and record counts separately, including nested Cloud `properties.rows`. The 18 row-based Cloud reads returned rows in this tenant. Metric/aggregation envelopes are preserved; an envelope count alone does not prove a populated time series. Successful Identity availability validation can still return `NoResults`.

## Validation

```powershell
./tests/Invoke-XdrReportValidation.ps1 -KeyFilePath '<software-passkey-file>'
./tests/Invoke-XdrReportValidation.ps1 -KeyFilePath '<software-passkey-file>' -Name 'Email.*' -Days 7
./tests/pester.ps1 -Include @('EndpointReports.Tests.ps1', 'Manifest.Tests.ps1', 'Help.Tests.ps1', 'PublicCmdlets.Metadata.Tests.ps1', 'Sync-CmdletDocumentation.Tests.ps1')
```

```bash
node tests/build/ReportMapping.Tests.js
```

The opt-in live harness imports the exported module, authenticates with the supplied passkey, reads each selected operation, and verifies cache equality for nonbinary reads. A complete selection additionally exercises all three dedicated Device Control modes. Binary files use temporary destinations and are removed. Results under `TestResults` contain names, status, structural fields/counts, cache checks, and sanitized diagnostics, not tenant report records or authentication material.

The final reviewed PR tree was validated in one sweep of 186 cases: 183 catalog operations and three dedicated Device Control modes. **180 cases passed, six were unavailable, and none failed; no retries were needed.** Earlier Data Insights Email HTTP 403s led to a connection-refresh fix: rotating XSRF now preserves tenant and scope headers. All four Identity exports returned `NoResults` from validation. Both web-threat drilldowns lacked a target because the parent domain list was empty. Binary transport is covered by mocked file, overwrite, race, cleanup, and validation-workflow regressions; a populated Identity file download was not live-validated.

Sanitized final live evidence is in `TestResults/Reports.Review.Final.Live.json` in the isolated reporting-review worktree. Results and authentication material are not committed to the PR.

Chromium and Firefox mappings are generated from the same catalog. Report requests sharing a path are distinguished by method, report-identifying query fields, schemas, metric IDs, and dimension filters. Named metric/dimension entries are matched by ID rather than array position. Replay preserves cataloged query overrides and JSON bodies with PowerShell literal quoting. To synchronize only report mappings without changing README, manifest, or unrelated mappings, run `./build/Sync-CmdletDocumentation.ps1 -MappingCmdlet Get-XdrReport`.

The full repository suite on the isolated branch based on `main` passed **20,554 tests with zero failures and three skips**, including 222 report regressions, connection regressions, file integrity, help, manifest, public metadata, documentation-generation, and script-analyzer checks. The skips are the existing opt-in metadata gate and two OS-specific connection tests that do not apply on Linux. Both extension regression suites pass, including reordered Cloud dimension filters. Unrelated working-tree edits, MCP files, browser logs, and credentials are excluded from the PR. The user-edited README was preserved during review and mapping synchronization.