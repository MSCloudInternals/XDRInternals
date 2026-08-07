# Cloud Apps timeline export validation

## Scope

This note records the correctness, recovery, and performance evidence used for the Cloud Apps timeline implementation on `feature/export-cloud-apps-activity-timeline`. It contains aggregate results only; no activity payloads, cookies, tokens, or tenant identifiers are retained.

## Kept implementation decisions

- `Export-XdrCloudAppsActivityTimeline` uses six-hour windows, page size 250, eight workers, timestamp keyset pagination, creation-time keyset recovery for dense recent timestamps, and stable-ID convergence only for dense archived timestamps.
- Bounded `Get-XdrCloudAppsActivityTimeline` now invokes the same internal pagination worker. The older independent offset loop was removed because short pages with `hasNext=true` and unstable ordering at dense timestamp boundaries could skip records.
- Normal duplicate suppression uses the complete serialized payload, not `_id`, `id`, or `recordId`. Reused identifiers therefore do not collapse distinct representations.
- Archived dense recovery fails closed if an activity lacks a stable ID or if one stable ID maps to different payloads.
- Null rows, missing/unparseable timestamps, out-of-range rows, ordering reversals, incomplete response shapes, and unpageable timestamp boundaries fail closed.
- A caller-provided `date` filter is rejected for bounded requests. A `created` filter is rejected whenever the range uses the archived API because that endpoint does not support it.
- HTTP 401/403 failures are not retried. Transient transport, 408, 429, and 5xx failures are retried; 429 honors a bounded `Retry-After` value.
- Count is a consistency signal, not an exact snapshot. A list shortfall receives one fresh-window restart. Persistent differences are retained in `CountDelta` rather than causing loss of successfully retrieved payloads.
- On resume, completed parts retain their hashes and route. Pending intervals are replanned against the current moving archive boundary and split if necessary before new work starts.

## Automated validation

The focused suites cover:

- short pages that still report more data;
- exact/full page continuation and timestamp rewinds;
- case-colliding JSON properties;
- recent and archived filter shapes;
- list/count mismatch and lower-bound behavior;
- repeated payload suppression while preserving reused IDs and distinct payloads;
- missing and null activity records;
- authentication, throttling with `Retry-After`, timeout, and 5xx handling;
- dense recent creation-time pagination;
- a creation timestamp that itself fills a page;
- archived dense stable-ID convergence and ID/payload collision failure;
- interruption/resume, incompatible manifests, archive-boundary aging, atomic replacement, publishing recovery, and final-hash rejection.

Run them with:

```powershell
Invoke-Pester ./tests/functions/CloudApps.Tests.ps1,./tests/functions/ExportCloudAppsActivityTimeline.Tests.ps1
```

The final focused run passed 60 of 60 tests. The repository harness then passed 19,992 tests with zero failures and three expected platform/coverage skips.

## Sanitized live-service evidence

### Recent 24-hour export

UTC range `2026-08-05T22:53:59.7426626Z` through `2026-08-06T22:53:59.7426626Z` produced 3,942 rows, 20 pages, four windows, and 15,627,611 bytes. Independent streaming validation found zero missing timestamps, out-of-range rows, ordering reversals, or duplicate payloads, and the final SHA-256 matched the manifest. One count remained 17 above the list after two fresh-window restarts.

Running the repaired `Get-XdrCloudAppsActivityTimeline` over the identical range with eight three-hour windows returned 3,986 payloads. Its canonical payload set contained all 3,942 payloads from the earlier export plus 44 later-visible payloads; none from the earlier export were lost.

### Interruption and resume

A seven-day export for `2026-07-30T22:58:29.4439428Z` through `2026-08-06T22:58:29.4439428Z` was interrupted after the manifest recorded 18 of 28 completed parts. At interruption there was no final output, no partial part, and ten windows remained pending.

After reconnecting, the exporter reported 18 resumed windows and completed with 11,485 rows, 69 pages, 46,829,763 bytes, and final SHA-256 `3d5d1feac1362ec4596732100399da04d13dad3e8276d4a1fba32fbb3028760e`. Independent validation found zero missing timestamps, out-of-range rows, ordering reversals, or duplicate payloads. The manifest was `Complete`; the parts and final `.partial` paths were absent.

### Archived route

UTC range `2026-07-06T17:08:23.5203495Z` through `2026-07-06T23:08:23.5203495Z` used one archived window and returned 212 rows with exact count parity. Independent validation found zero missing timestamps, out-of-range rows, ordering reversals, or duplicate payloads, and the final SHA-256 matched.

### Restart policy comparison

The same fixed recent 24-hour interval was queried with zero and one allowed count-mismatch restart after late-arriving service data had stabilized:

| Restarts allowed | Rows | Canonical set | Count delta | Elapsed |
| --- | ---: | --- | ---: | ---: |
| 0 | 4,039 | Reference | -17 | 36.972 s |
| 1 | 4,039 | Identical to zero-restart run | -17 | 71.220 s |

The extra request did not change the canonical payload set or count delta. One restart is retained as a conservative defense against a genuinely partial list response; the previous second restart was removed because it added latency without evidence of additional coverage.

## Remaining limitations and future probes

- A real manifest cannot be aged by days during one test session. Moving archive-boundary resume is covered synthetically and should be observed opportunistically on a naturally aged interrupted export.
- The archived dense fallback was exercised synthetically and a normal archived live window completed cleanly, but a naturally occurring archived timestamp containing more than 250 rows was not found in this proof.
- Count snapshots and fixed-range list contents can change as late activities become visible. Compare canonical payload sets and range/order invariants rather than expecting byte-identical independent runs.
- A prior 60-day bulk exercise covered both routes with approximately 205,000 rows and roughly 1 GiB of output. Repeat a 30- or 60-day run only after meaningful pagination or worker changes; focused dense, recovery, and archive-boundary proofs are more diagnostic for the current delta.
