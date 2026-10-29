# Identity timeline exporter follow-up plan

## Purpose

Use this plan in a dedicated session to stress and tune `Export-XdrIdentityUserTimeline` without importing assumptions from the Cloud Apps or device APIs. The implementation is on branch `feature/export-identity-user-timeline` in `/home/nathan/GitHub/XdrInternals-identity-export` and is associated with PR #130.

The current exporter uses 24-hour chunks, page size 1,000, eight workers, at most two fresh-window restarts, and manifest pagination strategy `TimestampKeysetV2`. Its worker always requests `skip=0`, moves an exclusive upper timestamp bound, withholds the oldest complete API-second group on a full page, validates the response `count`, `data`, and `errors` contract, and fails closed when one API second fills an entire page.

Do not use EventId as a durable deduplication key. Prior live work found that it can be reused or change between requests. Do not port the Cloud Apps archived stable-ID convergence algorithm unless new identity-specific evidence proves a stable key.

## Initial setup

1. Work only in `/home/nathan/GitHub/XdrInternals-identity-export`; confirm the branch and dirty state before editing.
2. Import the worktree module and authenticate with:

   ```powershell
   Import-Module ./XDRInternals/XDRInternals.psd1 -Force
   Connect-XdrBySoftwarePasskey -KeyFilePath /home/nathan/GitHub/XdrInternals/.github/secadmin.passkey
   ```

3. Select a known high-activity identity using the supported identity resolution workflow. Record only sanitized identifiers and aggregate metrics.
4. Run the focused baseline before experiments:

   ```powershell
   Invoke-Pester ./tests/functions/ExportIdentityUserTimeline.Tests.ps1
   ```

## Experiments

### 1. Dense API-second boundary

Export a 30- or 60-day range for the busiest available identity. Inspect manifests and output to determine the maximum events sharing one API second and whether pagination rewinds occur. Repeat a focused dense interval with page sizes 250, 500, and 1,000 in a disposable spike.

The important failure condition is a full page whose records all occupy the same API second. The current safe behavior is to fail closed because no proven secondary ordering/filter exists. If this occurs, capture the sanitized response shape and investigate the service contract before changing code.

### 2. Short-page terminal assumption

The identity response has no `hasNext`. The exporter therefore treats a short page as terminal. For fixed historical windows, compare the stable payload set obtained with page sizes 250, 500, and 1,000. A smaller-page run returning records absent from a larger-page run would disprove the terminal assumption and requires a new API-specific continuation strategy.

Do not demand byte-identical output when the service is changing. Compare canonical payload hashes, timestamp distributions, range validity, and page-boundary groups.

### 3. Performance matrix

Benchmark representative 7-day and 30-day ranges using disposable parameterized copies or a temporary spike. Suggested matrix:

| Variable | Values |
| --- | --- |
| Page size | 250, 500, 1,000 |
| Chunk hours | 6, 12, 24 |
| Workers | 4, 8, 16 |

Screen configurations on seven days, then retest the best candidates over 30 days. Judge results in this order: completeness and validation, warnings/restarts, peak working set, output bytes/rows, then wall-clock time. Do not keep a faster configuration that weakens boundary handling or materially increases memory.

### 4. Recovery and authentication interruption

Interrupt a real multi-chunk export after completed parts exist. Reconnect and rerun the same command. Verify `ResumedChunks`, part length/hash validation, final SHA-256, atomic publication, and preservation of a prior output under `-Force`. Also simulate or induce a 401/403 in one worker and confirm new scheduling stops while completed parts remain resumable.

### 5. Retry and malformed-response injection

Add focused tests for 429 with `Retry-After`, 5xx, timeout/transport failure, an `errors` collection after earlier valid pages, missing `data`, response-count mismatch, out-of-range timestamps, and an ordering reversal between pages. Authentication and permanent HTTP failures must not be retried as transient failures.

## Decision gates

- Keep existing defaults unless a 30-day proof shows a repeatable improvement with identical correctness evidence and acceptable memory.
- Keep fail-closed dense-second behavior unless an identity-specific secondary cursor is proven live.
- Version `PaginationStrategy` and invalidate incompatible manifests if pagination semantics change.
- Add tests before promoting any finding. Run focused tests, then the repository harness and a sanitized live proof.

## Expected handoff

Record the entity selection method, UTC ranges, parameter matrix, rows/pages/restarts/rewinds, peak memory, elapsed time, output hash, and any cross-run volatility. Separate mock evidence from live-service evidence. Update PR #130 but do not merge unless explicitly requested.
