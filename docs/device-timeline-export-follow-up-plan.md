# Device timeline exporter follow-up plan

## Purpose

Use this plan in a dedicated session to stress and tune `Export-XdrEndpointDeviceTimeline` without importing assumptions from Identity or Cloud Apps. The implementation is on branch `feature/export-endpoint-device-timeline` in `/home/nathan/GitHub/XdrInternals-export-timeline` and is associated with PR #123.

The current exporter uses four-hour chunks, page size 1,000, four workers, and at most two fresh-window restarts. Pagination follows the service-provided `Prev` continuation URI regardless of page length and deliberately ignores `Next`. The worker validates continuation host/path, repeated cursors, page limits, partial-response reasons, timestamp range, newest-first ordering, and half-open chunk boundaries.

Device timeline data was materially volatile in prior fixed-range repetitions. There is no proven durable event identifier. Do not add ID- or payload-based deduplication merely to make repeated runs look identical; it could discard legitimate representations.

## Initial setup

1. Work only in `/home/nathan/GitHub/XdrInternals-export-timeline`; confirm the branch and dirty state before editing.
2. Import the worktree module and authenticate with:

   ```powershell
   Import-Module ./XDRInternals/XDRInternals.psd1 -Force
   Connect-XdrBySoftwarePasskey -KeyFilePath /home/nathan/GitHub/XdrInternals/.github/secadmin.passkey
   ```

3. Select the busiest available device and retain only sanitized identifiers and aggregate measurements.
4. Run the focused baseline before experiments:

   ```powershell
   Invoke-Pester ./tests/functions/ExportEndpointDeviceTimeline.Tests.ps1
   ```

## Experiments

### 1. Dense timestamps across server cursors

Find a high-volume interval containing many events with identical timestamps. Verify that the same timestamp can span multiple `Prev` pages without loss, duplication introduced by the client, ordering failure, or a repeated-cursor loop. Add a synthetic test that distributes equal timestamps over at least three continuation pages.

The server cursor is expected to disambiguate ties; do not replace it with timestamp keyset pagination unless live evidence disproves that contract.

### 2. Cursor-contract adversarial tests

Exercise a short page with a valid `Prev`, a full page without `Prev`, both `Prev` and `Next`, a repeated `Prev`, an off-host continuation, an unexpected path/query shape, partial-response reasons on a later page, and a continuation page whose newest timestamp is newer than the prior page's oldest timestamp. Confirm the exporter follows only validated `Prev` values and fails closed on ambiguity.

### 3. Performance matrix

Benchmark representative 7-day and 30-day ranges using disposable parameterized copies or a temporary spike. Suggested matrix:

| Variable | Values |
| --- | --- |
| Page size | 250, 500, 1,000 |
| Chunk hours | 2, 4, 8 |
| Workers | 2, 4, 8, 16 |

Screen configurations on seven days and retest finalists over 30 days. Judge range/order/cursor validation first, then warnings/restarts, peak working set, output rows/bytes, and wall-clock time. Because the source is volatile, do not require exact set or byte equality between separate live runs.

### 4. Recovery and authentication interruption

Interrupt a real multi-chunk export after completed parts exist. Reconnect and rerun it. Verify `ResumedChunks`, part length/hash validation, final SHA-256, atomic publication, `Finalizing` recovery, and preservation of the previous output during a failed `-Force` replacement. Simulate a 401/403 in one worker and confirm scheduling stops while completed parts remain resumable.

### 5. Retry and partial-response injection

Add focused tests for 429 with `Retry-After`, 5xx, timeout/transport failure, malformed JSON, explicit partial-response reasons after valid pages, and worker failure during part writing. Authentication and permanent HTTP failures must not be retried as transient failures.

### 6. Sentinel-backed inclusion

The Sentinel request flag is covered by unit tests, but inclusion of Sentinel-backed events has not been proven live. If the tenant has a known Sentinel-only event, compare exports with and without the option over a fixed range and retain sanitized aggregate evidence.

## Decision gates

- Keep current defaults unless a 30-day proof produces a repeatable win without weaker cursor validation or materially higher memory.
- Do not add deduplication without a proven durable device-event identity.
- If pagination semantics change, add an explicit manifest strategy such as `ServerPrevCursorV1` and invalidate incompatible resumable state. Otherwise defer the marker to avoid churn.
- Add tests before promotion, then run the focused suite, repository harness, and a sanitized live proof.

## Expected handoff

Record the device selection method, UTC ranges, parameter matrix, rows/pages/restarts, peak memory, elapsed time, output hash, continuation diagnostics, and observed volatility. Separate mock evidence from live-service evidence. Update PR #123 but do not merge unless explicitly requested.
