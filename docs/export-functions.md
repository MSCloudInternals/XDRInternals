# Timeline export functions

## Purpose

The timeline export cmdlets are designed for large incident-response collections where
the complete result should not be held in memory. They write newline-delimited JSON
(NDJSON) to disk and return a compact summary object.

Current and planned coverage:

| Workload | Export cmdlet | Status |
| --- | --- | --- |
| Defender for Endpoint device timeline | `Export-XdrEndpointDeviceTimeline` | Implemented |
| Defender for Identity user timeline | To be determined | Planned |
| Defender for Cloud Apps activity timeline | To be determined | Planned |

This document describes the common export model and the device implementation. The
workload-specific sections can be expanded as the identity and Cloud Apps exporters are
implemented.

## Why `Export-` is separate from `Get-`

`Get-XdrEndpointDeviceTimeline` is intended for smaller queries whose results will be
used as PowerShell objects. `Export-XdrEndpointDeviceTimeline` is optimized for long
ranges and bounded resource use:

- it streams records to disk instead of accumulating the timeline in a collection;
- it downloads independent time windows concurrently;
- it can resume after process, network, or computer interruption;
- it does not publish a final file unless every window passes validation;
- its public parameters intentionally omit unvalidated performance tuning controls.

The public command is small from a caller's perspective. Its internal implementation is
more involved because it provides concurrency, integrity, and recovery around a portal
API that was designed for an infinite-scroll user interface rather than bulk export.

## Device timeline export lifecycle

`Export-XdrEndpointDeviceTimeline` performs these stages:

1. Normalize the requested range to UTC and validate the device ID, range, and output
   path.
2. Create a new manifest, or load an existing compatible manifest for resume.
3. Divide the range into adjacent four-hour, newest-first windows.
4. Validate the length and SHA-256 hash of every previously completed part.
5. Snapshot the current authenticated session for isolated worker runspaces.
6. Run up to four windows concurrently. Pagination inside each window remains
   sequential because every continuation URI comes from the preceding response.
7. Atomically update the manifest whenever a window completes, restarts, or fails.
8. Verify and concatenate all parts into a temporary final file, atomically publish the
   requested path, and remove the parts after success.

The implementation is split across four files:

| File | Responsibility |
| --- | --- |
| `XDRInternals/functions/Export-XdrEndpointDeviceTimeline.ps1` | Public validation, manifest state, scheduling, progress, recovery, and finalization |
| `XDRInternals/internal/functions/New-XdrEndpointTimelineExportChunk.ps1` | Creates adjacent newest-first time windows |
| `XDRInternals/internal/functions/New-XdrEndpointTimelineExportWorker.ps1` | Downloads and validates one window while streaming NDJSON |
| `XDRInternals/internal/functions/Merge-XdrEndpointTimelineNdjsonPart.ps1` | Verifies and concatenates completed parts without parsing them again |

## Files and atomic publication

For an output path such as `timeline.ndjson`, an in-progress export can use:

| Path | Purpose |
| --- | --- |
| `timeline.ndjson.manifest.json` | Request identity, per-window state, counts, hashes, and final summary |
| `timeline.ndjson.manifest.json.partial` | Temporary manifest write; renamed over the manifest only after a complete write |
| `timeline.ndjson.parts/` | Completed per-window NDJSON files |
| `timeline.ndjson.parts/*.partial` | A worker's current incomplete file; never accepted for resume |
| `timeline.ndjson.partial` | Verified merged output before final publication |
| `timeline.ndjson` | Final export; created only after every window succeeds |

The temporary names prevent a terminated process from making an incomplete file look
complete. A successful export retains the final NDJSON and compact manifest, but removes
the part directory. If part cleanup fails, the export still succeeds and reports that
the temporary parts were retained.

## Windowing, ordering, and pagination

The requested range is treated as a half-open interval: `FromDate` is inclusive and
`ToDate` is exclusive. Adjacent windows therefore do not duplicate an event that lands
exactly on a boundary. The worker counts boundary events for diagnostics and skips the
exclusive upper boundary.

Windows are scheduled newest first because recent activity is normally the most useful
during an active incident. The service's order within each window is preserved, and the
final merge follows window order.

Each worker follows only the response's `Prev` continuation reference, regardless of
page length, and ignores `Next`. Before resolving that reference against the trusted
Defender base URL, it requires the live-confirmed relative
`/machines/{deviceId}/events` path and exact continuation query-key set. Absolute or
network-path URIs, another device or path, fragments, malformed or duplicate query keys,
empty values, and repeated resolved cursors fail closed. Pagination cannot safely be
parallelized within one window because later continuation references do not exist until
earlier pages have been returned. Throughput therefore comes from concurrent independent
windows.

## Streaming and memory behavior

Each response page is serialized one record at a time to UTF-8 NDJSON. The writer also
computes the part's SHA-256 hash as bytes are written. Once a page has been processed,
the response reference is released.

The complete timeline and completed parts are never parsed into one in-memory
collection. Memory is primarily bounded by the active response pages, serialization
overhead, runspaces, and the underlying PowerShell web stack. Finalization copies and
hashes byte streams; it does not deserialize the NDJSON.

The current internal settings are:

- four-hour windows;
- four concurrent workers;
- 1,000 records per page.

These values are fixed because the benchmark results were not monotonic: smaller
windows or more workers improved some short runs but increased memory, retries, or
window restarts in longer runs. `ChunkHours` and `ThrottleLimit` should remain private
until an automatic policy or broadly validated settings can replace manual guessing.

## Retries, restart, and resume

Recovery occurs at two levels:

- A worker retries genuine transport failures, HTTP 408/429/5xx responses, and a
  partial response with bounded exponential backoff and jitter. A valid HTTP
  429 `Retry-After` delta or date is honored up to 30 seconds; malformed JSON,
  authentication failures, and permanent HTTP errors are not retried.
- If a window's continuation context appears poisoned, the coordinator can restart the
  entire window with a fresh correlation ID and request context.

The entire window is restarted because an arbitrary page is not a durable checkpoint.
Continuation URIs are service-owned and may expire, and appending a retried page to a
partial file could introduce gaps or duplicates.

After an interruption, running the same command with the same path validates each
completed part by recorded byte length and SHA-256. Valid parts are reused; invalid,
failed, and in-progress parts are downloaded again. The device ID, time range, Sentinel
option, window size, and page size must match the manifest. `-Force` deliberately
discards resumable state and starts a replacement, but an existing published output is
not replaced unless the new export has been fully validated and atomically published.

## Correctness and fail-closed behavior

The exporter refuses to publish the final path when it cannot prove completeness. A
window fails when, for example:

- the service reports a partial response after its bounded recovery attempts;
- a continuation URI repeats or fails validation;
- an event has no parseable `ActionTimeIsoString` or `ActionTime`;
- an event falls outside the requested window;
- authentication or a permanent HTTP error occurs;
- a completed part fails length or SHA-256 validation;
- the output volume cannot be finalized with the available disk space.

This is intentionally stricter than returning whatever data happened to arrive. During
incident response, a plausible-looking but incomplete timeline is more dangerous than a
clear failure that preserves resumable work.

## Progress and heartbeat

Interactive progress is refreshed at most every two seconds. A 30-second informational
heartbeat reports time coverage, completed windows, event and byte counts, active and
queued work, elapsed time, and a rough ETA.

Workers update only small counters in a concurrent status map. The coordinator reads
those counters on the existing polling loop, so progress reporting does not scan NDJSON
files, deserialize events, or issue additional service requests. The ETA is based on
completed time-window coverage and is deliberately described as rough because event
density varies across the range.

## `IncludeSentinelEvents`

For the device exporter, `-IncludeSentinelEvents` sends
`includeSentinelEvents=true` on each window's initial request. Without the switch, the
request sends `includeSentinelEvents=false`. Continuation URIs come from the service and
retain the server-side query context.

The option means "include," not "return only." Enabling it should not remove ordinary
MDE timeline events. It also does not guarantee that Sentinel-specific records exist for
a device and range; tenant integration, device mapping, and available Sentinel data are
controlled by the service.

If a Sentinel-enabled export appears empty, compare the same device, UTC range, and a
new output path without the switch. Preserve the two compact manifests and summary
objects, but raw NDJSON is not needed for initial diagnosis. Useful details are:

- the exact command with tenant-sensitive values redacted;
- UTC `FromDate` and `ToDate` values;
- event/page/retry/restart counts from each summary;
- manifest state and per-window errors;
- whether the final file is absent, zero bytes, or contains zero lines;
- whether the portal shows Sentinel events for the same device and range.

Do not silently fall back to a non-Sentinel request when a Sentinel-enabled request is
empty. An empty response can be legitimate, and fallback would make the file appear
complete while failing to satisfy the caller's request.

## Follow-up validation evidence

A fixed one-hour UTC export on sanitized device label `known-high-volume-01` traversed
five live `Prev` pages and published 4,967 lines (18,698,247 bytes) with no retries,
restarts, warnings, or timestamp diagnostics. The independent line count, file length,
and SHA-256 matched the completed manifest. The densest live timestamp contained 257
events, so no equal timestamp crossed a 1,000-record page in that range; the focused
suite retains a synthetic three-page equal-timestamp proof.

A separate seven-day export was terminated after one part completed. A new authenticated
process validated and resumed that part, ignored an injected stale partial, and
atomically published 167,599 lines (1,204,753,184 bytes) with a matching SHA-256 and no
retries or window restarts.

Sentinel-enabled and disabled probes over the same one-hour range each returned 4,967
ordinary MDE events. No known Sentinel-backed event was available, so Sentinel-specific
inclusion remains unproven and behavior was not changed.

## Why the implementation is not a single download loop

A shorter implementation would have to give up at least one important property:

| Simplification | Consequence |
| --- | --- |
| One sequential request chain | Long exports take substantially longer during active incident response |
| Accumulate all pages before writing | Memory grows with the exported timeline |
| Let workers append to one file | Concurrent writes make ordering, integrity, and recovery unsafe |
| Append pages directly to the final file | Retried pages and power loss can leave gaps, duplicates, or a misleading partial result |
| Trust every response and continuation | Partial service results or cursor loops can silently lose data |
| Remove the manifest and hashes | Interrupted exports must restart, and completed bytes cannot be trusted on resume |
| Remove timestamp boundary checks | Concurrent windows can duplicate or misassign boundary records |

Some code can still be made easier to read, but moving it into more helper functions
does not remove the underlying states. A shared export engine may become worthwhile once
the identity and Cloud Apps implementations reveal which behavior is genuinely common.
Until then, keeping service-specific pagination and validation explicit avoids an
abstraction that hides important differences between these undocumented portal APIs.
