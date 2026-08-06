# Timeline export functions

## Purpose

The timeline export cmdlets are designed for large incident-response collections where
the complete result should not be held in memory. They write newline-delimited JSON
(NDJSON) to disk and return a compact summary object.

Current and planned coverage:

| Workload | Export cmdlet | Status |
| --- | --- | --- |
| Defender for Endpoint device timeline | `Export-XdrEndpointDeviceTimeline` | Implemented |
| Defender for Identity user timeline | `Export-XdrIdentityUserTimeline` | Implemented |
| Defender for Cloud Apps activity timeline | To be determined | Planned |

This document describes the common export model and the workload-specific device and
identity implementations.

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

The byte-stream merger is shared by both exporters. Request construction, pagination,
timestamp validation, and recovery remain workload-specific.

## Identity timeline export lifecycle

`Export-XdrIdentityUserTimeline` resolves one user, fingerprints the canonical API
identifiers, and divides the requested range into adjacent 24-hour windows. Up to eight
windows run concurrently; pages within each window remain sequential.

Some portal entities cannot be resolved through the UPN lookup even though their AadId
and SID resolve correctly. The exporter fails that UPN selection instead of sending the
raw UPN directly: live testing found that the timeline endpoint accepted such a raw UPN
but returned an empty result for a range that returned events with resolved identifiers.
Use the AadId or SID from the Defender user URL for those entities.

The identity endpoint is not a continuation API. It accepts POST bodies containing
`count` and `skip`, but live testing found that offset pages drift when many events
share a timestamp: adjacent pages can repeat records while omitting different records.
The exporter therefore sends `skip = 0` and pages by timestamp. It validates that:

- `count` equals the number of returned records;
- `errors` has no properties (the successful response is an empty object);
- every `Timestamp` is parseable, descending, and inside the requested interval;
- only representations differing in observed volatile fields share a duplicate key.

The service treats its Unix-second bounds as exclusive. To implement a conventional
half-open `[FromDate, ToDate)` interval, the worker sends
`(ceil(FromDate)-1 second, ceil(ToDate))` and validates the returned timestamps again.
This prevents an event exactly on an adjacent window boundary from being lost.

For every full 1,000-row response, the worker withholds the complete oldest API-second
group, commits only the newer prefix, and repeats `skip = 0` with that second included
as the new exclusive upper bound. A partial response completes the window. If one
second fills a complete page, the API cannot prove which additional records may exist
in that second. The export fails with `UnpageableBoundary` and preserves completed
parts; it never discards the second or publishes a partial final file.

Identity events are written without removing or rewriting correlation properties.
Live testing also found that `EventId` is reused across timestamps and that identical
representations can recur with different `Id`, `RowNumber`, and `Description` values.
The duplicate key therefore combines the timestamp, `EventId` when present, and a
canonical payload hash excluding those three observed volatile fields. The first raw
object is retained unchanged and later matching representations are counted. Stable
payload differences remain separate events.

The identity manifest also supports a recoverable `Publishing` state. The expected final
length and SHA-256 are committed before the atomic move, allowing an interrupted rerun
to validate either the final or partial output and complete publication without
redownloading finished windows. During `-Force`, an existing final file remains readable
until the replacement has passed validation.

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

Each worker follows only the response's `Prev` continuation URI. It rejects repeated,
off-host, or unexpected continuation paths. Pagination cannot safely be parallelized
within one window because later continuation URIs do not exist until earlier pages have
been returned. Throughput therefore comes from concurrent independent windows.

## Streaming and memory behavior

Each response page is serialized one record at a time to UTF-8 NDJSON. Once a page has
been processed, the response reference is released. The endpoint worker hashes bytes as
they are written. The identity worker stages at most one 1,000-row response while it
decides whether the oldest timestamp group is complete, then hashes the completed part
before publication.

The complete timeline and completed parts are never parsed into one in-memory
collection. Memory is primarily bounded by the active response pages, serialization
overhead, runspaces, and the underlying PowerShell web stack. Finalization copies and
hashes byte streams; it does not deserialize the NDJSON.

The current endpoint settings are:

- four-hour windows;
- four concurrent workers;
- 1,000 records per page.

These values are fixed because the benchmark results were not monotonic: smaller
windows or more workers improved some short runs but increased memory, retries, or
window restarts in longer runs. `ChunkHours` and `ThrottleLimit` should remain private
until an automatic policy or broadly validated settings can replace manual guessing.

The identity exporter uses 24-hour windows, eight workers, and 1,000-row
timestamp-keyset pages. Delayed fresh-context probes over a fixed 30-day range for a
dense test identity produced the same 23,490-event logical set across 36 requests,
including a page boundary
with 723 events in one second. Raw bytes differed because the service regenerated
`Id`, `RowNumber`, and `Description`; no stable payload field differed. The fallback key
also remained stable for the three events without `EventId`.

Repeated corrected-strategy benchmarks favored 24 hours/eight workers over 48
hours/four workers: median elapsed time improved from 19.5 to 14.1 seconds over seven
days and from 87.5 to 54.1 seconds over 30 days. Over 90 days, 24 hours/eight workers
completed in 192.3 seconds versus 316.9 seconds for 24 hours/four workers. Directly
comparable event sets were identical, candidate runs had no retries or restarts, and
peak working set remained below 756 MiB. The settings remain private because these are
tenant-specific measurements rather than a documented service guarantee.

Independent streaming validation confirmed line count, range, global order, length,
SHA-256, interruption/resume, and equality across adjacent-window splits. A fixed
six-hour public-command check also produced identical 1,845-event stable sets from
`Get-` and `Export-`. One 44-day-old event without an `EventId` appeared between delayed
90-day snapshots, demonstrating that the service can backfill historical data. The
manifest timestamps therefore describe a point-in-time collection, not an immutable
history.

## Retries, restart, and resume

Recovery occurs at two levels:

- A worker retries transient transport failures, HTTP 408/429/5xx responses, and an
  initially partial response with bounded exponential backoff and jitter.
- If a window's request context appears poisoned, the coordinator can restart the
  entire window with a fresh session. Device restarts also receive a new correlation ID.

The entire window is restarted because an arbitrary page is not a durable checkpoint.
Device continuation URIs are service-owned and may expire; identity page membership can
drift between identical offset requests. Appending a retried page to a partial file could
therefore introduce gaps or duplicates.

After an interruption, running the same command with the same path validates each
completed part by recorded byte length and SHA-256. Valid parts are reused; invalid,
failed, and in-progress parts are downloaded again. The device ID, time range, Sentinel
option, window size, and page size must match the device manifest. The identity
fingerprint, range, window size, page size, and pagination strategy must match the identity
manifest. `-Force` deliberately discards resumable state.

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

## Deferred device exporter follow-ups

The identity implementation exposed several improvements worth evaluating separately
for the device exporter: recover a manifest interrupted after final publication, retain
the previous final file throughout a forced replacement, reset all diagnostics when a
completed part fails resume validation, and complete live `IncludeSentinelEvents`
validation with a device that has Sentinel-backed timeline data. Identity testing also
showed that identifiers and descriptive fields can be request-volatile, so any future
device duplicate validation should first establish device-specific stable keys rather
than reuse the identity key. Repeated fixed-range device probes should compare complete
continuation-chain sets both immediately and after a delay, verify cross-page ordering,
and test whether cache flags or a fresh request context change membership before those
checks are tightened. The delayed probe matters because the identity service backfilled
a 44-day-old event between otherwise fixed 90-day snapshots.
