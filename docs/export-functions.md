# Export functions

XDRInternals can export pipeline data to hosted Azure Data Explorer, a local Kusto emulator (Kustainer), or a Microsoft Sentinel custom table. The two Kusto exporters support typed source routing and raw-table mode, but their ingestion transports have different performance and reliability characteristics.

## Choose a Kusto target and ingestion mode

| Consideration | Azure Data Explorer queued | Kustainer inline | Kustainer streaming |
| --- | --- | --- | --- |
| Best fit | Durable, high-volume hosted ingestion | Bulk local development and test loads | Low-latency local event delivery |
| Submission | Blob upload followed by queued-ingestion request | Synchronous `.ingest inline` management command | Direct `/v1/rest/ingest` request |
| Authentication | Azure Data Explorer bearer token | None at the emulator | None at the emulator |
| Default request size | 1,024 MB uncompressed, capped by service configuration | 100 MB uncompressed | 5 MB uncompressed |
| Configurable size | `-MaxBlobSizeMB`, capped by service configuration | `-MaxBatchSizeMB`, 0.0625–256 MB | `-MaxBatchSizeMB`, 0.0625–10 MB |
| Data visibility | Asynchronous; commonly minutes | Queryable when the command succeeds | Intended for near-real-time visibility |
| Tracking | Operation IDs and optional wait support | No separate operation tracking | No separate operation tracking |
| Compression | Gzip by default | No | No |
| Automatic ambiguous retry | Managed queued ingestion provides at-least-once behavior | No, to avoid duplicates | No, to avoid duplicates |
| Schema changes | Queued ingestion resolves the target mapping during processing | Management endpoint observes bootstrap immediately | New tables and mappings can take several minutes to propagate |

### Inline versus streaming

Use inline ingestion for:

- Historical imports or a complete timeline retrieved in one operation.
- Large data sets where throughput and fewer extents matter more than per-event latency.
- Simple local workflows that shouldn't enable an experimental database policy.
- Loads where you want the ingestion command to finish before continuing.

Use streaming ingestion for:

- Small, frequent batches that should become queryable with low latency.
- Long-running collectors that continually send new events.
- Workloads where a 5–10 MB request is a natural unit of work.

Streaming is not a faster bulk loader merely because its name contains “streaming.” Its small request ceiling creates more requests and potentially more fragmented storage. It also requires the database streaming-ingestion policy, cannot attach extent tags for deduplication, and can temporarily reject newly created tables or mappings until its schema cache catches up.

Neither Kustainer transport has the managed queue, durable retry, batching, status tracking, or deduplication facilities available in hosted Azure Data Explorer. If a Kustainer request fails after the server might have received it, query the target data before deciding whether to resend it.

## Shared exporter behavior

The hosted and emulator exporters share:

- Typed table profiles and routing by `ActionType` or `SourceTable`.
- Typed record conversion and JSON ingestion mappings.
- Automatic table and mapping bootstrap.
- A raw-table mode containing the complete record in an `Event:dynamic` column.
- Per-table staging, rollover, cleanup, `-KeepTempFiles`, `-SkipBootstrap`, and `-PassThru` behavior.

Their transport implementations remain separate. `Export-XdrAzureDataExplorer` handles token acquisition, ingestion-endpoint discovery, gzip, blob upload, queued submission, status tracking, and waits. `Export-XdrKustainer` talks directly to the emulator over HTTP, supports inline or streaming ingestion, and deliberately avoids adding emulator branches to the hosted exporter.

## Microsoft Sentinel export

`Export-XdrToSentinel` sends PowerShell objects to a Log Analytics custom table through the HTTP Data Collector API. It is independent of the Kusto table profiles used by the Azure Data Explorer and Kustainer exporters.

Configure the workspace and export pipeline data:

```powershell
Set-XdrSentinelConnection `
    -WorkspaceId '12345678-abcd-1234-abcd-123456789012' `
    -SharedKey $sharedKey

Get-XdrAlert |
    Export-XdrToSentinel `
        -LogType XdrAlerts `
        -TimestampField CreationTime
```

The destination table is named `<LogType>_CL`. `-BatchSize` controls the number of records in each request and defaults to 500; lower it for unusually wide records because the current exporter doesn't separately roll over batches by serialized byte size. `-PassThru` returns the original input objects to the pipeline.

The exporter currently uses the legacy workspace-ID/shared-key HTTP Data Collector transport. `Set-XdrSentinelConnection -DceEndpoint` stores a Data Collection Endpoint for other module workflows but doesn't change `Export-XdrToSentinel` transport behavior. Moving this exporter to the Logs Ingestion API and DCR/DCE model is separate future work.

## Azure Data Explorer export

Export XDR data directly to Azure Data Explorer for long-term investigation and custom analytics. The cmdlet supports two modes: typed source routing, which automatically creates well-structured tables, and manual table mode for custom schemas.

### Authentication

`Export-XdrAzureDataExplorer` requires a separate Azure Data Explorer token. This is independent of the XDR portal session. The token is acquired automatically using the following priority:

| Method | When available |
| --- | --- |
| Explicit token | `-AccessToken` on `Set-XdrAzureDataExplorerConnection` |
| ESTS CLI bridge | `Connect-XdrByCredential`, `Connect-XdrByBrowser`, `Connect-XdrBySoftwarePasskey`, `Connect-XdrByPhoneSignIn`, or `Connect-XdrByTemporaryAccessPass` |
| Az.Accounts | `Connect-AzAccount` is active |
| Azure CLI | An `az login` session exists |
| Managed identity | Running on Azure with IMDS |

> [!IMPORTANT]
> `Connect-XdrBySSO` and `Set-XdrConnection` with raw `sccauth` and XSRF tokens do not capture ESTS cookies. When using these methods, ensure you have an active `Connect-AzAccount` or `az login` session, use managed identity, or provide an explicit `-AccessToken`.

### Discover clusters and databases

If the authenticated Azure context can access the target resources, discover cluster and database details directly:

```powershell
Get-XdrAzureDataExplorerCluster
Get-XdrAzureDataExplorerCluster -IncludeDatabases

Set-XdrAzureDataExplorerConnection `
    -ClusterName 'nm-test-cluster' `
    -DatabaseName 'Investigations' `
    -NonInteractive

Set-XdrAzureDataExplorerConnection `
    -ClusterUri 'https://mycluster.westeurope.kusto.windows.net' `
    -Database 'Investigations' `
    -AccessToken $token
```

### Typed source routing

Use `-Source` to route events into purpose-built typed tables with promoted columns:

```powershell
Set-XdrAzureDataExplorerConnection `
    -ClusterUri 'https://mycluster.westeurope.kusto.windows.net' `
    -Database 'Investigations'

Get-XdrEndpointDeviceTimeline -DeviceId $deviceId -LastNDays 7 |
    Export-XdrAzureDataExplorer -Source DeviceTimeline -WaitForIngestion -Verbose

Get-XdrIdentityUserTimeline -Upn 'user@contoso.com' -LastNDays 7 |
    Export-XdrAzureDataExplorer -Source IdentityTimeline -Verbose

Get-XdrCloudAppsActivityTimeline -LastNDays 1 |
    Export-XdrAzureDataExplorer -Source CloudAppsActivityTimeline -Verbose

Get-XdrAlert | Export-XdrAzureDataExplorer -Source Alert
Get-XdrIncident | Export-XdrAzureDataExplorer -Source Incident
Get-XdrEndpointDevice | Export-XdrAzureDataExplorer -Source Device
```

Typed tables created automatically:

| Source | Tables |
| --- | --- |
| DeviceTimeline | `XDRDeviceTimelineProcessEvents`, `XDRDeviceTimelineFileEvents`, `XDRDeviceTimelineNetworkEvents`, `XDRDeviceTimelineRegistryEvents`, `XDRDeviceTimelineLogonEvents`, `XDRDeviceTimelineAlertEvents`, `XDRDeviceTimelineOtherEvents` |
| IdentityTimeline | `XDRIdentityTimelineCloudAppEvents`, `XDRIdentityTimelineSignInEvents`, `XDRIdentityTimelineAlerts` |
| CloudAppsActivityTimeline | `XDRCloudAppsActivityTimeline` |
| Alert | `XDRAlerts` |
| Incident | `XDRIncidents` |
| Device | `XDRDevices` |
| AdvancedHunting | `XDRAdvancedHuntingResults` |

Every typed table includes an `Event` dynamic column containing the complete original event, so fields that aren't promoted remain available.

For `XDRCloudAppsActivityTimeline`, `Date` is the query-friendly UTC `datetime` converted from the source's Unix-millisecond `timestamp`. `Timestamp` retains that original numeric source value for fidelity, and `Event` retains the complete activity object.

### Manual table mode

For custom schemas or ad-hoc exports, specify a table name directly:

```powershell
Get-XdrEndpointDeviceTimeline -DeviceId $deviceId -LastNDays 7 |
    Export-XdrAzureDataExplorer -TableName DeviceTimeline

Get-XdrEndpointDeviceTimeline -DeviceId $deviceId -LastNDays 7 |
    Export-XdrAzureDataExplorer -TableName DeviceTimeline -WaitForIngestion -Verbose

Get-XdrAzureDataExplorerIngestionStatus `
    -TableName DeviceTimeline `
    -OperationId $operationId `
    -Details
```

### Operational notes

- Queued ingestion is asynchronous and data may take several minutes to become queryable.
- Batches already submitted to queued ingestion cannot be rolled back if a later batch or pipeline stage fails.
- Pipeline cancellation closes local writers and removes unsubmitted staging files unless `-KeepTempFiles` is used.
- Payload files are gzip-compressed before upload unless `-DisableCompression` is specified.
- Long-running exports refresh the queued-ingestion storage configuration before its SAS expires.
- Prefer `-TrackIngestion` only when operation IDs are needed for troubleshooting.

## Kusto emulator (Kustainer) export

`Export-XdrKustainer` targets the local Kusto emulator without changing the hosted Azure Data Explorer export path. Start Kustainer with its HTTP port exposed, following the [Microsoft installation guide](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-install):

```bash
docker run -e ACCEPT_EULA=Y -m 4G -d -p 8080:8080 -t mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
```

Inline ingestion requires no ingestion-policy switch and is accepted through `/v1/rest/mgmt`. Streaming ingestion through `/v1/rest/ingest` is the experimental opt-in mode described below. Kustainer doesn't expose the Azure Data Explorer queued-ingestion service.

The default emulator database is commonly named `NetDefaultDB`. Confirm the databases before exporting:

```powershell
$body = @{ csl = '.show databases' } | ConvertTo-Json
Invoke-RestMethod -Method Post -ContentType 'application/json' -Body $body `
    -Uri 'http://localhost:8080/v1/rest/mgmt'
```

Configure Kustainer and export a device timeline into typed tables:

```powershell
Connect-XdrBySoftwarePasskey -KeyFilePath '.github/secadmin.passkey'
Set-XdrKustainer -ClusterUri 'http://localhost:8080' -Database 'NetDefaultDB'

Get-XdrEndpointDeviceTimeline -DeviceId $deviceId |
    Export-XdrKustainer -Source DeviceTimeline -Verbose
```

For an ad-hoc raw table with one `Event:dynamic` column, replace `-Source DeviceTimeline` with `-TableName DeviceTimeline`.

### Inline request sizing

Inline ingestion defaults to 100 MB requests for bulk throughput and accepts fractional sizes from 0.0625 MB (64 KiB) through 256 MB:

```powershell
Get-Content '.\large-export.ndjson' | ConvertFrom-Json |
    Export-XdrKustainer `
        -TableName BulkEvents `
        -MaxBatchSizeMB 200 `
        -RequestTimeout 1200
```

Larger requests reduce the number of small extents because the emulator doesn't merge extents. They also require proportionally more client, reverse-proxy, and container memory. Start around 100 MB for bulk inline loads, lower the size on memory-constrained hosts, and ensure a reverse proxy permits a body larger than the configured batch size. The exporter doesn't automatically retry inline requests because a lost response doesn't prove the server rejected the data.

For large local data sets:

- Persist `/kustodata` with a Docker bind mount or volume and monitor the host filesystem. Container-local data disappears with the container.
- Size the container above Microsoft's 4 GB recommendation when using large requests or running queries during ingestion. The staged file, PowerShell request body, reverse proxy, and Kusto engine can each need memory for the same batch.
- Prefer fewer, larger inline requests for bulk loading. Prefer smaller streaming requests only when ingestion latency matters.
- Treat the emulator as rebuildable development or test storage. Emulator metadata and extent formats aren't guaranteed to remain compatible across versions, and retention and partitioning policies aren't enforced.
- Use mounted-file ingestion for data sets too large to move comfortably through an HTTP management request. The 256 MB ceiling is a client safety limit, not a claim about the engine's absolute maximum.

### Streaming ingestion

Enable the database-level policy while configuring the connection:

```powershell
Set-XdrKustainer `
    -ClusterUri 'http://localhost:8080' `
    -Database 'NetDefaultDB' `
    -EnableStreamingIngestion
```

The database-level policy applies to existing and future tables. A table-level policy alone might not be enough when the database policy is disabled. Enabling it emits a warning because Microsoft currently documents emulator streaming ingestion as unsupported, although tested current Kustainer builds accept it.

Use the streaming endpoint explicitly:

```powershell
Get-XdrEndpointDeviceTimeline -DeviceId $deviceId |
    Export-XdrKustainer `
        -Source DeviceTimeline `
        -IngestionMode Streaming `
        -Verbose
```

Streaming defaults to 5 MB requests and accepts fractional sizes up to 10 MB. Use smaller requests when latency matters and 10 MB when throughput is more important. New tables and mappings can take several minutes to become visible to the streaming endpoint. The exporter retries only the explicit pre-ingestion `BadRequest_EntityNotFound` response while waiting for schema propagation; it doesn't retry ambiguous transport failures.

### Querying Kustainer

Query the configured emulator with PowerShell-native results:

```powershell
Invoke-XdrKustainerQuery `
    -Query 'XDRCloudAppsActivityTimeline | summarize Events=count() by AppName'

Invoke-XdrKustainerQuery -Query '.show tables'
```

Use `-Raw` for the complete Kusto REST response envelope. `-ClusterUri` and `-Database` can also be supplied directly without first calling `Set-XdrKustainer`.

### HTTPS, mounted files, and deduplication

Kustainer exposes HTTP directly. `Set-XdrKustainer`, `Export-XdrKustainer`, and `Invoke-XdrKustainerQuery` accept an HTTPS URL when an operator places a TLS reverse proxy in front of the container. The module doesn't provision that proxy.

Mounted-file ingestion requires a Docker bind mount or volume configured by the container operator. The HTTP management endpoint can instruct Kustainer to ingest an existing container path, but it can't create a Docker mount or upload a file into one. Automating it is practical only when the PowerShell client can write to the corresponding host-mounted directory; remote clients should use inline or streaming ingestion.

Queued-ingestion `sourceId` values identify sources for tracking; they don't provide deduplication. Queued deduplication uses `ingestIfNotExists` with matching `ingest-by:` extent tags. Streaming ingestion can't attach extent tags, so callers should treat streaming retries as non-idempotent.
