function Export-XdrKustainer {
    <#
    .SYNOPSIS
        Exports pipeline data to a local Kusto emulator (Kustainer).

    .DESCRIPTION
        Accepts pipeline input, stages records as newline-delimited JSON, bootstraps the target
        tables and JSON mappings when needed, and ingests each batch through either the Kusto
        emulator management endpoint or the streaming ingestion endpoint.

        The emulator supports HTTP without authentication and doesn't support the dedicated
        queued-ingestion endpoint used by Export-XdrAzureDataExplorer. This cmdlet uses the Kusto
        inline-ingestion command by default. Streaming endpoint support is available as an
        experimental mode when the database streaming-ingestion policy is enabled.

        When used with -TableName alone, the cmdlet creates a raw table with one Event:dynamic
        column. When used with -Source, it routes events to the same typed table profiles used by
        Export-XdrAzureDataExplorer.

    .PARAMETER Data
        The objects to export. Accepts pipeline input.

    .PARAMETER ClusterUri
        Optional HTTP endpoint exposed by the Kusto emulator, or an HTTPS reverse-proxy endpoint.
        When omitted, uses the endpoint configured by Set-XdrKustainer.

    .PARAMETER Database
        Optional emulator database to receive the data. When omitted, uses the database configured
        by Set-XdrKustainer.

    .PARAMETER TableName
        The target table name. Mandatory when -Source isn't specified. With -Source, this is an
        optional fallback table for events that don't match a typed table profile.

    .PARAMETER Source
        Enables typed table routing based on ActionType or SourceTable.

    .PARAMETER MappingName
        Optional mapping name for raw-table mode. Defaults to <TableName>_EventMapping.

    .PARAMETER MaxBatchSizeMB
        Maximum uncompressed ingestion request size in MB. Fractional values are supported.
        Defaults to 100 MB for inline ingestion and 5 MB for streaming ingestion. Inline requests
        can be configured up to 256 MB. Streaming requests cannot exceed 10 MB.

    .PARAMETER IngestionMode
        Ingestion transport. Inline uses the synchronous Kusto inline-ingestion management command.
        Streaming uses /v1/rest/ingest and requires the database streaming-ingestion policy.

    .PARAMETER StreamingSchemaTimeoutSeconds
        Maximum time for streaming ingestion to wait for a newly created table and mapping to
        propagate to the streaming endpoint. Defaults to 300 seconds.

    .PARAMETER RequestTimeout
        Client-side timeout for each ingestion request, in seconds. Defaults to 600 seconds.

    .PARAMETER TempPath
        Optional root path for temporary staging files.

    .PARAMETER KeepTempFiles
        Keeps temporary staging files after ingestion.

    .PARAMETER SkipBootstrap
        Skips the create-if-missing table and mapping bootstrap logic.

    .PARAMETER PassThru
        Outputs the original input objects after staging them for ingestion.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" |
            Export-XdrKustainer -ClusterUri "http://localhost:8080" -Database "NetDefaultDB" -TableName "DeviceTimeline"

        Exports a device timeline to one raw table in the local emulator.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" |
            Export-XdrKustainer -ClusterUri "http://localhost:8080" -Database "NetDefaultDB" -Source DeviceTimeline -Verbose

        Routes device timeline events into typed tables in the local emulator.

    .EXAMPLE
        Get-Content '.\large-export.ndjson' | ConvertFrom-Json |
            Export-XdrKustainer -TableName 'BulkEvents' -MaxBatchSizeMB 200

        Uses 200 MB inline requests for a large local bulk load.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ManualTable')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Data,

        [uri]$ClusterUri,

        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$Database,

        [Parameter(ParameterSetName = 'ManualTable')]
        [Parameter(ParameterSetName = 'TypedSource')]
        [Alias('Table')]
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$TableName,

        [Parameter(Mandatory, ParameterSetName = 'TypedSource')]
        [ValidateSet('DeviceTimeline', 'IdentityTimeline', 'CloudAppsActivityTimeline', 'CloudAppsTimeline', 'Alert', 'Incident', 'Device', 'AdvancedHunting')]
        [string]$Source,

        [Parameter(ParameterSetName = 'ManualTable')]
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$MappingName,

        [ValidateRange(0.0625, 256.0)]
        [double]$MaxBatchSizeMB,

        [ValidateSet('Inline', 'Streaming')]
        [string]$IngestionMode = 'Inline',

        [ValidateRange(0, 300)]
        [int]$StreamingSchemaTimeoutSeconds = 300,

        [ValidateRange(1, 3600)]
        [int]$RequestTimeout = 600,

        [string]$TempPath,

        [switch]$KeepTempFiles,

        [switch]$SkipBootstrap,

        [switch]$PassThru
    )

    begin {
        $sessionStagingPath = $null
        $cleanupCompleted = $false
        $tableStates = @{}
        $isSourceMode = $PSCmdlet.ParameterSetName -eq 'TypedSource'

        if (-not $isSourceMode -and [string]::IsNullOrWhiteSpace($TableName)) {
            throw 'Specify -TableName when -Source is not used.'
        }

        if (-not $ClusterUri -or [string]::IsNullOrWhiteSpace($Database)) {
            $configuredConnection = Get-XdrKustainerConnection
            if (-not $ClusterUri) {
                $ClusterUri = $configuredConnection.ClusterUri
            }
            if ([string]::IsNullOrWhiteSpace($Database)) {
                $Database = $configuredConnection.Database
            }
        }

        if ($ClusterUri.Scheme -notin @('http', 'https')) {
            throw 'Kustainer requires an http:// endpoint or an https:// reverse-proxy endpoint.'
        }

        if ($IngestionMode -eq 'Streaming') {
            Write-Warning 'Kustainer streaming ingestion is experimental. It works in tested container builds, but Microsoft currently documents streaming ingestion as unsupported by the emulator.'
        }

        $effectiveMaxBatchSizeMB = if ($PSBoundParameters.ContainsKey('MaxBatchSizeMB')) {
            $MaxBatchSizeMB
        }
        elseif ($IngestionMode -eq 'Streaming') {
            5.0
        }
        else {
            100.0
        }

        if ($IngestionMode -eq 'Streaming' -and $effectiveMaxBatchSizeMB -gt 10.0) {
            throw 'Kustainer streaming ingestion requests cannot exceed 10 MB. Specify -MaxBatchSizeMB 10 or less, or use inline ingestion for larger batches.'
        }

        $normalizedClusterUri = [uri]$ClusterUri.GetLeftPart([System.UriPartial]::Authority)
        $stagingRoot = if ($TempPath) { $TempPath } else { Join-Path ([System.IO.Path]::GetTempPath()) 'XdrKustainer' }
        $sessionStagingPath = Join-Path $stagingRoot ([guid]::NewGuid().ToString())
        $null = New-Item -ItemType Directory -Path $sessionStagingPath -Force
        $utf8 = [System.Text.UTF8Encoding]::new($false)
        $maxBatchSizeBytes = [int64][math]::Floor($effectiveMaxBatchSizeMB * 1MB)

        $newTableState = {
            param(
                [Parameter(Mandatory)]
                [string]$TargetTableName,

                [Parameter(Mandatory)]
                [string]$TargetMappingName,

                $TargetProfile
            )

            $tableStagingPath = Join-Path $sessionStagingPath $TargetTableName
            $null = New-Item -ItemType Directory -Path $tableStagingPath -Force

            return @{
                tableName     = $TargetTableName
                mappingName   = $TargetMappingName
                profile       = $TargetProfile
                initialized   = $false
                writer        = $null
                jsonPath      = $null
                rawSizeBytes  = 0L
                batchSequence = 0
                recordCount   = 0
                stagingPath   = $tableStagingPath
            }
        }

        $closeStagedBatch = {
            param(
                [Parameter(Mandatory)]
                [hashtable]$TableState
            )

            if (-not $TableState.writer -or $TableState.rawSizeBytes -le 0) {
                return
            }

            $TableState.writer.Flush()
            $TableState.writer.Dispose()
            $TableState.writer = $null

            if ($IngestionMode -eq 'Streaming') {
                $null = Send-XdrKustainerStreamingIngestion `
                    -ClusterUri $normalizedClusterUri `
                    -Database $Database `
                    -TableName $TableState.tableName `
                    -MappingName $TableState.mappingName `
                    -FilePath $TableState.jsonPath `
                    -SchemaPropagationTimeoutSeconds $StreamingSchemaTimeoutSeconds `
                    -RequestTimeout $RequestTimeout
            }
            else {
                $null = Send-XdrKustainerInlineIngestion `
                    -ClusterUri $normalizedClusterUri `
                    -Database $Database `
                    -TableName $TableState.tableName `
                    -MappingName $TableState.mappingName `
                    -FilePath $TableState.jsonPath `
                    -RequestTimeout $RequestTimeout
            }

            if (-not $KeepTempFiles) {
                Remove-Item -LiteralPath $TableState.jsonPath -Force -ErrorAction SilentlyContinue
            }

            $TableState.jsonPath = $null
            $TableState.rawSizeBytes = 0L
        }

        if (-not $isSourceMode) {
            $resolvedMappingName = if ($PSBoundParameters.ContainsKey('MappingName')) { $MappingName } else { "${TableName}_EventMapping" }
            $tableStates[$TableName] = & $newTableState $TableName $resolvedMappingName $null

            if (-not $SkipBootstrap) {
                $preserveExistingMapping = $PSBoundParameters.ContainsKey('MappingName')
                Initialize-XdrAzureDataExplorerTable `
                    -ClusterUri $normalizedClusterUri `
                    -Database $Database `
                    -TableName $TableName `
                    -MappingName $resolvedMappingName `
                    -PreserveExistingMapping:$preserveExistingMapping
                $tableStates[$TableName].initialized = $true
            }
        }
    }

    process {
        $targetTableName = $null
        $targetMappingName = $null
        $targetProfile = $null

        if ($isSourceMode) {
            $resolvedProfile = Resolve-XdrAzureDataExplorerTableProfile -Source $Source -InputEvent $Data
            if (-not $resolvedProfile) {
                if (-not $TableName) {
                    Write-Warning 'No table profile matched for event and no -TableName fallback was specified. Skipping event.'
                    if ($PassThru) { $Data }
                    return
                }

                $targetTableName = $TableName
                $targetMappingName = "${TableName}_EventMapping"
            }
            else {
                $targetTableName = $resolvedProfile.TableName
                $targetMappingName = "$($resolvedProfile.TableName)_EventMapping"
                $targetProfile = $resolvedProfile
            }
        }
        else {
            $targetTableName = $TableName
            $targetMappingName = $resolvedMappingName
        }

        if (-not $tableStates.ContainsKey($targetTableName)) {
            $tableStates[$targetTableName] = & $newTableState $targetTableName $targetMappingName $targetProfile
        }

        $tableState = $tableStates[$targetTableName]
        if (-not $tableState.initialized -and -not $SkipBootstrap) {
            $initializeParams = @{
                ClusterUri  = $normalizedClusterUri
                Database    = $Database
                TableName   = $tableState.tableName
                MappingName = $tableState.mappingName
            }
            if ($tableState.profile) {
                $initializeParams['TableProfile'] = $tableState.profile
            }

            Initialize-XdrAzureDataExplorerTable @initializeParams
            $tableState.initialized = $true
        }

        $jsonLine = $Data | ConvertTo-Json -Depth 20 -Compress
        $lineText = "$jsonLine`n"
        $lineByteCount = $utf8.GetByteCount($lineText)
        if ($lineByteCount -gt $maxBatchSizeBytes) {
            throw "A single serialized record is $lineByteCount bytes, which exceeds the configured maximum batch size of $maxBatchSizeBytes bytes."
        }

        if ($tableState.rawSizeBytes -gt 0 -and ($tableState.rawSizeBytes + $lineByteCount) -gt $maxBatchSizeBytes) {
            & $closeStagedBatch $tableState
        }

        if (-not $tableState.writer) {
            $tableState.jsonPath = Join-Path $tableState.stagingPath ("{0:D6}.json" -f $tableState.batchSequence)
            $tableState.writer = [System.IO.StreamWriter]::new($tableState.jsonPath, $false, $utf8)
            $tableState.batchSequence++
        }

        $tableState.writer.Write($lineText)
        $tableState.rawSizeBytes += $lineByteCount
        $tableState.recordCount++

        if ($PassThru) {
            $Data
        }
    }

    end {
        foreach ($tableState in $tableStates.Values) {
            & $closeStagedBatch $tableState
        }

        foreach ($tableState in $tableStates.Values) {
            if ($tableState.recordCount -gt 0) {
                Write-Verbose "Ingested $($tableState.recordCount) record(s) into Kustainer table '$($tableState.tableName)' using $IngestionMode ingestion."
            }
        }
    }

    clean {
        Clear-XdrAzureDataExplorerExportState `
            -TableStates $tableStates `
            -SessionStagingPath $sessionStagingPath `
            -KeepTempFiles:$KeepTempFiles `
            -CleanupCompleted ([ref]$cleanupCompleted)
    }
}
