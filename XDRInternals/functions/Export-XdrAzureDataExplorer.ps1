function Export-XdrAzureDataExplorer {
    <#
    .SYNOPSIS
        Exports pipeline data to Azure Data Explorer using queued ingestion.

    .DESCRIPTION
        Accepts pipeline input, stages records as newline-delimited JSON, compresses the staged
        files with gzip, uploads them to the Azure Data Explorer-managed staging container, and
        submits queued-ingestion requests.

        When used with -TableName alone, the cmdlet uses a raw-table pattern with a single
        Event:dynamic column. When used with -Source, the cmdlet automatically routes events
        to typed tables based on their ActionType or SourceTable, creating typed schemas with
        the appropriate column definitions and JSON ingestion mappings.

        Queued ingestion is asynchronous. After this cmdlet uploads blobs and submits ingestion
        requests, Azure Data Explorer may still take several minutes before the data is queryable.
        Use -TrackIngestion together with Get-XdrAzureDataExplorerIngestionStatus, or use
        -WaitForIngestion when you want the cmdlet to wait for queued ingestion to finish.

        Requires Set-XdrAzureDataExplorerConnection to be called first.

    .NOTES
        AUTHENTICATION: This cmdlet requires a separate Azure Data Explorer token, independent
        of your XDR portal session. The token is acquired automatically with the following
        priority: explicit token > Az.Accounts/Azure CLI for ADX resources > ESTS CLI bridge >
        Managed Identity.

        Connect-XdrBySSO and Set-XdrConnection (with raw sccauth/xsrf tokens) do NOT capture
        ESTS cookies, so the silent CLI bridge is unavailable. When using these methods, ensure
        you have an active Connect-AzAccount or az login session, or provide an explicit
        -AccessToken on Set-XdrAzureDataExplorerConnection.

    .PARAMETER Data
        The objects to export. Accepts pipeline input.

    .PARAMETER TableName
        The target Azure Data Explorer table name. Mandatory when -Source is not specified.
        When -Source is specified, -TableName is optional and serves as a fallback table for
        events that don't match any typed table profile.

    .PARAMETER Source
        Enables typed table routing. Events are automatically routed to the appropriate typed
        ADX table based on their ActionType or SourceTable. Each unique table gets its own
        staging file, blob upload, and ingestion submission.

    .PARAMETER MappingName
        Optional mapping name. Defaults to <TableName>_EventMapping. Only valid when -Source
        is not specified.

    .PARAMETER MaxBlobSizeMB
        Maximum uncompressed staging size, in MB, before the cmdlet rolls over to a new blob.
        The value is capped by the service's reported queued-ingestion maxDataSize.

    .PARAMETER TempPath
        Optional root path for temporary staging files.

    .PARAMETER KeepTempFiles
        Keeps temporary staging files instead of deleting them after upload.

    .PARAMETER SkipBootstrap
        Skips the create-if-missing table and mapping bootstrap logic.

    .PARAMETER DisableCompression
        Disables gzip compression for uploaded staging files.

    .PARAMETER TrackIngestion
        Requests ADX ingestion operation IDs for each queued ingestion request. Leave this disabled
        for high-volume exports unless you specifically need per-request tracking.

    .PARAMETER WaitForIngestion
        Waits for all queued ingestion requests submitted by this invocation to finish. This
        automatically enables tracking for the current export.

    .PARAMETER WaitTimeoutMinutes
        Maximum number of minutes to wait when -WaitForIngestion is specified.

    .PARAMETER StatusPollingIntervalSeconds
        Number of seconds between ingestion-status polls when -WaitForIngestion is specified.

    .PARAMETER PassThru
        Outputs the original input objects after staging them for ingestion.

    .EXAMPLE
        Set-XdrAzureDataExplorerConnection -ClusterUri "https://mycluster.westeurope.kusto.windows.net" -Database "Investigations"
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" | Export-XdrAzureDataExplorer -TableName "DeviceTimeline"

        Exports a device timeline to Azure Data Explorer using queued ingestion with a single dynamic table.

    .EXAMPLE
        Get-XdrIdentityUser -Upn "user@contoso.com" | Get-XdrIdentityUserTimeline -LastNDays 30 | Export-XdrAzureDataExplorer -TableName "IdentityTimeline" -PassThru

        Queues identity timeline data for ingestion and also passes the records through the pipeline.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -LastNDays 7 | Export-XdrAzureDataExplorer -TableName "DeviceTimeline" -TrackIngestion -Verbose

        Queues device timeline data for ingestion and asks ADX to return queued-ingestion operation IDs.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -LastNDays 7 | Export-XdrAzureDataExplorer -TableName "DeviceTimeline" -WaitForIngestion -Verbose

        Queues a device timeline export and waits until the queued-ingestion operations finish.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -LastNDays 7 | Export-XdrAzureDataExplorer -Source DeviceTimeline -Verbose

        Exports a device timeline using typed table routing. Events are automatically split across
        tables like XDRDeviceTimelineProcessEvents, XDRDeviceTimelineNetworkEvents, etc. based on
        their ActionType.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -LastNDays 7 | Export-XdrAzureDataExplorer -Source DeviceTimeline -TableName "DeviceTimelineFallback" -WaitForIngestion -Verbose

        Exports a device timeline using typed table routing with a fallback table for unrecognized
        event types, and waits for all queued ingestion operations to complete.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ManualTable')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Data,

        [Parameter(Mandatory, ParameterSetName = 'ManualTable')]
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

        [ValidateRange(10, 6144)]
        [int]$MaxBlobSizeMB = 1024,

        [string]$TempPath,

        [switch]$KeepTempFiles,

        [switch]$SkipBootstrap,

        [switch]$DisableCompression,

        [switch]$TrackIngestion,

        [switch]$WaitForIngestion,

        [ValidateRange(1, 1440)]
        [int]$WaitTimeoutMinutes = 30,

        [ValidateRange(1, 300)]
        [int]$StatusPollingIntervalSeconds = 15,

        [switch]$PassThru
    )

    begin {
        $connection = Get-XdrAzureDataExplorerConnection
        $isSourceMode = $PSCmdlet.ParameterSetName -eq 'TypedSource'

        $token = Get-XdrAzureAccessToken -Resource 'https://api.kusto.windows.net' `
            -Scope ("$($connection.ClusterUri.AbsoluteUri.TrimEnd('/'))/.default") `
            -TenantId $connection.TenantId `
            -ManagedIdentityClientId $connection.ManagedIdentityClientId `
            -AccessToken $connection.AccessToken `
            -ResourceDisplayName 'Azure Data Explorer'

        $shouldTrackIngestion = $TrackIngestion -or $WaitForIngestion
        $stagingRoot = if ($TempPath) {
            $TempPath
        }
        else {
            Join-Path ([System.IO.Path]::GetTempPath()) 'XdrAzureDataExplorer'
        }

        $sessionStagingPath = Join-Path $stagingRoot ([guid]::NewGuid().ToString())
        $null = New-Item -ItemType Directory -Path $sessionStagingPath -Force

        $utf8 = [System.Text.UTF8Encoding]::new($false)
        $tableStates = @{}
        $runtimeState = @{
            Configuration           = $null
            ContainerPath           = $null
            ServiceMaxDataSizeBytes = 0L
            TargetMaxBlobSizeBytes  = 0L
            MaxBlobsPerRequest      = 0
        }

        $updateIngestionRuntimeState = {
            param(
                [Parameter(Mandatory)]
                [hashtable]$State
            )

            $State.Configuration = Get-XdrAzureDataExplorerIngestionRuntimeConfiguration -IngestionUri $connection.IngestionUri -Token $token -MaxBlobSizeMB $MaxBlobSizeMB
            $State.ContainerPath = $State.Configuration.ContainerPath
            $State.ServiceMaxDataSizeBytes = $State.Configuration.ServiceMaxDataSizeBytes
            $State.TargetMaxBlobSizeBytes = $State.Configuration.TargetMaxBlobSizeBytes
            $State.MaxBlobsPerRequest = $State.Configuration.MaxBlobsPerRequest
        }

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
                tableName           = $TargetTableName
                mappingName         = $TargetMappingName
                profile             = $TargetProfile
                initialized         = $false
                writer              = $null
                jsonPath            = $null
                rawSizeBytes        = 0L
                pendingBlobs        = [System.Collections.Generic.List[hashtable]]::new()
                pendingRawSizeBytes = 0L
                queuedOperationIds  = [System.Collections.Generic.List[string]]::new()
                blobSequence        = 0
                recordCount         = 0
                stagingPath         = $tableStagingPath
            }
        }

        $submitPendingBlobBatch = {
            param(
                [Parameter(Mandatory)]
                [hashtable]$TableState
            )

            if ($TableState.pendingBlobs.Count -eq 0) {
                return
            }

            $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                -Database $connection.Database `
                -TableName $TableState.tableName `
                -MappingName $TableState.mappingName `
                -Token $token `
                -PendingBlobs $TableState.pendingBlobs `
                -PendingRawSizeBytes ([ref]$TableState.pendingRawSizeBytes) `
                -QueuedOperationIds $TableState.queuedOperationIds `
                -TrackIngestion:$shouldTrackIngestion
        }

        $refreshIngestionRuntimeIfDue = {
            if (-not (Test-XdrAzureDataExplorerIngestionConfigurationRefreshDue -Configuration $runtimeState.Configuration)) {
                return
            }

            foreach ($refreshTs in $tableStates.Values) {
                & $submitPendingBlobBatch $refreshTs
            }

            & $updateIngestionRuntimeState $runtimeState
        }

        $closeStagedBlob = {
            param(
                [Parameter(Mandatory)]
                [hashtable]$TableState,

                [bool]$SubmitWhenBatchFull = $false
            )

            if (-not $TableState.writer -or $TableState.rawSizeBytes -le 0) {
                return
            }

            $TableState.writer.Flush()
            $TableState.writer.Dispose()
            $TableState.writer = $null

            $uploadPath = $TableState.jsonPath
            $compressed = $false
            if (-not $DisableCompression) {
                $uploadPath = "$($TableState.jsonPath).gz"
                $null = Compress-XdrFileToGzip -SourcePath $TableState.jsonPath -DestinationPath $uploadPath
                $compressed = $true
            }

            & $refreshIngestionRuntimeIfDue

            $blobExtension = if ($compressed) { '.json.gz' } else { '.json' }
            $blobName = "XDRInternals/$($TableState.tableName)/$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N'))$blobExtension"
            $blobBuilder = [System.UriBuilder]::new([uri]$runtimeState.ContainerPath)
            $basePath = $blobBuilder.Path.TrimEnd('/')
            $blobBuilder.Path = if ([string]::IsNullOrEmpty($basePath)) { "/$blobName" } else { "$basePath/$blobName" }
            $blobUri = $blobBuilder.Uri.AbsoluteUri

            Send-XdrAzureDataExplorerBlobUpload -BlobUri $blobUri -FilePath $uploadPath -Compressed:$compressed

            if ($TableState.pendingBlobs.Count -gt 0 -and ($TableState.pendingRawSizeBytes + $TableState.rawSizeBytes) -gt $runtimeState.ServiceMaxDataSizeBytes) {
                & $submitPendingBlobBatch $TableState
            }

            $TableState.pendingBlobs.Add(@{
                    url      = $blobUri
                    sourceId = [guid]::NewGuid().Guid
                    rawSize  = $TableState.rawSizeBytes
                }) | Out-Null
            $TableState.pendingRawSizeBytes += $TableState.rawSizeBytes

            if ($SubmitWhenBatchFull -and $TableState.pendingBlobs.Count -ge $runtimeState.MaxBlobsPerRequest) {
                & $submitPendingBlobBatch $TableState
            }

            if (-not $KeepTempFiles) {
                Remove-Item -Path $TableState.jsonPath -Force -ErrorAction SilentlyContinue
                if ($compressed) {
                    Remove-Item -Path $uploadPath -Force -ErrorAction SilentlyContinue
                }
            }

            $TableState.jsonPath = $null
            $TableState.rawSizeBytes = 0L
        }

        & $updateIngestionRuntimeState $runtimeState

        if (-not $isSourceMode) {
            $resolvedMappingName = if ($PSBoundParameters.ContainsKey('MappingName')) {
                $MappingName
            }
            else {
                "${TableName}_EventMapping"
            }

            $tableStates[$TableName] = & $newTableState $TableName $resolvedMappingName $null

            if (-not $SkipBootstrap) {
                Initialize-XdrAzureDataExplorerTable -ClusterUri $connection.ClusterUri -Database $connection.Database -TableName $TableName -MappingName $resolvedMappingName -Token $token
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
                if ($TableName) {
                    $targetTableName = $TableName
                    $targetMappingName = "${TableName}_EventMapping"
                }
                else {
                    Write-Warning "No table profile matched for event and no -TableName fallback specified. Skipping event."
                    if ($PassThru) { $Data }
                    return
                }
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

        $ts = $tableStates[$targetTableName]
        if (-not $ts.initialized -and -not $SkipBootstrap) {
            $initParams = @{
                ClusterUri  = $connection.ClusterUri
                Database    = $connection.Database
                TableName   = $ts.tableName
                MappingName = $ts.mappingName
                Token       = $token
            }
            if ($ts.profile) {
                $initParams['TableProfile'] = $ts.profile
            }

            Initialize-XdrAzureDataExplorerTable @initParams
            $ts.initialized = $true
        }

        $jsonLine = $Data | ConvertTo-Json -Depth 20 -Compress
        $lineText = "$jsonLine`n"
        $lineByteCount = $utf8.GetByteCount($lineText)

        if ($lineByteCount -gt $runtimeState.TargetMaxBlobSizeBytes) {
            throw "A single serialized record is $lineByteCount bytes, which exceeds the configured maximum blob size of $($runtimeState.TargetMaxBlobSizeBytes) bytes."
        }

        if ($ts.rawSizeBytes -gt 0 -and ($ts.rawSizeBytes + $lineByteCount) -gt $runtimeState.TargetMaxBlobSizeBytes) {
            & $closeStagedBlob $ts $true
        }

        if (-not $ts.writer) {
            $ts.jsonPath = Join-Path $ts.stagingPath ("{0:D6}.json" -f $ts.blobSequence)
            $ts.writer = [System.IO.StreamWriter]::new($ts.jsonPath, $false, $utf8)
            $ts.rawSizeBytes = 0L
            $ts.blobSequence++
        }

        $ts.writer.Write($lineText)
        $ts.rawSizeBytes += $lineByteCount
        $ts.recordCount++

        if ($PassThru) {
            $Data
        }
    }

    end {
        try {
            foreach ($ts in $tableStates.Values) {
                & $closeStagedBlob $ts
            }

            foreach ($ts in $tableStates.Values) {
                & $submitPendingBlobBatch $ts
            }

            $totalRecords = ($tableStates.Values | Measure-Object -Property recordCount -Sum).Sum
            foreach ($ts in $tableStates.Values) {
                if ($ts.recordCount -le 0) {
                    continue
                }

                if ($isSourceMode) {
                    Write-Verbose "Queued $($ts.recordCount) record(s) for table '$($ts.tableName)'"
                }
                else {
                    Write-Verbose "Queued $($ts.recordCount) record(s) for Azure Data Explorer table '$($ts.tableName)'."
                }

                if ($shouldTrackIngestion -and $ts.queuedOperationIds.Count -gt 0) {
                    Write-Verbose "Queued ingestion operation IDs for '$($ts.tableName)': $($ts.queuedOperationIds -join ', ')"
                }
            }

            if ($totalRecords -gt 0 -and -not $WaitForIngestion) {
                Write-Verbose "Azure Data Explorer queued ingestion is asynchronous, so the exported data may take a few minutes before it becomes queryable."
            }

            if ($WaitForIngestion) {
                $allFailedStatuses = [System.Collections.Generic.List[pscustomobject]]::new()

                foreach ($ts in $tableStates.Values) {
                    if ($ts.queuedOperationIds.Count -eq 0) {
                        continue
                    }

                    $statuses = Wait-XdrAzureDataExplorerQueuedIngestion -IngestionUri $connection.IngestionUri `
                        -Database $connection.Database `
                        -TableName $ts.tableName `
                        -OperationId ($ts.queuedOperationIds.ToArray()) `
                        -Token $token `
                        -TimeoutMinutes $WaitTimeoutMinutes `
                        -PollingIntervalSeconds $StatusPollingIntervalSeconds `
                        -Details

                    $failedStatuses = @($statuses | Where-Object HasFailures)
                    foreach ($fs in $failedStatuses) {
                        $allFailedStatuses.Add($fs) | Out-Null
                    }
                }

                if ($allFailedStatuses.Count -gt 0) {
                    $failureSummary = $allFailedStatuses | ForEach-Object {
                        $detailText = if ($_.Details) {
                            @($_.Details | Where-Object { $_.Status -eq 'Failed' -or $_.Status -eq 'Canceled' } | ForEach-Object {
                                    if ($_.ErrorCode) { "$($_.ErrorCode): $($_.Details)" } else { $_.Details }
                                }) -join ' | '
                        }
                        else {
                            $null
                        }

                        if ([string]::IsNullOrWhiteSpace($detailText)) {
                            "$($_.OperationId) ($($_.Status))"
                        }
                        else {
                            "$($_.OperationId) ($($_.Status)): $detailText"
                        }
                    }

                    throw "One or more Azure Data Explorer queued ingestion operations failed: $($failureSummary -join '; ')"
                }

                if ($totalRecords -gt 0) {
                    Write-Verbose "All Azure Data Explorer queued ingestion operations completed successfully."
                }
            }
        }
        finally {
            foreach ($ts in $tableStates.Values) {
                if ($ts.writer) {
                    $ts.writer.Dispose()
                }
            }

            if (-not $KeepTempFiles -and $sessionStagingPath -and (Test-Path $sessionStagingPath)) {
                Remove-Item -Path $sessionStagingPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
