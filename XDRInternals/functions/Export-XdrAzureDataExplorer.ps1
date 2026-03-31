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
        priority: ESTS CLI bridge > Az.Accounts > Azure CLI > Managed Identity > explicit token.

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
        [ValidateSet('DeviceTimeline', 'IdentityTimeline', 'Alert', 'Incident', 'Device', 'AdvancedHunting')]
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

        $ingestionRuntime = Get-XdrAzureDataExplorerIngestionRuntimeConfiguration -IngestionUri $connection.IngestionUri -Token $token -MaxBlobSizeMB $MaxBlobSizeMB
        $containerPath = $ingestionRuntime.ContainerPath
        $serviceMaxDataSizeBytes = $ingestionRuntime.ServiceMaxDataSizeBytes
        $targetMaxBlobSizeBytes = $ingestionRuntime.TargetMaxBlobSizeBytes
        $maxBlobsPerRequest = $ingestionRuntime.MaxBlobsPerRequest
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

        if ($isSourceMode) {
            $tableStates = @{}
        }
        else {
            $resolvedMappingName = if ($PSBoundParameters.ContainsKey('MappingName')) {
                $MappingName
            }
            else {
                "${TableName}_EventMapping"
            }

            if (-not $SkipBootstrap) {
                Initialize-XdrAzureDataExplorerTable -ClusterUri $connection.ClusterUri -Database $connection.Database -TableName $TableName -MappingName $resolvedMappingName -Token $token
            }

            $pendingBlobs = [System.Collections.Generic.List[hashtable]]::new()
            $pendingRawSizeBytes = 0L
            $queuedOperationIds = [System.Collections.Generic.List[string]]::new()
            $blobSequence = 0
            $recordCount = 0
            $activeWriter = $null
            $activeJsonPath = $null
            $activeRawSizeBytes = 0L
        }
    }

    process {
        if ($isSourceMode) {
            $resolvedProfile = Resolve-XdrAzureDataExplorerTableProfile -Source $Source -InputEvent $Data

            if (-not $resolvedProfile) {
                if ($TableName) {
                    $targetTableName = $TableName
                    $targetMappingName = "${TableName}_EventMapping"
                    $targetProfile = $null
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

            if (-not $tableStates.ContainsKey($targetTableName)) {
                $tableStagingPath = Join-Path $sessionStagingPath $targetTableName
                $null = New-Item -ItemType Directory -Path $tableStagingPath -Force
                $tableStates[$targetTableName] = @{
                    tableName           = $targetTableName
                    mappingName         = $targetMappingName
                    profile             = $targetProfile
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

            $jsonLine = $Data | ConvertTo-Json -Depth 10 -Compress
            $lineText = "$jsonLine`n"
            $lineByteCount = $utf8.GetByteCount($lineText)

            if ($lineByteCount -gt $targetMaxBlobSizeBytes) {
                throw "A single serialized record is $lineByteCount bytes, which exceeds the configured maximum blob size of $targetMaxBlobSizeBytes bytes."
            }

            if (-not $ts.writer) {
                $ts.jsonPath = Join-Path $ts.stagingPath ("{0:D6}.json" -f $ts.blobSequence)
                $ts.writer = [System.IO.StreamWriter]::new($ts.jsonPath, $false, $utf8)
                $ts.rawSizeBytes = 0L
                $ts.blobSequence++
            }

            if ($ts.rawSizeBytes -gt 0 -and ($ts.rawSizeBytes + $lineByteCount) -gt $targetMaxBlobSizeBytes) {
                $ts.writer.Flush()
                $ts.writer.Dispose()
                $ts.writer = $null

                $uploadPath = $ts.jsonPath
                $compressed = $false
                if (-not $DisableCompression) {
                    $uploadPath = "$($ts.jsonPath).gz"
                    $null = Compress-XdrFileToGzip -SourcePath $ts.jsonPath -DestinationPath $uploadPath
                    $compressed = $true
                }

                if (Test-XdrAzureDataExplorerIngestionConfigurationRefreshDue -Configuration $ingestionRuntime) {
                    foreach ($refreshTs in $tableStates.Values) {
                        if ($refreshTs.pendingBlobs.Count -gt 0) {
                            $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                                -Database $connection.Database `
                                -TableName $refreshTs.tableName `
                                -MappingName $refreshTs.mappingName `
                                -Token $token `
                                -PendingBlobs $refreshTs.pendingBlobs `
                                -PendingRawSizeBytes ([ref]$refreshTs.pendingRawSizeBytes) `
                                -QueuedOperationIds $refreshTs.queuedOperationIds `
                                -TrackIngestion:$shouldTrackIngestion
                        }
                    }

                    $ingestionRuntime = Get-XdrAzureDataExplorerIngestionRuntimeConfiguration -IngestionUri $connection.IngestionUri -Token $token -MaxBlobSizeMB $MaxBlobSizeMB
                    $containerPath = $ingestionRuntime.ContainerPath
                    $serviceMaxDataSizeBytes = $ingestionRuntime.ServiceMaxDataSizeBytes
                    $targetMaxBlobSizeBytes = $ingestionRuntime.TargetMaxBlobSizeBytes
                    $maxBlobsPerRequest = $ingestionRuntime.MaxBlobsPerRequest
                }

                $blobExtension = if ($compressed) { '.json.gz' } else { '.json' }
                $blobName = "XDRInternals/$($ts.tableName)/$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N'))$blobExtension"
                $blobUri = Get-XdrAzureDataExplorerBlobUri -ContainerUri $containerPath -BlobName $blobName

                Send-XdrAzureDataExplorerBlobUpload -BlobUri $blobUri -FilePath $uploadPath -Compressed:$compressed

                if ($ts.pendingBlobs.Count -gt 0 -and ($ts.pendingRawSizeBytes + $ts.rawSizeBytes) -gt $serviceMaxDataSizeBytes) {
                    $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                        -Database $connection.Database `
                        -TableName $ts.tableName `
                        -MappingName $ts.mappingName `
                        -Token $token `
                        -PendingBlobs $ts.pendingBlobs `
                        -PendingRawSizeBytes ([ref]$ts.pendingRawSizeBytes) `
                        -QueuedOperationIds $ts.queuedOperationIds `
                        -TrackIngestion:$shouldTrackIngestion
                }

                $ts.pendingBlobs.Add(@{
                        url      = $blobUri
                        sourceId = [guid]::NewGuid().Guid
                        rawSize  = $ts.rawSizeBytes
                    }) | Out-Null
                $ts.pendingRawSizeBytes += $ts.rawSizeBytes

                if ($ts.pendingBlobs.Count -ge $maxBlobsPerRequest) {
                    $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                        -Database $connection.Database `
                        -TableName $ts.tableName `
                        -MappingName $ts.mappingName `
                        -Token $token `
                        -PendingBlobs $ts.pendingBlobs `
                        -PendingRawSizeBytes ([ref]$ts.pendingRawSizeBytes) `
                        -QueuedOperationIds $ts.queuedOperationIds `
                        -TrackIngestion:$shouldTrackIngestion
                }

                if (-not $KeepTempFiles) {
                    Remove-Item -Path $ts.jsonPath -Force -ErrorAction SilentlyContinue
                    if ($compressed) {
                        Remove-Item -Path $uploadPath -Force -ErrorAction SilentlyContinue
                    }
                }

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
        else {
            $jsonLine = $Data | ConvertTo-Json -Depth 10 -Compress
            $lineText = "$jsonLine`n"
            $lineByteCount = $utf8.GetByteCount($lineText)

            if ($lineByteCount -gt $targetMaxBlobSizeBytes) {
                throw "A single serialized record is $lineByteCount bytes, which exceeds the configured maximum blob size of $targetMaxBlobSizeBytes bytes."
            }

            if (-not $activeWriter) {
                $activeJsonPath = Join-Path $sessionStagingPath ("{0:D6}.json" -f $blobSequence)
                $activeWriter = [System.IO.StreamWriter]::new($activeJsonPath, $false, $utf8)
                $activeRawSizeBytes = 0L
                $blobSequence++
            }

            if ($activeRawSizeBytes -gt 0 -and ($activeRawSizeBytes + $lineByteCount) -gt $targetMaxBlobSizeBytes) {
                $activeWriter.Flush()
                $activeWriter.Dispose()
                $activeWriter = $null

                $uploadPath = $activeJsonPath
                $compressed = $false
                if (-not $DisableCompression) {
                    $uploadPath = "$activeJsonPath.gz"
                    $null = Compress-XdrFileToGzip -SourcePath $activeJsonPath -DestinationPath $uploadPath
                    $compressed = $true
                }

                if (Test-XdrAzureDataExplorerIngestionConfigurationRefreshDue -Configuration $ingestionRuntime) {
                    if ($pendingBlobs.Count -gt 0) {
                        $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                            -Database $connection.Database `
                            -TableName $TableName `
                            -MappingName $resolvedMappingName `
                            -Token $token `
                            -PendingBlobs $pendingBlobs `
                            -PendingRawSizeBytes ([ref]$pendingRawSizeBytes) `
                            -QueuedOperationIds $queuedOperationIds `
                            -TrackIngestion:$shouldTrackIngestion
                    }

                    $ingestionRuntime = Get-XdrAzureDataExplorerIngestionRuntimeConfiguration -IngestionUri $connection.IngestionUri -Token $token -MaxBlobSizeMB $MaxBlobSizeMB
                    $containerPath = $ingestionRuntime.ContainerPath
                    $serviceMaxDataSizeBytes = $ingestionRuntime.ServiceMaxDataSizeBytes
                    $targetMaxBlobSizeBytes = $ingestionRuntime.TargetMaxBlobSizeBytes
                    $maxBlobsPerRequest = $ingestionRuntime.MaxBlobsPerRequest
                }

                $blobExtension = if ($compressed) { '.json.gz' } else { '.json' }
                $blobName = "XDRInternals/$TableName/$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N'))$blobExtension"
                $blobUri = Get-XdrAzureDataExplorerBlobUri -ContainerUri $containerPath -BlobName $blobName

                Send-XdrAzureDataExplorerBlobUpload -BlobUri $blobUri -FilePath $uploadPath -Compressed:$compressed

                if ($pendingBlobs.Count -gt 0 -and ($pendingRawSizeBytes + $activeRawSizeBytes) -gt $serviceMaxDataSizeBytes) {
                    $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                        -Database $connection.Database `
                        -TableName $TableName `
                        -MappingName $resolvedMappingName `
                        -Token $token `
                        -PendingBlobs $pendingBlobs `
                        -PendingRawSizeBytes ([ref]$pendingRawSizeBytes) `
                        -QueuedOperationIds $queuedOperationIds `
                        -TrackIngestion:$shouldTrackIngestion
                }

                $pendingBlobs.Add(@{
                        url      = $blobUri
                        sourceId = [guid]::NewGuid().Guid
                        rawSize  = $activeRawSizeBytes
                    }) | Out-Null
                $pendingRawSizeBytes += $activeRawSizeBytes

                if ($pendingBlobs.Count -ge $maxBlobsPerRequest) {
                    $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                        -Database $connection.Database `
                        -TableName $TableName `
                        -MappingName $resolvedMappingName `
                        -Token $token `
                        -PendingBlobs $pendingBlobs `
                        -PendingRawSizeBytes ([ref]$pendingRawSizeBytes) `
                        -QueuedOperationIds $queuedOperationIds `
                        -TrackIngestion:$shouldTrackIngestion
                }

                if (-not $KeepTempFiles) {
                    Remove-Item -Path $activeJsonPath -Force -ErrorAction SilentlyContinue
                    if ($compressed) {
                        Remove-Item -Path $uploadPath -Force -ErrorAction SilentlyContinue
                    }
                }

                $activeJsonPath = Join-Path $sessionStagingPath ("{0:D6}.json" -f $blobSequence)
                $activeWriter = [System.IO.StreamWriter]::new($activeJsonPath, $false, $utf8)
                $activeRawSizeBytes = 0L
                $blobSequence++
            }

            $activeWriter.Write($lineText)
            $activeRawSizeBytes += $lineByteCount
            $recordCount++

            if ($PassThru) {
                $Data
            }
        }
    }

    end {
        try {
            if ($isSourceMode) {
                foreach ($ts in $tableStates.Values) {
                    if ($ts.writer -and $ts.rawSizeBytes -gt 0) {
                        $ts.writer.Flush()
                        $ts.writer.Dispose()
                        $ts.writer = $null

                        $uploadPath = $ts.jsonPath
                        $compressed = $false
                        if (-not $DisableCompression) {
                            $uploadPath = "$($ts.jsonPath).gz"
                            $null = Compress-XdrFileToGzip -SourcePath $ts.jsonPath -DestinationPath $uploadPath
                            $compressed = $true
                        }

                        if (Test-XdrAzureDataExplorerIngestionConfigurationRefreshDue -Configuration $ingestionRuntime) {
                            foreach ($refreshTs in $tableStates.Values) {
                                if ($refreshTs.pendingBlobs.Count -gt 0) {
                                    $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                                        -Database $connection.Database `
                                        -TableName $refreshTs.tableName `
                                        -MappingName $refreshTs.mappingName `
                                        -Token $token `
                                        -PendingBlobs $refreshTs.pendingBlobs `
                                        -PendingRawSizeBytes ([ref]$refreshTs.pendingRawSizeBytes) `
                                        -QueuedOperationIds $refreshTs.queuedOperationIds `
                                        -TrackIngestion:$shouldTrackIngestion
                                }
                            }

                            $ingestionRuntime = Get-XdrAzureDataExplorerIngestionRuntimeConfiguration -IngestionUri $connection.IngestionUri -Token $token -MaxBlobSizeMB $MaxBlobSizeMB
                            $containerPath = $ingestionRuntime.ContainerPath
                            $serviceMaxDataSizeBytes = $ingestionRuntime.ServiceMaxDataSizeBytes
                            $targetMaxBlobSizeBytes = $ingestionRuntime.TargetMaxBlobSizeBytes
                            $maxBlobsPerRequest = $ingestionRuntime.MaxBlobsPerRequest
                        }

                        $blobExtension = if ($compressed) { '.json.gz' } else { '.json' }
                        $blobName = "XDRInternals/$($ts.tableName)/$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N'))$blobExtension"
                        $blobUri = Get-XdrAzureDataExplorerBlobUri -ContainerUri $containerPath -BlobName $blobName

                        Send-XdrAzureDataExplorerBlobUpload -BlobUri $blobUri -FilePath $uploadPath -Compressed:$compressed

                        if ($ts.pendingBlobs.Count -gt 0 -and ($ts.pendingRawSizeBytes + $ts.rawSizeBytes) -gt $serviceMaxDataSizeBytes) {
                            $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                                -Database $connection.Database `
                                -TableName $ts.tableName `
                                -MappingName $ts.mappingName `
                                -Token $token `
                                -PendingBlobs $ts.pendingBlobs `
                                -PendingRawSizeBytes ([ref]$ts.pendingRawSizeBytes) `
                                -QueuedOperationIds $ts.queuedOperationIds `
                                -TrackIngestion:$shouldTrackIngestion
                        }

                        $ts.pendingBlobs.Add(@{
                                url      = $blobUri
                                sourceId = [guid]::NewGuid().Guid
                                rawSize  = $ts.rawSizeBytes
                            }) | Out-Null
                        $ts.pendingRawSizeBytes += $ts.rawSizeBytes

                        if (-not $KeepTempFiles) {
                            Remove-Item -Path $ts.jsonPath -Force -ErrorAction SilentlyContinue
                            if ($compressed) {
                                Remove-Item -Path $uploadPath -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }

                foreach ($ts in $tableStates.Values) {
                    if ($ts.pendingBlobs.Count -gt 0) {
                        $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                            -Database $connection.Database `
                            -TableName $ts.tableName `
                            -MappingName $ts.mappingName `
                            -Token $token `
                            -PendingBlobs $ts.pendingBlobs `
                            -PendingRawSizeBytes ([ref]$ts.pendingRawSizeBytes) `
                            -QueuedOperationIds $ts.queuedOperationIds `
                            -TrackIngestion:$shouldTrackIngestion
                    }
                }

                foreach ($ts in $tableStates.Values) {
                    if ($ts.recordCount -gt 0) {
                        Write-Verbose "Queued $($ts.recordCount) record(s) for table '$($ts.tableName)'"
                        if ($shouldTrackIngestion -and $ts.queuedOperationIds.Count -gt 0) {
                            Write-Verbose "  Queued ingestion operation IDs: $($ts.queuedOperationIds -join ', ')"
                        }
                    }
                }

                $totalRecords = ($tableStates.Values | Measure-Object -Property recordCount -Sum).Sum
                if ($totalRecords -gt 0 -and -not $WaitForIngestion) {
                    Write-Verbose "Azure Data Explorer queued ingestion is asynchronous, so the exported data may take a few minutes before it becomes queryable."
                }

                if ($WaitForIngestion) {
                    $allFailedStatuses = [System.Collections.Generic.List[pscustomobject]]::new()

                    foreach ($ts in $tableStates.Values) {
                        if ($ts.queuedOperationIds.Count -eq 0) { continue }

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

                    Write-Verbose "All Azure Data Explorer queued ingestion operations completed successfully."
                }
            }
            else {
                if ($activeWriter -and $activeRawSizeBytes -gt 0) {
                    $activeWriter.Flush()
                    $activeWriter.Dispose()
                    $activeWriter = $null

                    $uploadPath = $activeJsonPath
                    $compressed = $false
                    if (-not $DisableCompression) {
                        $uploadPath = "$activeJsonPath.gz"
                        $null = Compress-XdrFileToGzip -SourcePath $activeJsonPath -DestinationPath $uploadPath
                        $compressed = $true
                    }

                    if (Test-XdrAzureDataExplorerIngestionConfigurationRefreshDue -Configuration $ingestionRuntime) {
                        if ($pendingBlobs.Count -gt 0) {
                            $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                                -Database $connection.Database `
                                -TableName $TableName `
                                -MappingName $resolvedMappingName `
                                -Token $token `
                                -PendingBlobs $pendingBlobs `
                                -PendingRawSizeBytes ([ref]$pendingRawSizeBytes) `
                                -QueuedOperationIds $queuedOperationIds `
                                -TrackIngestion:$shouldTrackIngestion
                        }

                        $ingestionRuntime = Get-XdrAzureDataExplorerIngestionRuntimeConfiguration -IngestionUri $connection.IngestionUri -Token $token -MaxBlobSizeMB $MaxBlobSizeMB
                        $containerPath = $ingestionRuntime.ContainerPath
                        $serviceMaxDataSizeBytes = $ingestionRuntime.ServiceMaxDataSizeBytes
                        $targetMaxBlobSizeBytes = $ingestionRuntime.TargetMaxBlobSizeBytes
                        $maxBlobsPerRequest = $ingestionRuntime.MaxBlobsPerRequest
                    }

                    $blobExtension = if ($compressed) { '.json.gz' } else { '.json' }
                    $blobName = "XDRInternals/$TableName/$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N'))$blobExtension"
                    $blobUri = Get-XdrAzureDataExplorerBlobUri -ContainerUri $containerPath -BlobName $blobName

                    Send-XdrAzureDataExplorerBlobUpload -BlobUri $blobUri -FilePath $uploadPath -Compressed:$compressed

                    if ($pendingBlobs.Count -gt 0 -and ($pendingRawSizeBytes + $activeRawSizeBytes) -gt $serviceMaxDataSizeBytes) {
                        $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                            -Database $connection.Database `
                            -TableName $TableName `
                            -MappingName $resolvedMappingName `
                            -Token $token `
                            -PendingBlobs $pendingBlobs `
                            -PendingRawSizeBytes ([ref]$pendingRawSizeBytes) `
                            -QueuedOperationIds $queuedOperationIds `
                            -TrackIngestion:$shouldTrackIngestion
                    }

                    $pendingBlobs.Add(@{
                            url      = $blobUri
                            sourceId = [guid]::NewGuid().Guid
                            rawSize  = $activeRawSizeBytes
                        }) | Out-Null
                    $pendingRawSizeBytes += $activeRawSizeBytes

                    if (-not $KeepTempFiles) {
                        Remove-Item -Path $activeJsonPath -Force -ErrorAction SilentlyContinue
                        if ($compressed) {
                            Remove-Item -Path $uploadPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                }

                if ($pendingBlobs.Count -gt 0) {
                    $null = Submit-XdrAzureDataExplorerQueuedIngestionBatch -IngestionUri $connection.IngestionUri `
                        -Database $connection.Database `
                        -TableName $TableName `
                        -MappingName $resolvedMappingName `
                        -Token $token `
                        -PendingBlobs $pendingBlobs `
                        -PendingRawSizeBytes ([ref]$pendingRawSizeBytes) `
                        -QueuedOperationIds $queuedOperationIds `
                        -TrackIngestion:$shouldTrackIngestion
                }

                if ($recordCount -gt 0) {
                    Write-Verbose "Queued $recordCount record(s) for Azure Data Explorer table '$TableName'."
                    if ($shouldTrackIngestion -and $queuedOperationIds.Count -gt 0) {
                        Write-Verbose "Queued ingestion operation IDs: $($queuedOperationIds -join ', ')"
                    }
                    if (-not $WaitForIngestion) {
                        Write-Verbose "Azure Data Explorer queued ingestion is asynchronous, so the exported data may take a few minutes before it becomes queryable."
                    }
                }

                if ($WaitForIngestion -and $queuedOperationIds.Count -gt 0) {
                    $statuses = Wait-XdrAzureDataExplorerQueuedIngestion -IngestionUri $connection.IngestionUri `
                        -Database $connection.Database `
                        -TableName $TableName `
                        -OperationId ($queuedOperationIds.ToArray()) `
                        -Token $token `
                        -TimeoutMinutes $WaitTimeoutMinutes `
                        -PollingIntervalSeconds $StatusPollingIntervalSeconds `
                        -Details

                    $failedStatuses = @($statuses | Where-Object HasFailures)
                    if ($failedStatuses.Count -gt 0) {
                        $failureSummary = $failedStatuses | ForEach-Object {
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

                    Write-Verbose "All Azure Data Explorer queued ingestion operations completed successfully."
                }
            }
        }
        finally {
            if ($isSourceMode) {
                foreach ($ts in $tableStates.Values) {
                    if ($ts.writer) {
                        $ts.writer.Dispose()
                    }
                }
            }
            else {
                if ($activeWriter) {
                    $activeWriter.Dispose()
                }
            }

            if (-not $KeepTempFiles -and $sessionStagingPath -and (Test-Path $sessionStagingPath)) {
                Remove-Item -Path $sessionStagingPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
