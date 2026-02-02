function Get-XdrEndpointDeviceTimeline {
    <#
    .SYNOPSIS
        Retrieves the timeline of events for a specific device from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the timeline of security events for a device from the Microsoft Defender XDR portal with options to filter by date range and other parameters.
        Uses parallel chunked requests (1-hour intervals) to improve performance and support longer date ranges up to 180 days.

    .PARAMETER DeviceId
        The unique identifier of the device. Accepts pipeline input and can also be specified as MachineId. Use this parameter set when identifying the device by ID.

    .PARAMETER MachineDnsName
        The DNS name of the machine. Use this parameter set when identifying the device by DNS name.

    .PARAMETER MarkedEventsOnly
        Only return events that have been marked in the timeline.

    .PARAMETER SenseClientVersion
        Optional. The version of the Sense client.

    .PARAMETER SkipIdentityEvents
        Skip generating and including identity events. By default, identity events are included.

    .PARAMETER SkipMdiOnlyEvents
        Skip MDI-only events. By default, MDI-only events are supported.

    .PARAMETER FromDate
        The start date for the timeline. Defaults to 1 hour before current time.

    .PARAMETER ToDate
        The end date for the timeline. Defaults to current time.

    .PARAMETER LastNDays
        Specifies the number of days to look back. Overrides FromDate and ToDate if specified.

    .PARAMETER DoNotUseCache
        Bypass the API cache when retrieving timeline data.

    .PARAMETER ForceUseCache
        Force using the API cache when retrieving timeline data.

    .PARAMETER PageSize
        The number of events to return per page. Defaults to 1000 for optimal performance.

    .PARAMETER IncludeSentinelEvents
        Include Sentinel events in the timeline results.

    .PARAMETER EventType
        Filter events by type. Supports wildcards. Examples: 'Process*', 'Network*', 'File*'.

    .PARAMETER EventsGroups
        Filter events by group category. Accepts one or more of the following values:
        AlertsRelatedEvents, AntiVirus, AppGuard, AppControl, ExploitGuard, Files, Firewall,
        Network, Processes, Registry, ResponseActions, ScheduledTask, SmartScreen, Other, UserActivity.
        Multiple values can be specified to include multiple event groups.

    .PARAMETER DataTypes
        Filter events by data type. Accepts one or more of the following values: Events, Techniques.
        Multiple values can be specified to include multiple data types.

    .PARAMETER SourceProviders
        Filter events by source provider. Accepts one or more of the following values: MDE, MDI.
        Multiple values can be specified to include multiple source providers.

    .PARAMETER ThrottleLimit
        The maximum number of concurrent requests. Defaults to 10.

    .PARAMETER TimeoutSeconds
        Maximum time in seconds to wait for all requests to complete. Defaults to 3600 (1 hour).

    .PARAMETER MaxRetries
        Maximum number of retry attempts for failed API requests. Defaults to 10.

    .PARAMETER RetryDelaySeconds
        Base delay in seconds between retry attempts (uses exponential backoff). Defaults to 30.

    .PARAMETER ChunkHours
        The size of each time chunk in hours for parallel processing. Defaults to 4 hours.
        For time windows of 40 hours or less, chunk size is automatically calculated as totalHours/10.
        Larger chunks reduce overhead but may increase individual request times.

    .PARAMETER OutputPath
        Optional. The path to store temporary JSON files. Defaults to a temp folder.

    .PARAMETER KeepTempFiles
        If specified, keeps the temporary JSON files after merging.

    .PARAMETER ExportPath
        Optional. Export results directly to a JSON file at the specified path.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2"
        Retrieves the last hour of timeline events for the specified device.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -MachineDnsName "computer.contoso.com"
        Retrieves the last hour of timeline events using the machine DNS name.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -FromDate (Get-Date).AddDays(-7) -ToDate (Get-Date)
        Retrieves timeline events for the last 7 days using parallel requests.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -LastNDays 90 -ThrottleLimit 5
        Retrieves 90 days of timeline events with 5 concurrent requests.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -EventType "Process*"
        Retrieves timeline events filtered to process-related events only.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -LastNDays 7 -ExportPath "C:\Reports\timeline.json"
        Retrieves 7 days of timeline events and exports directly to a JSON file.

    .EXAMPLE
        "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" | Get-XdrEndpointDeviceTimeline
        Retrieves timeline events using pipeline input.
    #>
    [OutputType([System.Object[]])]
    # Suppress false positive: $chunks and $throttle ARE declared via param() in Start-ThreadJob scriptblock
    # and passed via -ArgumentList, but PSScriptAnalyzer incorrectly flags them as needing $using: scope
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
    [CmdletBinding(DefaultParameterSetName = 'ByDeviceId')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByDeviceId')]
        [Alias('MachineId')]
        [string]$DeviceId,

        [Parameter(Mandatory, ParameterSetName = 'ByMachineDnsName')]
        [string]$MachineDnsName,

        [Parameter()]
        [datetime]$FromDate = ((Get-Date).AddHours(-1)),

        [Parameter()]
        [datetime]$ToDate = (Get-Date),

        [Parameter()]
        [int]$LastNDays,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 1000,

        [Parameter()]
        [switch]$MarkedEventsOnly,

        [Parameter()]
        [string]$SenseClientVersion,

        [Parameter()]
        [switch]$SkipIdentityEvents,

        [Parameter()]
        [switch]$SkipMdiOnlyEvents,

        [Parameter()]
        [switch]$DoNotUseCache,

        [Parameter()]
        [switch]$ForceUseCache,

        [Parameter()]
        [switch]$IncludeSentinelEvents,

        [Parameter()]
        [string]$EventType,

        [Parameter()]
        [ValidateSet('AlertsRelatedEvents', 'AntiVirus', 'AppGuard', 'AppControl', 'ExploitGuard', 'Files', 'Firewall', 'Network', 'Processes', 'Registry', 'ResponseActions', 'ScheduledTask', 'SmartScreen', 'Other', 'UserActivity')]
        [string[]]$EventsGroups,

        [Parameter()]
        [ValidateSet('Events', 'Techniques')]
        [string[]]$DataTypes,

        [Parameter()]
        [ValidateSet('MDE', 'MDI')]
        [string[]]$SourceProviders,

        [Parameter()]
        [ValidateRange(1, 20)]
        [int]$ThrottleLimit = 10,

        [Parameter()]
        [ValidateRange(60, 86400)]
        [int]$TimeoutSeconds = 3600,

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$MaxRetries = 10,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$RetryDelaySeconds = 30,

        [Parameter()]
        [ValidateRange(1, 24)]
        [int]$ChunkHours = 4,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [switch]$KeepTempFiles,

        [Parameter()]
        [string]$ExportPath
    )

    begin {
        Update-XdrConnectionSettings

        # Module-level base URL for consistency
        $script:XdrBaseUrl = "https://security.microsoft.com"
    }

    process {
        if ($PSBoundParameters.ContainsKey('LastNDays')) {
            $ToDate = Get-Date
            $FromDate = $ToDate.AddDays(-$LastNDays)
        }

        # Validate time range (180 days max)
        if (($ToDate - $FromDate).TotalDays -gt 180) {
            throw "The time range between FromDate and ToDate cannot exceed 180 days."
        }

        # Validate cache parameters are not both specified
        if ($DoNotUseCache -and $ForceUseCache) {
            throw "DoNotUseCache and ForceUseCache cannot both be specified. Use DoNotUseCache to bypass the cache, or ForceUseCache to force using cached data."
        }

        # Determine the device identifier with proper error handling
        $deviceLookup = $null
        if ($PSCmdlet.ParameterSetName -eq 'ByDeviceId') {
            $deviceIdentifier = $DeviceId
            # Note: Get-XdrEndpointDevice only supports MachineSearchPrefix (name prefix search),
            # not lookup by MachineId, so we skip device lookup when using -DeviceId
        } else {
            Write-Verbose "Looking up device by DNS name: $MachineDnsName"
            $deviceLookup = Get-XdrEndpointDevice -MachineSearchPrefix $MachineDnsName
            if (-not $deviceLookup) {
                throw "Could not find device with DNS name '$MachineDnsName'. Please verify the device exists and you have access."
            }
            $deviceIdentifier = $deviceLookup | Select-Object -First 1 -ExpandProperty MachineId
            if (-not $deviceIdentifier) {
                throw "Device lookup for '$MachineDnsName' returned results but MachineId was empty."
            }
            Write-Verbose "Resolved '$MachineDnsName' to device ID: $deviceIdentifier"
        }

        # Get the ComputerDnsName for folder naming
        # Reuse $deviceLookup from DNS name resolution if available, otherwise use DeviceId as folder name
        # (Get-XdrEndpointDevice doesn't support lookup by MachineId)
        $computerDnsName = if ($deviceLookup) {
            ($deviceLookup | Select-Object -First 1).ComputerDnsName
        } else {
            $deviceIdentifier
        }
        # Sanitize folder name - ensure we have a valid value
        if ([string]::IsNullOrWhiteSpace($computerDnsName)) {
            $computerDnsName = $deviceIdentifier
        }
        # Remove invalid path characters (covers Windows and Unix)
        $safeFolderName = $computerDnsName -replace '[\\/:*?"<>|]', '_'

        # Set up output directory using cross-platform temp path
        $baseTempPath = if ($OutputPath) {
            $OutputPath
        } else {
            Join-Path ([System.IO.Path]::GetTempPath()) 'XdrTimeline'
        }
        $deviceTempPath = Join-Path $baseTempPath $safeFolderName
        $runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $runTempPath = Join-Path $deviceTempPath $runId

        # Create temporary directory for chunk files
        if (-not (Test-Path $runTempPath)) {
            New-Item -Path $runTempPath -ItemType Directory -Force | Out-Null
        }
        Write-Verbose "Temporary files will be stored in: $runTempPath"

        # Build the base query parameters (without date range)
        # Convert switch parameters to boolean values for serialization
        $baseQueryParams = @{
            GenerateIdentityEvents = -not $SkipIdentityEvents.IsPresent
            IncludeIdentityEvents  = -not $SkipIdentityEvents.IsPresent
            SupportMdiOnlyEvents   = -not $SkipMdiOnlyEvents.IsPresent
            DoNotUseCache          = $DoNotUseCache.IsPresent
            ForceUseCache          = $ForceUseCache.IsPresent
            PageSize               = $PageSize
            IncludeSentinelEvents  = $IncludeSentinelEvents.IsPresent
            MarkedEventsOnly       = $MarkedEventsOnly.IsPresent
            SenseClientVersion     = $SenseClientVersion
            MachineDnsName         = if ($PSBoundParameters.ContainsKey('MachineDnsName')) { $MachineDnsName } else { $null }
            EventsGroups           = if ($PSBoundParameters.ContainsKey('EventsGroups')) { $EventsGroups } else { $null }
            DataTypes              = if ($PSBoundParameters.ContainsKey('DataTypes')) { $DataTypes } else { $null }
            SourceProviders        = if ($PSBoundParameters.ContainsKey('SourceProviders')) { $SourceProviders } else { $null }
            MaxRetries             = $MaxRetries
            RetryDelaySeconds      = $RetryDelaySeconds
        }

        # Generate date chunks using configurable chunk size
        $dateChunks = [System.Collections.Generic.List[hashtable]]::new()
        $totalDays = ($ToDate - $FromDate).TotalDays
        $totalHours = $totalDays * 24

        # For small time windows (≤40 hours), dynamically calculate chunk size unless explicitly specified
        if (-not $PSBoundParameters.ContainsKey('ChunkHours') -and $totalHours -le 40) {
            $ChunkHours = [math]::Max(1, [math]::Ceiling($totalHours / 10))
            Write-Verbose "Auto-calculated ChunkHours=$ChunkHours for $([math]::Round($totalHours, 1)) hour time window"
        }

        # Use configurable chunk size (default 4 hours, or auto-calculated for small windows)
        $currentDate = $FromDate
        $chunkIndex = 0
        while ($currentDate -lt $ToDate) {
            $chunkEnd = $currentDate.AddHours($ChunkHours)
            if ($chunkEnd -gt $ToDate) {
                $chunkEnd = $ToDate
            }
            $DifferenceInSeconds = ($chunkEnd - $currentDate).TotalSeconds
            Write-Debug "Chunk difference in seconds: $DifferenceInSeconds"
            if ($DifferenceInSeconds -lt 1) {
                # Prevent infinite loop in case of unexpected date calculation
                Write-Debug "Chunk difference is less than 1 second; stopping chunk generation to avoid infinite loop."
                break
            }
            $dateChunks.Add(@{
                    FromDate = $currentDate
                    ToDate   = $chunkEnd
                    Index    = $chunkIndex
                })
            Write-Debug "$($dateChunks[$chunkIndex].FromDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) to $($dateChunks[$chunkIndex].ToDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
            $chunkIndex++
            $currentDate = $chunkEnd
        }
        Write-Information "Split $([math]::Round($totalHours, 1)) hours into $($dateChunks.Count) chunks ($ChunkHours hour$(if($ChunkHours -gt 1){'s'}) each)" -InformationAction Continue

        # Store session cookies as a serializable format for parallel execution
        $cookieContainer = $script:session.Cookies
        $cookies = $cookieContainer.GetCookies([Uri]$script:XdrBaseUrl)
        $cookieData = @()
        foreach ($cookie in $cookies) {
            $cookieData += @{
                Name   = $cookie.Name
                Value  = $cookie.Value
                Domain = $cookie.Domain
                Path   = $cookie.Path
            }
        }
        $headersData = @{}
        foreach ($key in $script:headers.Keys) {
            $headersData[$key] = $script:headers[$key]
        }

        try {
            Write-Verbose "Starting parallel retrieval of $($dateChunks.Count) chunk(s) with throttle limit of $ThrottleLimit"

            # Initialize progress tracking
            $progressParams = @{
                Activity        = "Retrieving Device Timeline"
                Status          = "Processing chunks..."
                PercentComplete = 0
                Id              = 1
            }
            Write-Progress @progressParams

            $operationStartTime = [System.Diagnostics.Stopwatch]::StartNew()

            # Process chunks in parallel using ForEach-Object -Parallel (PowerShell 7+)
            # NOTE: The chunk processing logic is duplicated between PS7 (-Parallel below) and PS5 (scriptblock
            # in the else branch). This is necessary because PS7's -Parallel runs in isolated runspaces that
            # cannot access external scriptblocks via $using:. Any changes to the chunk processing logic must
            # be made in BOTH locations.
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                # Run parallel processing as a job so we can poll for progress
                $totalChunks = $dateChunks.Count
                $parallelJob = Start-ThreadJob -ScriptBlock {
                    param($chunks, $throttle, $deviceId, $baseParams, $tempPath, $cookieInfo, $headerInfo, $baseUrl)
                    $chunks | ForEach-Object -ThrottleLimit $throttle -Parallel {
                        $chunk = $_
                        $deviceId = $using:deviceId
                        $baseParams = $using:baseParams
                        $tempPath = $using:tempPath
                        $cookieInfo = $using:cookieInfo
                        $headerInfo = $using:headerInfo
                        $baseUrl = $using:baseUrl
                        $chunkFromDate = $chunk.FromDate
                        $chunkToDate = $chunk.ToDate
                        $chunkIndex = $chunk.Index

                        # Recreate web session with cookies
                        $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                        foreach ($c in $cookieInfo) {
                            $cookie = [System.Net.Cookie]::new($c.Name, $c.Value, $c.Path, $c.Domain)
                            $webSession.Cookies.Add($cookie)
                        }

                        # Build query parameters for this chunk
                        $correlationId = [guid]::NewGuid().ToString()
                        $queryParams = @(
                            "generateIdentityEvents=$($baseParams.GenerateIdentityEvents.ToString().ToLower())"
                            "includeIdentityEvents=$($baseParams.IncludeIdentityEvents.ToString().ToLower())"
                            "supportMdiOnlyEvents=$($baseParams.SupportMdiOnlyEvents.ToString().ToLower())"
                            "fromDate=$([System.Uri]::EscapeDataString($chunkFromDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
                            "toDate=$([System.Uri]::EscapeDataString($chunkToDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
                            "correlationId=$correlationId"
                            "doNotUseCache=$($baseParams.DoNotUseCache.ToString().ToLower())"
                            "forceUseCache=$($baseParams.ForceUseCache.ToString().ToLower())"
                            "pageSize=$($baseParams.PageSize)"
                            "includeSentinelEvents=$($baseParams.IncludeSentinelEvents.ToString().ToLower())"
                        )

                        if ($baseParams.MachineDnsName) {
                            $queryParams = @("machineDnsName=$([System.Uri]::EscapeDataString($baseParams.MachineDnsName))") + $queryParams
                        }

                        if ($baseParams.SenseClientVersion) {
                            $queryParams = @("SenseClientVersion=$([System.Uri]::EscapeDataString($baseParams.SenseClientVersion))") + $queryParams
                        }

                        if ($baseParams.MarkedEventsOnly) {
                            $queryParams = @("markedEventsOnly=true") + $queryParams
                        }

                        if ($baseParams.EventsGroups -and $baseParams.EventsGroups.Count -gt 0) {
                            $eventsGroupsParams = $baseParams.EventsGroups | ForEach-Object { "eventsGroups=$_" }
                            $queryParams = $queryParams + $eventsGroupsParams
                        }

                        if ($baseParams.DataTypes -and $baseParams.DataTypes.Count -gt 0) {
                            $dataTypesParams = $baseParams.DataTypes | ForEach-Object { "dataTypes=$_" }
                            $queryParams = $queryParams + $dataTypesParams
                        }

                        if ($baseParams.SourceProviders -and $baseParams.SourceProviders.Count -gt 0) {
                            $sourceProvidersParams = $baseParams.SourceProviders | ForEach-Object { "sourceProviders=$_" }
                            $queryParams = $queryParams + $sourceProvidersParams
                        }

                        $Uri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience/machines/$deviceId/events/?$($queryParams -join '&')"
                        $maxRetries = $baseParams.MaxRetries
                        $baseDelay = $baseParams.RetryDelaySeconds

                        # Prepare file path for streaming writes
                        $fileName = "chunk_{0:D4}_{1:yyyyMMdd_HHmmss}_{2:yyyyMMdd_HHmmss}.json" -f $chunkIndex, $chunkFromDate, $chunkToDate
                        $filePath = Join-Path $tempPath $fileName

                        try {
                            # Start timing this chunk
                            $chunkStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                            $pagesRetrieved = 0
                            $eventCount = 0

                            # Use StreamWriter to write events directly to file - avoids memory accumulation
                            $streamWriter = [System.IO.StreamWriter]::new($filePath, $false, [System.Text.Encoding]::UTF8)
                            $streamWriter.Write('{"ChunkIndex":' + $chunkIndex + ',"FromDate":"' + $chunkFromDate.ToString('o') + '","ToDate":"' + $chunkToDate.ToString('o') + '","Events":[')
                            $isFirstEvent = $true

                            do {
                                $attempt = 0
                                $success = $false

                                while (-not $success -and $attempt -lt $maxRetries) {
                                    try {
                                        $attempt++
                                        $response = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $webSession -Headers $headerInfo -ErrorAction Stop
                                        $success = $true
                                        $pagesRetrieved++
                                    } catch {
                                        $statusCode = $null
                                        if ($_.Exception.Response) {
                                            $statusCode = [int]$_.Exception.Response.StatusCode
                                        }

                                        if ($statusCode -eq 429 -or $statusCode -eq 403) {
                                            # Rate limited - use exponential backoff
                                            $delay = $baseDelay * [Math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 1 -Maximum 10)
                                            $delay = [Math]::Min($delay, 300) # Cap at 5 minutes
                                            Start-Sleep -Seconds $delay
                                        } elseif ($attempt -lt $maxRetries) {
                                            $delay = Get-Random -Minimum 5 -Maximum 15
                                            Start-Sleep -Seconds $delay
                                        } else {
                                            throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                        }
                                    }
                                }

                                # Stream events directly to file instead of accumulating in memory
                                $nextUri = $null
                                if ($response) {
                                    if ($response.Items) {
                                        foreach ($item in $response.Items) {
                                            if (-not $isFirstEvent) { $streamWriter.Write(',') }
                                            $streamWriter.Write(($item | ConvertTo-Json -Depth 20 -Compress))
                                            $isFirstEvent = $false
                                            $eventCount++
                                        }
                                    }
                                    # Capture next page URL before clearing response
                                    if (-not [string]::IsNullOrWhiteSpace($response.Prev)) {
                                        $nextUri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience$($response.Prev)"
                                    }
                                    # Clear response to free memory immediately
                                    $response = $null
                                }

                                if (-not $nextUri) {
                                    break
                                } else {
                                    $Uri = $nextUri
                                    # Small delay between pagination requests
                                    Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 1500)
                                }
                            } while ($true)

                            # Complete the JSON structure
                            $streamWriter.Write('],"EventCount":' + $eventCount + '}')
                            $streamWriter.Close()
                            $streamWriter.Dispose()
                            $streamWriter = $null

                            # Stop timing
                            $chunkStopwatch.Stop()
                            $elapsedSeconds = $chunkStopwatch.Elapsed.TotalSeconds
                            $fileSizeKB = [math]::Round((Get-Item $filePath).Length / 1KB, 2)

                            @{
                                ChunkIndex     = $chunkIndex
                                FilePath       = $filePath
                                EventCount     = $eventCount
                                FromDate       = $chunkFromDate
                                ToDate         = $chunkToDate
                                Success        = $true
                                ElapsedSeconds = [math]::Round($elapsedSeconds, 2)
                                PagesRetrieved = $pagesRetrieved
                                FileSizeKB     = $fileSizeKB
                            }
                        } catch {
                            $chunkError = $_.ToString()
                            if ($streamWriter) {
                                try { $streamWriter.Close(); $streamWriter.Dispose() } catch {
                                    # Log disposal error but don't override the original error
                                    Write-Warning "Failed to dispose stream writer for chunk $chunkIndex`: $_"
                                }
                            }
                            if ($chunkStopwatch) { $chunkStopwatch.Stop() }
                            @{
                                ChunkIndex     = $chunkIndex
                                Success        = $false
                                Error          = $chunkError
                                FromDate       = $chunkFromDate
                                ToDate         = $chunkToDate
                                ElapsedSeconds = if ($chunkStopwatch) { [math]::Round($chunkStopwatch.Elapsed.TotalSeconds, 2) } else { 0 }
                            }
                        }
                    }
                } -ArgumentList $dateChunks, $ThrottleLimit, $deviceIdentifier, $baseQueryParams, $runTempPath, $cookieData, $headersData, $script:XdrBaseUrl

                # Poll for progress by counting completed chunk files
                $lastCompletedCount = 0
                $completedChunks = @{}
                
                # Wait for job to start or complete (covers NotStarted, Running states)
                while ($parallelJob.State -in @('NotStarted', 'Running')) {
                    # Check timeout
                    if ($operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                        Write-Warning "Operation timed out after $TimeoutSeconds seconds. Stopping job..."
                        Stop-Job -Job $parallelJob
                        break
                    }

                    # Count completed chunk files for progress
                    $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue
                    $completedFiles = $chunkFiles.Count
                    
                    # Report newly completed chunks
                    if ($completedFiles -gt $lastCompletedCount) {
                        foreach ($file in $chunkFiles) {
                            if (-not $completedChunks.ContainsKey($file.Name)) {
                                $completedChunks[$file.Name] = $true
                                $sizeKB = [math]::Round($file.Length / 1KB, 1)
                                Write-Verbose "  Downloaded chunk $($completedChunks.Count)/${totalChunks}: $($file.BaseName) ($sizeKB KB)"
                            }
                        }
                        $lastCompletedCount = $completedFiles
                    }
                    
                    $percentComplete = [math]::Min(99, [math]::Round(($completedFiles / [math]::Max(1, $totalChunks)) * 100))
                    Write-Progress -Activity "Retrieving Device Timeline" -Status "Downloaded $completedFiles of $totalChunks chunks" -PercentComplete $percentComplete -Id 1

                    Start-Sleep -Milliseconds 250
                }
                
                # Handle job terminal states (Failed, Stopped, Blocked, etc.)
                $jobState = $parallelJob.State
                if ($jobState -eq 'Failed') {
                    $jobError = $parallelJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason } | Where-Object { $_ }
                    Write-Warning "Parallel job failed: $($jobError -join '; ')"
                } elseif ($jobState -eq 'Stopped') {
                    Write-Warning "Parallel job was stopped (likely due to timeout or cancellation)"
                } elseif ($jobState -eq 'Blocked') {
                    Write-Warning "Parallel job is blocked - this may indicate a resource contention issue"
                    Stop-Job -Job $parallelJob -ErrorAction SilentlyContinue
                } elseif ($jobState -notin @('Completed', 'Running', 'NotStarted')) {
                    Write-Warning "Parallel job ended in unexpected state: $jobState"
                }

                # Final check for any chunks completed after loop exit
                $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue
                foreach ($file in $chunkFiles) {
                    if (-not $completedChunks.ContainsKey($file.Name)) {
                        $completedChunks[$file.Name] = $true
                        $sizeKB = [math]::Round($file.Length / 1KB, 1)
                        Write-Verbose "  Downloaded chunk $($completedChunks.Count)/${totalChunks}: $($file.BaseName) ($sizeKB KB)"
                    }
                }

                # Collect results from job and clean up
                $results = Receive-Job -Job $parallelJob -Wait
                Remove-Job -Job $parallelJob -Force
                
                # Force garbage collection after parallel job completes to reclaim thread memory
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
            } else {
                # Fallback for PowerShell 5.1 using runspace pool
                # NOTE: The chunk processing logic is duplicated between PS7 (ForEach-Object -Parallel above)
                # and PS5 (scriptblock below). This is necessary because PS7's -Parallel runs in isolated
                # runspaces that cannot access external scriptblocks via $using:. Any changes to the chunk
                # processing logic must be made in BOTH locations.
                $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
                $runspacePool.Open()

                # Define chunk processing scriptblock for PS5 runspace pool
                $chunkProcessingScript = {
                    param($chunk, $deviceId, $baseParams, $tempPath, $cookieInfo, $headerInfo, $baseUrl)

                    $chunkFromDate = $chunk.FromDate
                    $chunkToDate = $chunk.ToDate
                    $chunkIndex = $chunk.Index

                    # Recreate web session with cookies
                    $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                    foreach ($c in $cookieInfo) {
                        $cookie = [System.Net.Cookie]::new($c.Name, $c.Value, $c.Path, $c.Domain)
                        $webSession.Cookies.Add($cookie)
                    }

                    # Build query parameters for this chunk
                    $correlationId = [guid]::NewGuid().ToString()
                    $queryParams = @(
                        "generateIdentityEvents=$($baseParams.GenerateIdentityEvents.ToString().ToLower())"
                        "includeIdentityEvents=$($baseParams.IncludeIdentityEvents.ToString().ToLower())"
                        "supportMdiOnlyEvents=$($baseParams.SupportMdiOnlyEvents.ToString().ToLower())"
                        "fromDate=$([System.Uri]::EscapeDataString($chunkFromDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
                        "toDate=$([System.Uri]::EscapeDataString($chunkToDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
                        "correlationId=$correlationId"
                        "doNotUseCache=$($baseParams.DoNotUseCache.ToString().ToLower())"
                        "forceUseCache=$($baseParams.ForceUseCache.ToString().ToLower())"
                        "pageSize=$($baseParams.PageSize)"
                        "includeSentinelEvents=$($baseParams.IncludeSentinelEvents.ToString().ToLower())"
                    )

                    if ($baseParams.MachineDnsName) {
                        $queryParams = @("machineDnsName=$([System.Uri]::EscapeDataString($baseParams.MachineDnsName))") + $queryParams
                    }

                    if ($baseParams.SenseClientVersion) {
                        $queryParams = @("SenseClientVersion=$([System.Uri]::EscapeDataString($baseParams.SenseClientVersion))") + $queryParams
                    }

                    if ($baseParams.MarkedEventsOnly) {
                        $queryParams = @("markedEventsOnly=true") + $queryParams
                    }

                    if ($baseParams.EventsGroups -and $baseParams.EventsGroups.Count -gt 0) {
                        $eventsGroupsParams = $baseParams.EventsGroups | ForEach-Object { "eventsGroups=$_" }
                        $queryParams = $queryParams + $eventsGroupsParams
                    }

                    if ($baseParams.DataTypes -and $baseParams.DataTypes.Count -gt 0) {
                        $dataTypesParams = $baseParams.DataTypes | ForEach-Object { "dataTypes=$_" }
                        $queryParams = $queryParams + $dataTypesParams
                    }

                    if ($baseParams.SourceProviders -and $baseParams.SourceProviders.Count -gt 0) {
                        $sourceProvidersParams = $baseParams.SourceProviders | ForEach-Object { "sourceProviders=$_" }
                        $queryParams = $queryParams + $sourceProvidersParams
                    }

                    $Uri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience/machines/$deviceId/events/?$($queryParams -join '&')"
                    $maxRetries = $baseParams.MaxRetries
                    $baseDelay = $baseParams.RetryDelaySeconds

                    # Prepare file path for streaming writes
                    $fileName = "chunk_{0:D4}_{1:yyyyMMdd_HHmmss}_{2:yyyyMMdd_HHmmss}.json" -f $chunkIndex, $chunkFromDate, $chunkToDate
                    $filePath = Join-Path $tempPath $fileName

                    try {
                        # Start timing this chunk
                        $chunkStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $pagesRetrieved = 0
                        $eventCount = 0

                        # Use StreamWriter to write events directly to file - avoids memory accumulation
                        $streamWriter = [System.IO.StreamWriter]::new($filePath, $false, [System.Text.Encoding]::UTF8)
                        $streamWriter.Write('{"ChunkIndex":' + $chunkIndex + ',"FromDate":"' + $chunkFromDate.ToString('o') + '","ToDate":"' + $chunkToDate.ToString('o') + '","Events":[')
                        $isFirstEvent = $true

                        do {
                            $attempt = 0
                            $success = $false

                            while (-not $success -and $attempt -lt $maxRetries) {
                                try {
                                    $attempt++
                                    $response = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $webSession -Headers $headerInfo -ErrorAction Stop
                                    $success = $true
                                    $pagesRetrieved++
                                } catch {
                                    $statusCode = $null
                                    if ($_.Exception.Response) {
                                        $statusCode = [int]$_.Exception.Response.StatusCode
                                    }

                                    if ($statusCode -eq 429 -or $statusCode -eq 403) {
                                        # Rate limited - use exponential backoff
                                        $delay = $baseDelay * [Math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 1 -Maximum 10)
                                        $delay = [Math]::Min($delay, 300) # Cap at 5 minutes
                                        Start-Sleep -Seconds $delay
                                    } elseif ($attempt -lt $maxRetries) {
                                        $delay = Get-Random -Minimum 5 -Maximum 15
                                        Start-Sleep -Seconds $delay
                                    } else {
                                        throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                    }
                                }
                            }

                            # Stream events directly to file instead of accumulating in memory
                            $nextUri = $null
                            if ($response) {
                                if ($response.Items) {
                                    foreach ($item in $response.Items) {
                                        if (-not $isFirstEvent) { $streamWriter.Write(',') }
                                        $streamWriter.Write(($item | ConvertTo-Json -Depth 20 -Compress))
                                        $isFirstEvent = $false
                                        $eventCount++
                                    }
                                }
                                # Capture next page URL before clearing response
                                if (-not [string]::IsNullOrWhiteSpace($response.Prev)) {
                                    $nextUri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience$($response.Prev)"
                                }
                                # Clear response to free memory immediately
                                $response = $null
                            }

                            if (-not $nextUri) {
                                break
                            } else {
                                $Uri = $nextUri
                                # Small delay between pagination requests
                                Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 1500)
                            }
                        } while ($true)

                        # Complete the JSON structure
                        $streamWriter.Write('],"EventCount":' + $eventCount + '}')
                        $streamWriter.Close()
                        $streamWriter.Dispose()
                        $streamWriter = $null

                        # Stop timing
                        $chunkStopwatch.Stop()
                        $elapsedSeconds = $chunkStopwatch.Elapsed.TotalSeconds
                        $fileSizeKB = [math]::Round((Get-Item $filePath).Length / 1KB, 2)

                        @{
                            ChunkIndex     = $chunkIndex
                            FilePath       = $filePath
                            EventCount     = $eventCount
                            FromDate       = $chunkFromDate
                            ToDate         = $chunkToDate
                            Success        = $true
                            ElapsedSeconds = [math]::Round($elapsedSeconds, 2)
                            PagesRetrieved = $pagesRetrieved
                            FileSizeKB     = $fileSizeKB
                        }
                    } catch {
                        $chunkError = $_.ToString()
                        if ($streamWriter) {
                            try { $streamWriter.Close(); $streamWriter.Dispose() } catch {
                                # Log disposal error but don't override the original error
                                Write-Warning "Failed to dispose stream writer for chunk $chunkIndex`: $_"
                            }
                        }
                        if ($chunkStopwatch) { $chunkStopwatch.Stop() }
                        @{
                            ChunkIndex     = $chunkIndex
                            Success        = $false
                            Error          = $chunkError
                            FromDate       = $chunkFromDate
                            ToDate         = $chunkToDate
                            ElapsedSeconds = if ($chunkStopwatch) { [math]::Round($chunkStopwatch.Elapsed.TotalSeconds, 2) } else { 0 }
                        }
                    }
                }

                # Use a queued approach to avoid creating all invocations upfront
                # This prevents memory/handle exhaustion for large date ranges (e.g., 180 days = 4320 chunks)
                $chunkQueue = [System.Collections.Generic.Queue[object]]::new($dateChunks)
                $activeJobs = [System.Collections.Generic.List[object]]::new()
                $results = @()
                $totalJobs = $dateChunks.Count
                $lastCompletedCount = 0
                $completedChunks = @{}

                # Helper function to create and start a job for a chunk
                $createJob = {
                    param($chunk)
                    $powershell = [powershell]::Create()
                    $powershell.RunspacePool = $runspacePool
                    [void]$powershell.AddScript($chunkProcessingScript)
                    [void]$powershell.AddParameter('chunk', $chunk)
                    [void]$powershell.AddParameter('deviceId', $deviceIdentifier)
                    [void]$powershell.AddParameter('baseParams', $baseQueryParams)
                    [void]$powershell.AddParameter('tempPath', $runTempPath)
                    [void]$powershell.AddParameter('cookieInfo', $cookieData)
                    [void]$powershell.AddParameter('headerInfo', $headersData)
                    [void]$powershell.AddParameter('baseUrl', $script:XdrBaseUrl)
                    
                    @{
                        PowerShell = $powershell
                        Handle     = $powershell.BeginInvoke()
                        Chunk      = $chunk
                    }
                }

                # Seed the initial batch of jobs up to ThrottleLimit
                while ($chunkQueue.Count -gt 0 -and $activeJobs.Count -lt $ThrottleLimit) {
                    $chunk = $chunkQueue.Dequeue()
                    $job = & $createJob $chunk
                    $activeJobs.Add($job)
                }

                # Process jobs: collect completed ones and queue new ones
                while ($activeJobs.Count -gt 0) {
                    # Check timeout
                    if ($operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                        Write-Warning "Operation timed out after $TimeoutSeconds seconds. Cancelling remaining jobs..."
                        foreach ($job in $activeJobs) {
                            $job.PowerShell.Stop()
                            $results += @{
                                ChunkIndex = $job.Chunk.Index
                                Success    = $false
                                Error      = "Job was cancelled due to timeout"
                            }
                            $job.PowerShell.Dispose()
                        }
                        $activeJobs.Clear()
                        break
                    }

                    # Check for completed jobs
                    $completedJobs = $activeJobs | Where-Object { $_.Handle.IsCompleted }
                    foreach ($job in $completedJobs) {
                        try {
                            $result = $job.PowerShell.EndInvoke($job.Handle)
                            $results += $result
                        } catch {
                            Write-Warning "Chunk $($job.Chunk.Index) failed: $_"
                            $results += @{
                                ChunkIndex = $job.Chunk.Index
                                Success    = $false
                                Error      = $_.ToString()
                            }
                        } finally {
                            $job.PowerShell.Dispose()
                        }
                        $activeJobs.Remove($job) | Out-Null
                        
                        # Queue next chunk if available
                        if ($chunkQueue.Count -gt 0) {
                            $nextChunk = $chunkQueue.Dequeue()
                            $newJob = & $createJob $nextChunk
                            $activeJobs.Add($newJob)
                        }
                    }

                    # Update progress by counting completed chunk files
                    $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue
                    $completedFiles = $chunkFiles.Count
                    
                    # Report newly completed chunks
                    if ($completedFiles -gt $lastCompletedCount) {
                        foreach ($file in $chunkFiles) {
                            if (-not $completedChunks.ContainsKey($file.Name)) {
                                $completedChunks[$file.Name] = $true
                                $sizeKB = [math]::Round($file.Length / 1KB, 1)
                                Write-Verbose "  Downloaded chunk $($completedChunks.Count)/${totalJobs}: $($file.BaseName) ($sizeKB KB)"
                            }
                        }
                        $lastCompletedCount = $completedFiles
                    }
                    
                    $percentComplete = [math]::Min(99, [math]::Round(($completedFiles / [math]::Max(1, $totalJobs)) * 100))
                    Write-Progress -Activity "Retrieving Device Timeline" -Status "Downloaded $completedFiles of $totalJobs chunks (Active: $($activeJobs.Count), Queued: $($chunkQueue.Count))" -PercentComplete $percentComplete -Id 1

                    Start-Sleep -Milliseconds 250
                }

                $runspacePool.Close()
                $runspacePool.Dispose()
                
                # Force garbage collection after runspace pool completes to reclaim thread memory
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
            }

            # Complete progress
            Write-Progress -Activity "Retrieving Device Timeline" -Completed -Id 1

            # Check for timeout in PS7
            if ($PSVersionTable.PSVersion.Major -ge 7 -and $operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                Write-Warning "Operation took longer than expected timeout of $TimeoutSeconds seconds."
            }

            # Check for failures
            $failures = $results | Where-Object { -not $_.Success }
            if ($failures) {
                Write-Warning "Some chunks failed to retrieve: $($failures.ChunkIndex -join ', ')"
            }

            # Output timing information for each chunk
            Write-Information "`n=== Chunk Download Statistics ===" -InformationAction Continue
            $totalElapsed = 0
            $totalEvents = 0
            $totalSizeKB = 0
            $maxElapsed = 0
            foreach ($result in ($results | Sort-Object ChunkIndex)) {
                $dateRange = "{0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}" -f $result.FromDate, $result.ToDate
                if ($result.Success) {
                    $totalElapsed += $result.ElapsedSeconds
                    $totalEvents += $result.EventCount
                    $totalSizeKB += $result.FileSizeKB
                    if ($result.ElapsedSeconds -gt $maxElapsed) { $maxElapsed = $result.ElapsedSeconds }
                    $eventsPerSec = if ($result.ElapsedSeconds -gt 0) { [math]::Round($result.EventCount / $result.ElapsedSeconds, 1) } else { 0 }
                    Write-Verbose "Chunk $($result.ChunkIndex): $dateRange | Events: $($result.EventCount) | Pages: $($result.PagesRetrieved) | Size: $($result.FileSizeKB) KB | Time: $($result.ElapsedSeconds)s | Rate: $eventsPerSec events/sec"
                } else {
                    Write-Warning "Chunk $($result.ChunkIndex): $dateRange | FAILED after $($result.ElapsedSeconds)s - $($result.Error)"
                }
            }
            $wallClockSeconds = $operationStartTime.Elapsed.TotalSeconds
            $overallEventsPerSec = if ($wallClockSeconds -gt 0) { [math]::Round($totalEvents / $wallClockSeconds, 1) } else { 0 }
            Write-Information "=== Summary ===" -InformationAction Continue
            Write-Information "Total chunks: $($results.Count) | Total events: $totalEvents | Total size: $([math]::Round($totalSizeKB / 1024, 2)) MB" -InformationAction Continue
            Write-Information "Cumulative download time: $([math]::Round($totalElapsed, 2))s | Wall-clock time: $([math]::Round($wallClockSeconds, 2))s | Effective rate: $overallEventsPerSec events/sec" -InformationAction Continue

            # Merge all JSON files with progress - using memory-efficient streaming
            Write-Progress -Activity "Processing Results" -Status "Merging chunk files..." -PercentComplete 0 -Id 2
            Write-Verbose "Merging results from $($results.Count) chunk(s)..."
            
            $jsonFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue | Sort-Object Name

            # If ExportPath is specified, use pure file-based merge (most memory efficient)
            if ($PSBoundParameters.ContainsKey('ExportPath')) {
                Write-Verbose "Exporting to file using streaming merge (memory-efficient)..."
                $exportDir = Split-Path -Parent $ExportPath
                if ($exportDir -and -not (Test-Path $exportDir)) {
                    New-Item -Path $exportDir -ItemType Directory -Force | Out-Null
                }
                
                # Stream merge directly to export file without loading into memory
                $exportWriter = [System.IO.StreamWriter]::new($ExportPath, $false, [System.Text.Encoding]::UTF8)
                try {
                    $exportWriter.Write('[')
                    $isFirstEvent = $true
                    $fileIndex = 0
                    $totalFiles = $jsonFiles.Count
                    
                    foreach ($file in $jsonFiles) {
                        $fileIndex++
                        $percentComplete = [math]::Round(($fileIndex / [math]::Max(1, $totalFiles)) * 100)
                        Write-Progress -Activity "Processing Results" -Status "Merging file $fileIndex of $totalFiles to export" -PercentComplete $percentComplete -Id 2
                        
                        # Read file content as text and extract just the Events array
                        $rawContent = [System.IO.File]::ReadAllText($file.FullName)
                        # Find Events array - it starts after "Events":[ and ends before ],"EventCount" or ]}
                        $eventsStart = $rawContent.IndexOf('"Events":[') + 10
                        $eventsEnd = $rawContent.LastIndexOf('],"EventCount"')
                        if ($eventsEnd -lt 0) { $eventsEnd = $rawContent.LastIndexOf(']}') }
                        
                        if ($eventsStart -gt 10 -and $eventsEnd -gt $eventsStart) {
                            $eventsJson = $rawContent.Substring($eventsStart, $eventsEnd - $eventsStart)
                            if ($eventsJson.Length -gt 0) {
                                if (-not $isFirstEvent) { $exportWriter.Write(',') }
                                $exportWriter.Write($eventsJson)
                                $isFirstEvent = $false
                            }
                        }
                        $rawContent = $null
                        
                        # GC periodically
                        if ($fileIndex % 50 -eq 0) {
                            [System.GC]::Collect()
                        }
                    }
                    $exportWriter.Write(']')
                } finally {
                    $exportWriter.Close()
                    $exportWriter.Dispose()
                }
                Write-Progress -Activity "Processing Results" -Completed -Id 2
                Write-Information "Exported $totalEvents events to: $ExportPath" -InformationAction Continue
                
                # Clean up temp files unless KeepTempFiles is specified
                if (-not $KeepTempFiles) {
                    Write-Verbose "Cleaning up temporary files..."
                    Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Verbose "Temporary files kept at: $runTempPath"
                }
                
                [System.GC]::Collect()
                
                # Return summary info instead of all events when exporting
                return [PSCustomObject]@{
                    ExportPath       = $ExportPath
                    TotalEvents      = $totalEvents
                    TotalChunks      = $results.Count
                    TotalSizeMB      = [math]::Round($totalSizeKB / 1024, 2)
                    WallClockSeconds = [math]::Round($wallClockSeconds, 2)
                    EffectiveRate    = $overallEventsPerSec
                }
            }
            
            # For in-memory return, load events but with aggressive memory management
            $allEvents = [System.Collections.Generic.List[object]]::new([math]::Max(10000, $totalEvents))

            $fileIndex = 0
            $totalFiles = $jsonFiles.Count
            foreach ($file in $jsonFiles) {
                $fileIndex++
                $percentComplete = [math]::Round(($fileIndex / [math]::Max(1, $totalFiles)) * 100)
                Write-Progress -Activity "Processing Results" -Status "Merging file $fileIndex of $totalFiles" -PercentComplete $percentComplete -Id 2

                # Read and process file, then clear to free memory
                $rawContent = Get-Content -Path $file.FullName -Raw
                $chunkData = $rawContent | ConvertFrom-Json
                $rawContent = $null  # Free the raw string memory
                
                if ($chunkData.Events) {
                    $allEvents.AddRange($chunkData.Events)
                }
                $chunkData = $null  # Free parsed object memory
                
                # Force garbage collection every 100 files to prevent memory buildup
                if ($fileIndex % 100 -eq 0) {
                    [System.GC]::Collect()
                    [System.GC]::WaitForPendingFinalizers()
                }
            }
            Write-Progress -Activity "Processing Results" -Completed -Id 2

            Write-Verbose "Total events retrieved: $($allEvents.Count)"

            # Apply EventType filter if specified
            if ($PSBoundParameters.ContainsKey('EventType') -and $allEvents.Count -gt 0) {
                Write-Verbose "Filtering events by type: $EventType"
                $filteredEvents = [System.Collections.Generic.List[object]]::new()
                foreach ($eventItem in $allEvents) {
                    # Check common event type properties
                    $eventTypeName = $eventItem.ActionType
                    if (-not $eventTypeName) { $eventTypeName = $eventItem.Type }
                    if (-not $eventTypeName) { $eventTypeName = $eventItem.EventType }

                    if ($eventTypeName -and $eventTypeName -like $EventType) {
                        $filteredEvents.Add($eventItem)
                    }
                }
                Write-Information "Filtered from $($allEvents.Count) to $($filteredEvents.Count) events matching '$EventType'" -InformationAction Continue
                $allEvents = $filteredEvents
            }

            # Clean up temp files unless KeepTempFiles is specified
            if (-not $KeepTempFiles) {
                Write-Verbose "Cleaning up temporary files..."
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Write-Verbose "Temporary files kept at: $runTempPath"
            }

            # Sort events in-place by timestamp (if available) to avoid creating a copy
            if ($allEvents.Count -gt 0 -and $allEvents[0].PSObject.Properties['Timestamp']) {
                Write-Verbose "Sorting $($allEvents.Count) events by timestamp..."
                # Use Sort() method for in-place sorting (more memory efficient than Sort-Object)
                $allEvents.Sort([System.Comparison[object]] {
                        param($a, $b)
                        # Sort descending (newest first)
                        [datetime]::Compare($b.Timestamp, $a.Timestamp)
                    })
            }

            # Return results and clean up
            $result = $allEvents.ToArray()
            $allEvents.Clear()
            $allEvents = $null
            [System.GC]::Collect()
            
            return $result
        } catch {
            Write-Progress -Activity "Retrieving Device Timeline" -Completed -Id 1
            Write-Progress -Activity "Processing Results" -Completed -Id 2
            Write-Error "Failed to retrieve endpoint device timeline: $_"
        }
    }

    end {
    }
}