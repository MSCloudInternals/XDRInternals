function Get-XdrEndpointDeviceTimeline {
    <#
    .SYNOPSIS
        Retrieves endpoint device timeline events from Microsoft Defender XDR.

    .DESCRIPTION
        Retrieves device timeline events using the Defender XDR portal timeline API.
        The request range is split into time chunks and processed concurrently with
        PowerShell 7.4+ runspaces. API-specific request behavior remains private to
        the endpoint timeline provider helpers; shared chunk planning, queueing, file
        merge, export, and diagnostics behavior lives in internal timeline helpers.

    .PARAMETER DeviceId
        The machine identifier. Accepts MachineId and SenseMachineId aliases.

    .PARAMETER MachineDnsName
        The DNS name of the machine. The cmdlet resolves this to a machine identifier.

    .PARAMETER FromDate
        Start of the requested timeline range. Defaults to one hour ago.

    .PARAMETER ToDate
        End of the requested timeline range. Defaults to now.

    .PARAMETER LastNDays
        Number of days to look back. Overrides FromDate and ToDate.

    .PARAMETER PageSize
        Number of events requested per page from the timeline API.

    .PARAMETER MarkedEventsOnly
        Limits results to events marked in the Defender timeline experience.

    .PARAMETER SenseClientVersion
        Overrides the Sense client version sent with requests when device lookup
        data is unavailable or should not be used.

    .PARAMETER SkipIdentityEvents
        Excludes identity-related timeline events from the response.

    .PARAMETER SkipMdiOnlyEvents
        Excludes MDI-only timeline events from the response.

    .PARAMETER DoNotUseCache
        Bypasses cached endpoint device metadata lookups.

    .PARAMETER ForceUseCache
        Uses cached endpoint device metadata even when it would normally be refreshed.

    .PARAMETER IncludeSentinelEvents
        Includes Sentinel-correlated events when the backend supports them.

    .PARAMETER EventType
        Filters results to a specific event type value.

    .PARAMETER EventsGroups
        Filters results to one or more Defender timeline event groups.

    .PARAMETER DataTypes
        Filters results to one or more supported timeline data types.

    .PARAMETER SourceProviders
        Filters results to events emitted by the selected source providers.

    .PARAMETER ThrottleLimit
        Maximum number of timeline chunks retrieved concurrently.

    .PARAMETER TimeoutSeconds
        Maximum total runtime for chunk processing before unfinished chunks fail.

    .PARAMETER MaxRetries
        Maximum number of retry attempts for retryable API failures.

    .PARAMETER RetryDelaySeconds
        Base retry delay used when the service does not return Retry-After.

    .PARAMETER PaginationDelayMinMilliseconds
        Minimum delay inserted between paginated requests within a chunk.

    .PARAMETER PaginationDelayMaxMilliseconds
        Maximum delay inserted between paginated requests within a chunk.

    .PARAMETER ChunkHours
        Fixed chunk size in hours when splitting the requested time range.

    .PARAMETER ChunkMinutes
        Fixed chunk size in minutes when splitting the requested time range.

    .PARAMETER OutputPath
        Compatibility parameter. Directory-like values are used as the temporary working
        root. File-like values ending in .json, .jsonl, or .ndjson are treated as ExportPath.

    .PARAMETER WorkingDirectory
        Directory used for temporary chunk files. Overrides directory-like OutputPath values.

    .PARAMETER KeepTempFiles
        Preserves temporary chunk files and manifest state after the command finishes.

    .PARAMETER ExportFormat
        Output file format used when ExportPath is specified.

    .PARAMETER RequestTimeoutSeconds
        Per-request timeout for individual timeline API calls.

    .PARAMETER AllowPartial
        Returns successful chunk data and warns when one or more chunks fail.

    .PARAMETER ExportPath
        Writes retrieved events to the specified JSON or NDJSON file and returns a summary.

    .PARAMETER ManifestPath
        Optional override for the automatic resume manifest. Defaults to <ExportPath>.manifest.json for export runs.

    .PARAMETER DiagnosticsPath
        Writes execution diagnostics and chunk statistics to the specified file.

    .PARAMETER MaxPagesPerChunk
        Maximum number of paginated API requests allowed for each chunk.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId 0123456789abcdef0123456789abcdef01234567 -LastNDays 1

        Retrieves the last day of timeline events for the specified device.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -MachineDnsName workstation01.contoso.com -FromDate (Get-Date).AddHours(-8) -ToDate (Get-Date) -ExportPath .\timeline.ndjson -ExportFormat Ndjson -AllowPartial

        Resolves the device by DNS name, downloads eight hours of events, and
        writes the results to an NDJSON export while allowing partial completion.
    #>
    [OutputType([System.Object[]])]
    [CmdletBinding(DefaultParameterSetName = 'ByDeviceId')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByDeviceId')]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40, 40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter(Mandatory, ParameterSetName = 'ByMachineDnsName')]
        [string]$MachineDnsName,

        [Parameter()]
        [datetime]$FromDate = ((Get-Date).AddHours(-1)),

        [Parameter()]
        [datetime]$ToDate = (Get-Date),

        [Parameter()]
        [ValidateRange(1, 180)]
        [int]$LastNDays,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 999,

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
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 16,

        [Parameter()]
        [ValidateRange(60, 86400)]
        [int]$TimeoutSeconds = 3600,

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$MaxRetries = 4,

        [Parameter()]
        [ValidateRange(0, 300)]
        [int]$RetryDelaySeconds = 2,

        [Parameter()]
        [ValidateRange(0, 10000)]
        [int]$PaginationDelayMinMilliseconds = 0,

        [Parameter()]
        [ValidateRange(0, 10000)]
        [int]$PaginationDelayMaxMilliseconds = 0,

        [Parameter()]
        [ValidateRange(1, 168)]
        [int]$ChunkHours = 4,

        [Parameter()]
        [ValidateRange(1, 10080)]
        [int]$ChunkMinutes,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [string]$WorkingDirectory,

        [Parameter()]
        [switch]$KeepTempFiles,

        [Parameter()]
        [ValidateSet('Json', 'Ndjson')]
        [string]$ExportFormat = 'Json',

        [Parameter()]
        [ValidateRange(10, 300)]
        [int]$RequestTimeoutSeconds = 60,

        [Parameter()]
        [switch]$AllowPartial,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$ManifestPath,

        [Parameter()]
        [string]$DiagnosticsPath,

        [Parameter()]
        [ValidateRange(1, 100000)]
        [int]$MaxPagesPerChunk = 10000
    )

    begin {
        Update-XdrConnectionSettings
        $xdrBaseUrl = 'https://security.microsoft.com'
    }

    process {
        if ($PSBoundParameters.ContainsKey('LastNDays')) {
            $ToDate = (Get-Date).ToUniversalTime()
            $FromDate = $ToDate.AddDays(-$LastNDays)
        }
        else {
            $FromDate = $FromDate.ToUniversalTime()
            $ToDate = $ToDate.ToUniversalTime()
        }

        if ($FromDate -ge $ToDate) {
            throw 'FromDate must be before ToDate.'
        }

        if (($ToDate - $FromDate).TotalDays -gt 180) {
            throw 'The time range between FromDate and ToDate cannot exceed 180 days.'
        }

        if ($DoNotUseCache -and $ForceUseCache) {
            throw 'DoNotUseCache and ForceUseCache cannot both be specified.'
        }

        if ($PaginationDelayMaxMilliseconds -lt $PaginationDelayMinMilliseconds) {
            throw 'PaginationDelayMaxMilliseconds must be greater than or equal to PaginationDelayMinMilliseconds.'
        }

        $target = Resolve-XdrEndpointTimelineOutputTarget -OutputPath $OutputPath -ExportPath $ExportPath -WorkingDirectory $WorkingDirectory
        $exportFilePath = $target.ExportPath
        $workingRoot = $target.WorkingDirectory

        $deviceLookupTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $deviceLookup = $null
        if ($PSCmdlet.ParameterSetName -eq 'ByDeviceId') {
            $deviceIdentifier = $DeviceId
            try {
                $deviceLookup = Get-XdrEndpointDevice -DeviceId $deviceIdentifier -ErrorAction Stop
            }
            catch {
                Write-Verbose "Device detail lookup failed for '$deviceIdentifier'; continuing with the supplied identifier. $($_.Exception.Message)"
            }
        }
        else {
            Write-Verbose "Looking up endpoint device by DNS name: $MachineDnsName"
            $deviceLookup = Get-XdrEndpointDevice -MachineSearchPrefix $MachineDnsName -ErrorAction Stop | Select-Object -First 1
            if (-not $deviceLookup) {
                throw "Could not find device with DNS name '$MachineDnsName'."
            }

            $deviceIdentifier = $deviceLookup.MachineId
            if (-not $deviceIdentifier) {
                $deviceIdentifier = $deviceLookup.SenseMachineId
            }
            if (-not $deviceIdentifier) {
                throw "Device lookup for '$MachineDnsName' did not return MachineId or SenseMachineId."
            }

            try {
                $deviceLookup = Get-XdrEndpointDevice -DeviceId $deviceIdentifier -ErrorAction Stop
            }
            catch {
                Write-Verbose "Detailed device lookup failed for '$deviceIdentifier'; using search result values. $($_.Exception.Message)"
            }
        }
        $deviceLookupTimer.Stop()

        if (-not $PSBoundParameters.ContainsKey('SenseClientVersion') -and $deviceLookup -and $deviceLookup.PSObject.Properties['SenseClientVersion']) {
            $SenseClientVersion = $deviceLookup.SenseClientVersion
        }

        $computerDnsName = if ($deviceLookup -and $deviceLookup.PSObject.Properties['ComputerDnsName'] -and $deviceLookup.ComputerDnsName) {
            $deviceLookup.ComputerDnsName
        }
        elseif ($PSBoundParameters.ContainsKey('MachineDnsName')) {
            $MachineDnsName
        }
        else {
            $deviceIdentifier
        }
        $safeFolderName = ([string]$computerDnsName) -replace '[\\/:*?"<>|]', '_'

        if (-not (Test-Path -LiteralPath $workingRoot)) {
            New-Item -Path $workingRoot -ItemType Directory -Force | Out-Null
        }
        $runTempLeaf = if ($exportFilePath) {
            ([System.IO.Path]::GetFileNameWithoutExtension($exportFilePath) -replace '[\\/:*?"<>|]', '_') + '.chunks'
        }
        else {
            [guid]::NewGuid().ToString('N').Substring(0, 8)
        }
        $runTempPath = Join-Path (Join-Path $workingRoot $safeFolderName) $runTempLeaf
        New-Item -Path $runTempPath -ItemType Directory -Force | Out-Null

        if ($PSBoundParameters.ContainsKey('ChunkHours') -and $PSBoundParameters.ContainsKey('ChunkMinutes')) {
            throw 'Specify either ChunkHours or ChunkMinutes, not both.'
        }

        $chunkStrategy = 'Explicit'
        $effectiveChunkHours = $ChunkHours
        $effectiveChunkMinutes = if ($PSBoundParameters.ContainsKey('ChunkMinutes')) { $ChunkMinutes } else { $ChunkHours * 60 }
        $targetChunkCount = 0
        $totalHours = ($ToDate - $FromDate).TotalHours
        if (-not $PSBoundParameters.ContainsKey('ChunkHours') -and -not $PSBoundParameters.ContainsKey('ChunkMinutes')) {
            if ($totalHours -le 24) {
                $effectiveChunkHours = 4
                $effectiveChunkMinutes = 240
                $chunkStrategy = 'Auto24HourFourHourChunks'
            }
            elseif ($totalHours -le 48) {
                $targetChunkCount = 24
                $chunkStrategy = 'Auto48HourBalanced'
            }
            else {
                $effectiveChunkHours = 4
                $effectiveChunkMinutes = 240
                $chunkStrategy = 'DefaultMultiDayFourHourChunks'
            }
        }
        elseif ($PSBoundParameters.ContainsKey('ChunkMinutes')) {
            $effectiveChunkHours = [math]::Round($effectiveChunkMinutes / 60, 4)
            $chunkStrategy = 'ExplicitMinutes'
        }

        $chunkPlanParameters = @{
            FromDate         = $FromDate
            ToDate           = $ToDate
            TargetChunkCount = $targetChunkCount
            Strategy         = $chunkStrategy
        }
        if ($PSBoundParameters.ContainsKey('ChunkMinutes')) {
            $chunkPlanParameters.ChunkMinutes = $effectiveChunkMinutes
        }
        else {
            $chunkPlanParameters.ChunkHours = $effectiveChunkHours
        }

        $ownerChunks = @(New-XdrTimelineChunkPlan @chunkPlanParameters)
        if ($ownerChunks.Count -eq 0) {
            throw 'The requested timeline range produced no chunks.'
        }

        $timelineOverlapSeconds = 10
        $dateChunks = @(
            foreach ($chunk in $ownerChunks) {
                $ownerFrom = ([datetime]$chunk.FromDate).ToUniversalTime()
                $ownerTo = ([datetime]$chunk.ToDate).ToUniversalTime()
                $requestFrom = $ownerFrom.AddSeconds(-$timelineOverlapSeconds)
                if ($requestFrom -lt $FromDate) { $requestFrom = $FromDate }
                $requestTo = $ownerTo.AddSeconds($timelineOverlapSeconds)
                if ($requestTo -gt $ToDate) { $requestTo = $ToDate }

                [PSCustomObject]@{
                    Index         = $chunk.Index
                    FromDate      = $requestFrom
                    ToDate        = $requestTo
                    OwnerFromDate = $ownerFrom
                    OwnerToDate   = $ownerTo
                    ChunkHours    = $chunk.ChunkHours
                    ChunkMinutes  = $chunk.ChunkMinutes
                    Strategy      = $chunk.Strategy
                }
            }
        )

        Write-Information "Split endpoint timeline range into $($dateChunks.Count) chunk(s); throttle=$ThrottleLimit; strategy=$chunkStrategy" -InformationAction Continue

        $requestContext = Get-XdrRequestContextSnapshot
        $requestContextSummary = ConvertTo-XdrSanitizedRequestContext -RequestContext $requestContext

        $paginationDelayMilliseconds = if ($PaginationDelayMaxMilliseconds -eq $PaginationDelayMinMilliseconds) {
            $PaginationDelayMinMilliseconds
        }
        else {
            Get-Random -Minimum $PaginationDelayMinMilliseconds -Maximum ($PaginationDelayMaxMilliseconds + 1)
        }

        $adaptiveDensePageThreshold = 32
        $adaptiveMinimumChunkMinutes = 15
        $adaptiveEarlyDensitySamplePages = 3
        $adaptiveEarlyDensityMaxTimestampSpanSeconds = 60

        $workerScript = New-XdrEndpointTimelineChunkWorkerScript
        $sharedParameters = @{
            BaseUrl                     = $xdrBaseUrl
            DeviceId                    = $deviceIdentifier
            MachineDnsName              = if ($PSBoundParameters.ContainsKey('MachineDnsName')) { $MachineDnsName } else { $computerDnsName }
            SenseClientVersion          = $SenseClientVersion
            GenerateIdentityEvents      = -not $SkipIdentityEvents.IsPresent
            IncludeIdentityEvents       = -not $SkipIdentityEvents.IsPresent
            SupportMdiOnlyEvents        = -not $SkipMdiOnlyEvents.IsPresent
            DoNotUseCache               = $DoNotUseCache.IsPresent
            ForceUseCache               = $ForceUseCache.IsPresent
            IncludeSentinelEvents       = $IncludeSentinelEvents.IsPresent
            MarkedEventsOnly            = $MarkedEventsOnly.IsPresent
            EventsGroups                = @($EventsGroups)
            DataTypes                   = @($DataTypes)
            SourceProviders             = @($SourceProviders)
            PageSize                    = $PageSize
            MaxRetries                  = $MaxRetries
            RetryDelaySeconds           = $RetryDelaySeconds
            RequestTimeoutSeconds       = $RequestTimeoutSeconds
            PaginationDelayMilliseconds = $paginationDelayMilliseconds
            MaxPagesPerChunk            = $MaxPagesPerChunk
            DensePageThreshold          = $adaptiveDensePageThreshold
            AdaptiveMinimumChunkMinutes = $adaptiveMinimumChunkMinutes
            EarlyDensitySamplePages     = $adaptiveEarlyDensitySamplePages
            EarlyDensityMaxTimestampSpanSeconds = $adaptiveEarlyDensityMaxTimestampSpanSeconds
            TempPath                    = $runTempPath
            CookieData                  = $requestContext.CookieData
            HeadersData                 = $requestContext.HeadersData
        }

        $tenantIdForManifest = $null
        try {
            $tenantValue = Get-XdrCache -CacheKey 'XdrTenantId' -ErrorAction SilentlyContinue
            $tenantIdForManifest = if ($tenantValue -and $tenantValue.PSObject.Properties['Value']) { $tenantValue.Value } else { $tenantValue }
        }
        catch {
            $tenantIdForManifest = $null
        }

        $manifestFilePath = $null
        if ($exportFilePath) {
            $manifestFilePath = if ($PSBoundParameters.ContainsKey('ManifestPath') -and -not [string]::IsNullOrWhiteSpace($ManifestPath)) {
                $ManifestPath
            }
            else {
                "$exportFilePath.manifest.json"
            }
        }

        $manifestCompatibility = @{
            Command              = 'Get-XdrEndpointDeviceTimeline'
            Provider             = 'EndpointDeviceTimeline'
            SchemaVersion        = 3
            PlannerVersion       = 'EndpointTimelineAdaptiveManifestV3'
            ModuleVersion        = 'TimelineAdaptiveV3'
            TenantId             = $tenantIdForManifest
            DeviceId             = $deviceIdentifier
            FromTicksUtc         = $FromDate.Ticks
            ToTicksUtc           = $ToDate.Ticks
            ExportFormat         = $ExportFormat
            PageSize             = $PageSize
            ChunkStrategy        = $chunkStrategy
            ChunkMinutes         = $effectiveChunkMinutes
            OverlapSeconds       = $timelineOverlapSeconds
            StableKeyVersion     = 'EndpointTimelineStableKeyV1'
            MarkedEventsOnly     = $MarkedEventsOnly.IsPresent
            SkipIdentityEvents   = $SkipIdentityEvents.IsPresent
            SkipMdiOnlyEvents    = $SkipMdiOnlyEvents.IsPresent
            IncludeSentinelEvents = $IncludeSentinelEvents.IsPresent
            EventType            = $EventType
            EventsGroups         = @($EventsGroups)
            DataTypes            = @($DataTypes)
            SourceProviders      = @($SourceProviders)
        }

        $manifestState = $null
        if ($manifestFilePath) {
            $existingManifest = Read-XdrTimelineManifest -Path $manifestFilePath
            if ($existingManifest -and (Test-XdrTimelineManifestCompatibility -Manifest $existingManifest -Compatibility $manifestCompatibility)) {
                Write-Information "Resuming endpoint timeline export from manifest: $manifestFilePath" -InformationAction Continue
                $manifestState = $existingManifest | ConvertTo-Json -Depth 32 | ConvertFrom-Json -AsHashtable -Depth 32
            }
            else {
                if ($existingManifest) {
                    $manifestDirectory = Split-Path -Path $manifestFilePath -Parent
                    if ([string]::IsNullOrWhiteSpace($manifestDirectory)) { $manifestDirectory = (Get-Location).Path }
                    $manifestLeaf = [System.IO.Path]::GetFileNameWithoutExtension($manifestFilePath)
                    $manifestExtension = [System.IO.Path]::GetExtension($manifestFilePath)
                    $manifestFilePath = Join-Path $manifestDirectory ("$manifestLeaf.$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))$manifestExtension")
                    Write-Warning "Existing endpoint timeline manifest is not compatible with this request. Starting a new manifest at '$manifestFilePath'."
                }
                $manifestState = New-XdrEndpointTimelineManifestState -Compatibility $manifestCompatibility -Chunks $dateChunks -RequestContextSummary $requestContextSummary
                Write-XdrTimelineManifest -Path $manifestFilePath -Manifest $manifestState
            }

            $estimatedBytesPerChunk = [double]([math]::Max([double]32MB, [double]$PageSize * 32768.0))
            $estimatedTimelineBytes = [int64]([math]::Max([double]1GB, [double]@($dateChunks).Count * $estimatedBytesPerChunk))
            Test-XdrTimelineDiskSpace -Path @($exportFilePath, $manifestFilePath, $runTempPath) -EstimatedBytes $estimatedTimelineBytes
        }
        else {
            $manifestState = New-XdrEndpointTimelineManifestState -Compatibility $manifestCompatibility -Chunks $dateChunks -RequestContextSummary $requestContextSummary
        }

        $operationTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @()
        $failures = @()
        $jsonFiles = @()
        $totalEvents = 0
        $totalSizeKB = 0.0
        $returnedEventsCount = 0
        $exportedEvents = 0
        $finalKeySetHash = $null
        $capturedError = $null
        $runCompleted = $false
        $apiDownloadSeconds = 0.0
        $mergeSeconds = 0.0
        $sortSeconds = 0.0
        $cleanupSeconds = 0.0
        $adaptiveWaveCount = 0
        $adaptiveSplitCount = 0
        $leafJobCount = @($dateChunks).Count
        $totalJobCount = @($dateChunks).Count

        try {
            $runResultByChunkIndex = @{}

            while ($true) {
                $pendingChunks = @(Get-XdrEndpointTimelinePendingChunk -Manifest $manifestState)
                if ($pendingChunks.Count -eq 0) {
                    break
                }

                $adaptiveWaveCount++
                $downloadResults = @(Invoke-XdrTimelineChunkQueue -Chunks $pendingChunks -WorkerScript $workerScript -SharedParameters $sharedParameters -ThrottleLimit $ThrottleLimit -TimeoutSeconds $TimeoutSeconds -Activity 'Retrieving Endpoint Device Timeline')
                foreach ($result in $downloadResults) {
                    Update-XdrEndpointTimelineManifestJob -Manifest $manifestState -Result $result
                    if ($manifestFilePath) { Write-XdrTimelineManifest -Path $manifestFilePath -Manifest $manifestState }
                }

                $authExpiredResults = @($downloadResults | Where-Object { -not $_.Success -and $_.FailureClass -eq 'AuthExpired' })
                if ($authExpiredResults.Count -gt 0) {
                    Write-Verbose "Refreshing XDR connection after $($authExpiredResults.Count) endpoint timeline chunk(s) reported expired auth."
                    Invoke-XdrConnectionRenewal
                    $requestContext = Get-XdrRequestContextSnapshot
                    $sharedParameters.CookieData = $requestContext.CookieData
                    $sharedParameters.HeadersData = $requestContext.HeadersData
                    $retryChunkIndexes = @($authExpiredResults | ForEach-Object { [int]$_.ChunkIndex })
                    $retryChunks = @($pendingChunks | Where-Object { $retryChunkIndexes -contains [int]$_.Index })
                    $retryResults = @(Invoke-XdrTimelineChunkQueue -Chunks $retryChunks -WorkerScript $workerScript -SharedParameters $sharedParameters -ThrottleLimit $ThrottleLimit -TimeoutSeconds $TimeoutSeconds -Activity 'Retrying Endpoint Device Timeline After Auth Renewal')
                    foreach ($result in $retryResults) {
                        Update-XdrEndpointTimelineManifestJob -Manifest $manifestState -Result $result
                        if ($manifestFilePath) { Write-XdrTimelineManifest -Path $manifestFilePath -Manifest $manifestState }
                    }
                    $downloadResults = @($downloadResults | Where-Object { $retryChunkIndexes -notcontains [int]$_.ChunkIndex }) + @($retryResults)
                }

                $newChildJobs = [System.Collections.Generic.List[object]]::new()
                foreach ($result in @($downloadResults)) {
                    $runResultByChunkIndex[[int]$result.ChunkIndex] = $result
                }
                foreach ($result in @($downloadResults | Where-Object { -not $_.Success -and $_.FailureClass -ne 'AuthExpired' })) {
                    $children = @(Split-XdrEndpointTimelineManifestJob -Manifest $manifestState -Result $result -GlobalFromDate $FromDate -GlobalToDate $ToDate -OverlapSeconds $timelineOverlapSeconds -MinimumChunkMinutes $adaptiveMinimumChunkMinutes -DensePageThreshold $adaptiveDensePageThreshold)
                    foreach ($child in $children) { [void]$newChildJobs.Add($child) }
                }

                if ($newChildJobs.Count -gt 0) {
                    $adaptiveSplitCount += $newChildJobs.Count
                    if ($manifestFilePath) { Write-XdrTimelineManifest -Path $manifestFilePath -Manifest $manifestState }
                    Write-Information "Adaptive endpoint timeline planner split $($newChildJobs.Count) dense child job(s) after wave $adaptiveWaveCount." -InformationAction Continue
                    continue
                }

                break
            }

            $results = @(
                foreach ($job in @(Get-XdrEndpointTimelineManifestJob -Manifest $manifestState -LeafOnly)) {
                    $jobStatus = [string](Get-XdrTimelineObjectValue -InputObject $job -Name 'Status')
                    $jobChunkIndex = [int](Get-XdrTimelineObjectValue -InputObject $job -Name 'ChunkIndex')
                    if ($runResultByChunkIndex.ContainsKey($jobChunkIndex)) {
                        $runResultByChunkIndex[$jobChunkIndex]
                        continue
                    }
                    if ($jobStatus -eq 'Succeeded' -and (Test-XdrEndpointTimelineManifestJobComplete -Job $job)) {
                        New-XdrEndpointTimelineResultFromJob -Job $job
                    }
                    elseif ($jobStatus -eq 'Failed') {
                        [PSCustomObject]@{
                            ChunkIndex            = [int](Get-XdrTimelineObjectValue -InputObject $job -Name 'ChunkIndex')
                            RequestShapeHash      = $null
                            RequestShape          = 'ManifestFailedJob'
                            FilePath              = Get-XdrTimelineObjectValue -InputObject $job -Name 'FilePath'
                            FileSha256            = Get-XdrTimelineObjectValue -InputObject $job -Name 'FileSha256'
                            EventCount            = [int](Get-XdrTimelineObjectValue -InputObject $job -Name 'EventCount')
                            UniqueKeyCount        = [int](Get-XdrTimelineObjectValue -InputObject $job -Name 'UniqueKeyCount')
                            KeySetHash            = Get-XdrTimelineObjectValue -InputObject $job -Name 'KeySetHash'
                            FirstTimestamp        = Get-XdrTimelineObjectValue -InputObject $job -Name 'FirstTimestamp'
                            LastTimestamp         = Get-XdrTimelineObjectValue -InputObject $job -Name 'LastTimestamp'
                            MissingTimestampCount = [int](Get-XdrTimelineObjectValue -InputObject $job -Name 'MissingTimestampCount')
                            FromDate              = [datetime](Get-XdrTimelineObjectValue -InputObject $job -Name 'RequestFrom')
                            ToDate                = [datetime](Get-XdrTimelineObjectValue -InputObject $job -Name 'RequestTo')
                            OwnerFromDate         = [datetime](Get-XdrTimelineObjectValue -InputObject $job -Name 'OwnerFrom')
                            OwnerToDate           = [datetime](Get-XdrTimelineObjectValue -InputObject $job -Name 'OwnerTo')
                            Success               = $false
                            FailureClass          = Get-XdrTimelineObjectValue -InputObject $job -Name 'FailureClass'
                            ElapsedSeconds        = 0
                            PagesRetrieved        = 0
                            ContinuationPageCount = 0
                            NextLinkCount         = 0
                            PrevLinkCount         = 0
                            RetryCount            = 0
                            Pages                 = @()
                            Partial               = $true
                            FileSizeKB            = 0
                            Error                 = Get-XdrTimelineObjectValue -InputObject $job -Name 'Error'
                        }
                    }
                }
            )

            $failures = @($results | Where-Object { -not $_.Success })
            $leafJobCount = @(Get-XdrEndpointTimelineManifestJob -Manifest $manifestState -LeafOnly).Count
            $totalJobCount = @(Get-XdrEndpointTimelineManifestJob -Manifest $manifestState).Count
            if ($failures.Count -gt 0 -and -not $AllowPartial) {
                $failureDetails = $failures | Sort-Object ChunkIndex | ForEach-Object { "chunk $($_.ChunkIndex): $($_.Error)" }
                throw "Failed to retrieve endpoint device timeline chunks: $($failureDetails -join '; '). Completed chunk files and manifest were preserved for resume. Re-run with -AllowPartial to export validated partial data."
            }
            elseif ($failures.Count -gt 0) {
                $failureDetails = $failures | Sort-Object ChunkIndex | ForEach-Object { "chunk $($_.ChunkIndex): $($_.Error)" }
                Write-Warning "Returning partial endpoint device timeline data; failed chunks: $($failureDetails -join '; ')"
            }
            $apiDownloadSeconds = [math]::Round($operationTimer.Elapsed.TotalSeconds, 4)

            $successfulResults = @($results | Where-Object { $_.Success })
            $mergeableResults = @(
                if ($AllowPartial) {
                    $results | Where-Object { $_.FilePath -and (Test-Path -LiteralPath $_.FilePath) }
                }
                else {
                    $successfulResults
                }
            )
            $totalEvents = [int](($mergeableResults | Measure-Object -Property EventCount -Sum).Sum)
            $totalSizeKB = [double](($mergeableResults | Measure-Object -Property FileSizeKB -Sum).Sum)

            $jsonFiles = @(
                $mergeableResults |
                    Where-Object { $_.FilePath -and (Test-Path -LiteralPath $_.FilePath) } |
                    ForEach-Object { Get-Item -LiteralPath $_.FilePath } |
                    Sort-Object Name
            )

            if ($jsonFiles.Count -lt $mergeableResults.Count -and -not $AllowPartial) {
                throw "Only $($jsonFiles.Count) of $($mergeableResults.Count) completed endpoint timeline chunk file(s) were available for merge."
            }

            $hasChunkFilesToMerge = $jsonFiles.Count -gt 0

            if ($exportFilePath) {
                $parent = Split-Path -Path $exportFilePath -Parent
                if ($parent -and -not (Test-Path -Path $parent)) {
                    New-Item -Path $parent -ItemType Directory -Force | Out-Null
                }

                $mergeTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $rawRecords = @(
                    if ($hasChunkFilesToMerge) {
                        Merge-XdrTimelineChunkRawEvent -File $jsonFiles -AllowPartial:$AllowPartial -FilterScript {
                            param($TimelineEvent)
                            Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent $TimelineEvent -EventType $EventType
                        } -GetStableEventKeyScript {
                            param($TimelineEvent)
                            Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent
                        } -EventType $EventType -UseFastJsonMetadata
                    }
                )
                $mergeTimer.Stop()
                $mergeSeconds = [math]::Round($mergeTimer.Elapsed.TotalSeconds, 4)
                $sortSeconds = 0.0

                Write-XdrTimelineRawEventExport -Path $exportFilePath -Record $rawRecords -Format $ExportFormat
                $exportedEvents = $rawRecords.Count
                $finalKeySetHash = Get-XdrStringHash -Value ((@($rawRecords | ForEach-Object { [string]$_.StableKey }) | Sort-Object) -join "`n")

                if ($manifestState) {
                    $manifestState['Partial'] = ($failures.Count -gt 0)
                    $manifestState['Summary'] = [ordered]@{
                        ExportPath            = $exportFilePath
                        ExportFormat          = $ExportFormat
                        TotalEvents           = $exportedEvents
                        DownloadedEvents      = $totalEvents
                        UniqueEvents          = $exportedEvents
                        DuplicatesRemoved     = [math]::Max(0, $totalEvents - $exportedEvents)
                        KeySetHash            = $finalKeySetHash
                        FailedJobs            = $failures.Count
                        Partial               = ($failures.Count -gt 0)
                        OverlapSeconds        = $timelineOverlapSeconds
                        PageSize              = $PageSize
                        ChunkStrategy         = $chunkStrategy
                        ChunkMinutes          = $effectiveChunkMinutes
                        AdaptiveWaveCount     = $adaptiveWaveCount
                        AdaptiveSplitJobCount = $adaptiveSplitCount
                        TotalJobs             = $totalJobCount
                        LeafJobs              = $leafJobCount
                        StableKeyVersion      = 'EndpointTimelineStableKeyV1'
                        FinalExportFileSha256 = Get-XdrFileSha256 -Path $exportFilePath
                        CompletedAtUtc        = (Get-Date).ToUniversalTime().ToString('o')
                    }
                    Write-XdrTimelineManifest -Path $manifestFilePath -Manifest $manifestState
                }

                $runCompleted = $true
                return [PSCustomObject]@{
                    PSTypeName       = 'XdrEndpointDeviceTimelineExport'
                    ExportPath       = $exportFilePath
                    ManifestPath     = $manifestFilePath
                    ExportFormat     = $ExportFormat
                    TotalEvents      = $exportedEvents
                    TotalChunks      = $leafJobCount
                    FailedChunks     = $failures.Count
                    TotalSizeMB      = [math]::Round($totalSizeKB / 1024, 2)
                    WallClockSeconds = [math]::Round($operationTimer.Elapsed.TotalSeconds, 2)
                    EffectiveRate    = if ($operationTimer.Elapsed.TotalSeconds -gt 0) { [math]::Round($exportedEvents / $operationTimer.Elapsed.TotalSeconds, 1) } else { 0 }
                    DiagnosticsPath  = $DiagnosticsPath
                }
            }

            $mergeTimer = [System.Diagnostics.Stopwatch]::StartNew()
            if ($hasChunkFilesToMerge) {
                $mergedEvents = @(
                    Merge-XdrTimelineChunkFile -File $jsonFiles -AllowPartial:$AllowPartial -SelectEventsScript {
                        param($ChunkData)

                        @(Get-XdrEndpointTimelineChunkEvent -ChunkData $ChunkData -EventType $EventType)
                    }
                )
            }
            else {
                $mergedEvents = @()
            }
            foreach ($eventItem in $mergedEvents) {
                $eventItem.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceTimelineEvent')
            }
            $mergeTimer.Stop()
            $mergeSeconds = [math]::Round($mergeTimer.Elapsed.TotalSeconds, 4)

            $sortTimer = [System.Diagnostics.Stopwatch]::StartNew()
            $sortedEvents = if ($hasChunkFilesToMerge) { @(Get-XdrTimelineSortedEvent -Events $mergedEvents) } else { @() }
            $sortTimer.Stop()
            $sortSeconds = [math]::Round($sortTimer.Elapsed.TotalSeconds, 4)

            $returnedEventsCount = $sortedEvents.Count
            $runCompleted = $true
            return $sortedEvents
        }
        catch {
            $capturedError = $_.ToString()
            throw
        }
        finally {
            $operationTimer.Stop()
            $cleanupTimer = [System.Diagnostics.Stopwatch]::StartNew()
            if (-not $KeepTempFiles -and (Test-Path -LiteralPath $runTempPath) -and (-not $exportFilePath -or $runCompleted)) {
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            elseif (Test-Path -LiteralPath $runTempPath) {
                Write-Information "Temporary endpoint timeline files preserved in: $runTempPath" -InformationAction Continue
            }
            $cleanupTimer.Stop()
            $cleanupSeconds = [math]::Round($cleanupTimer.Elapsed.TotalSeconds, 4)

            if ($DiagnosticsPath) {
                $diagnostics = [ordered]@{
                    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                    Command        = 'Get-XdrEndpointDeviceTimeline'
                    Status         = if ($capturedError) { 'Failed' } elseif ($runCompleted) { 'Succeeded' } else { 'Incomplete' }
                    Error          = $capturedError
                    Device         = [ordered]@{
                        ParameterSetName = $PSCmdlet.ParameterSetName
                        DeviceId         = $deviceIdentifier
                        MachineDnsName   = $computerDnsName
                    }
                    Request        = [ordered]@{
                        FromDate                       = $FromDate.ToString('o')
                        ToDate                         = $ToDate.ToString('o')
                        TotalHours                     = [math]::Round($totalHours, 2)
                        ChunkHours                     = $effectiveChunkHours
                        ChunkMinutes                   = $effectiveChunkMinutes
                        ChunkStrategy                  = $chunkStrategy
                        TotalChunksPlanned             = @($dateChunks).Count
                        TotalJobsPlanned               = $totalJobCount
                        LeafJobsPlanned                = $leafJobCount
                        AdaptiveWaveCount              = $adaptiveWaveCount
                        AdaptiveSplitJobCount          = $adaptiveSplitCount
                        AdaptiveDensePageThreshold     = $adaptiveDensePageThreshold
                        AdaptiveMinimumChunkMinutes    = $adaptiveMinimumChunkMinutes
                        EarlyDensitySamplePages              = $adaptiveEarlyDensitySamplePages
                        EarlyDensityMaxTimestampSpanSeconds = $adaptiveEarlyDensityMaxTimestampSpanSeconds
                        OverlapSeconds                 = $timelineOverlapSeconds
                        PageSize                       = $PageSize
                        ThrottleLimit                  = $ThrottleLimit
                        TimeoutSeconds                 = $TimeoutSeconds
                        MaxRetries                     = $MaxRetries
                        RetryDelaySeconds              = $RetryDelaySeconds
                        RequestTimeoutSeconds          = $RequestTimeoutSeconds
                        PaginationDelayMinMilliseconds = $PaginationDelayMinMilliseconds
                        PaginationDelayMaxMilliseconds = $PaginationDelayMaxMilliseconds
                        ReturnMode                     = if ($exportFilePath) { 'Export' } else { 'InMemory' }
                        ExportFormat                   = $ExportFormat
                        ManifestPath                   = $manifestFilePath
                    }
                    Phases         = [ordered]@{
                        DeviceLookupSeconds = [math]::Round($deviceLookupTimer.Elapsed.TotalSeconds, 4)
                        ApiDownloadSeconds  = $apiDownloadSeconds
                        DownloadSeconds     = [math]::Round($operationTimer.Elapsed.TotalSeconds, 4)
                        MergeSeconds        = $mergeSeconds
                        SortSeconds         = $sortSeconds
                        CleanupSeconds      = $cleanupSeconds
                    }
                    Totals         = [ordered]@{
                        ReturnedEvents       = if ($exportFilePath) { $exportedEvents } else { $returnedEventsCount }
                        DownloadedEvents     = $totalEvents
                        SuccessfulChunkCount = @($results | Where-Object { $_.Success }).Count
                        FailedChunkCount     = @($results | Where-Object { -not $_.Success }).Count
                        MergedChunkFileCount = @($jsonFiles).Count
                        TotalSizeMB          = [math]::Round($totalSizeKB / 1024, 2)
                        KeySetHash           = $finalKeySetHash
                    }
                    Jobs           = @(
                        Get-XdrEndpointTimelineManifestJob -Manifest $manifestState |
                            Sort-Object { [int](Get-XdrTimelineObjectValue -InputObject $_ -Name 'ChunkIndex') } |
                            ForEach-Object {
                                [ordered]@{
                                    JobId          = Get-XdrTimelineObjectValue -InputObject $_ -Name 'JobId'
                                    ParentJobId    = Get-XdrTimelineObjectValue -InputObject $_ -Name 'ParentJobId'
                                    Generation     = [int](Get-XdrTimelineObjectValue -InputObject $_ -Name 'Generation')
                                    ChunkIndex     = [int](Get-XdrTimelineObjectValue -InputObject $_ -Name 'ChunkIndex')
                                    Status         = Get-XdrTimelineObjectValue -InputObject $_ -Name 'Status'
                                    SplitReason    = Get-XdrTimelineObjectValue -InputObject $_ -Name 'SplitReason'
                                    SplitStrategy  = Get-XdrTimelineObjectValue -InputObject $_ -Name 'SplitStrategy'
                                    SplitMetadata  = Get-XdrTimelineObjectValue -InputObject $_ -Name 'SplitMetadata'
                                    ChildJobIds    = @(Get-XdrTimelineObjectValue -InputObject $_ -Name 'ChildJobIds')
                                    PagesRetrieved = Get-XdrTimelineObjectValue -InputObject $_ -Name 'PagesRetrieved'
                                    OwnerFrom      = Get-XdrTimelineObjectValue -InputObject $_ -Name 'OwnerFrom'
                                    OwnerTo        = Get-XdrTimelineObjectValue -InputObject $_ -Name 'OwnerTo'
                                    RequestFrom    = Get-XdrTimelineObjectValue -InputObject $_ -Name 'RequestFrom'
                                    RequestTo      = Get-XdrTimelineObjectValue -InputObject $_ -Name 'RequestTo'
                                }
                            }
                    )
                    Chunks         = @(
                        $results |
                            Sort-Object ChunkIndex |
                            ForEach-Object {
                                [ordered]@{
                                    ChunkIndex            = $_.ChunkIndex
                                    RequestShape          = $_.RequestShape
                                    RequestShapeHash      = $_.RequestShapeHash
                                    FilePath              = $_.FilePath
                                    FileSha256            = $_.FileSha256
                                    FromDate              = if ($_.FromDate) { ([datetime]$_.FromDate).ToUniversalTime().ToString('o') } else { $null }
                                    ToDate                = if ($_.ToDate) { ([datetime]$_.ToDate).ToUniversalTime().ToString('o') } else { $null }
                                    OwnerFromDate         = if ($_.OwnerFromDate) { ([datetime]$_.OwnerFromDate).ToUniversalTime().ToString('o') } else { $null }
                                    OwnerToDate           = if ($_.OwnerToDate) { ([datetime]$_.OwnerToDate).ToUniversalTime().ToString('o') } else { $null }
                                    Success               = [bool]$_.Success
                                    Partial               = [bool]($_.Partial)
                                    EventCount            = [int]($_.EventCount)
                                    UniqueKeyCount        = if ($_.PSObject.Properties['UniqueKeyCount']) { [int]($_.UniqueKeyCount) } else { [int]($_.EventCount) }
                                    KeySetHash            = if ($_.PSObject.Properties['KeySetHash']) { $_.KeySetHash } else { $null }
                                    FirstTimestamp        = if ($_.PSObject.Properties['FirstTimestamp']) { $_.FirstTimestamp } else { $null }
                                    LastTimestamp         = if ($_.PSObject.Properties['LastTimestamp']) { $_.LastTimestamp } else { $null }
                                    MissingTimestampCount = if ($_.PSObject.Properties['MissingTimestampCount']) { [int]($_.MissingTimestampCount) } else { 0 }
                                    PagesRetrieved        = [int]($_.PagesRetrieved)
                                    ContinuationPageCount = [int]($_.ContinuationPageCount)
                                    NextLinkCount         = [int]($_.NextLinkCount)
                                    PrevLinkCount         = [int]($_.PrevLinkCount)
                                    RetryCount            = [int]($_.RetryCount)
                                    FileSizeKB            = [double]($_.FileSizeKB)
                                    ElapsedSeconds        = [double]($_.ElapsedSeconds)
                                    FailureClass          = if ($_.PSObject.Properties['FailureClass']) { $_.FailureClass } else { $null }
                                    Pages                 = @(
                                        @($_.Pages) |
                                            Where-Object { $null -ne $_ } |
                                            ForEach-Object {
                                                $page = $_
                                                [ordered]@{
                                                    PageIndex                 = [int]($page.PageIndex)
                                                    ElapsedMilliseconds       = [double]($page.ElapsedMilliseconds)
                                                    RawItemCount              = if ($page.PSObject.Properties['RawItemCount']) { [int]($page.RawItemCount) } else { [int]($page.ItemCount) }
                                                    ItemCount                 = [int]($page.ItemCount)
                                                    FilteredOutOfChunkCount   = if ($page.PSObject.Properties['FilteredOutOfChunkCount']) { [int]($page.FilteredOutOfChunkCount) } else { 0 }
                                                    ReachedChunkEnd           = if ($page.PSObject.Properties['ReachedChunkEnd']) { [bool]($page.ReachedChunkEnd) } else { $false }
                                                    EventPayloadBytes         = [int64]($page.EventPayloadBytes)
                                                    HasNext                   = [bool]($page.HasNext)
                                                    HasPrev                   = [bool]($page.HasPrev)
                                                    NextShape                 = $page.NextShape
                                                    PrevShape                 = $page.PrevShape
                                                    NextHash                  = $page.NextHash
                                                    PrevHash                  = $page.PrevHash
                                                    RequestUriHash            = $page.RequestUriHash
                                                    FirstEventTimestamp       = $page.FirstEventTimestamp
                                                    LastEventTimestamp        = $page.LastEventTimestamp
                                                    DuplicateWithinChunkCount = [int]($page.DuplicateWithinChunkCount)
                                                }
                                            }
                                    )
                                    Error                 = $_.Error
                                }
                            }
                    )
                }

                try {
                    Write-XdrTimelineDiagnosticFile -Path $DiagnosticsPath -Diagnostics $diagnostics
                }
                catch {
                    Write-Warning "Failed to write endpoint timeline diagnostics to '$DiagnosticsPath': $($_.Exception.Message)"
                }
            }
        }
    }
}
