function Read-XdrEndpointTimelineChunkFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter()]
        [switch]$AllowPartial
    )

    try {
        return Get-Content -Path $File.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        if ($AllowPartial) {
            Write-Warning "Skipping unreadable endpoint timeline chunk file '$($File.Name)': $($_.Exception.Message)"
            return $null
        }

        throw
    }
}

function Get-XdrEndpointTimelineChunkEventsJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter()]
        [switch]$AllowPartial
    )

    try {
        $rawContent = [System.IO.File]::ReadAllText($File.FullName)
        $eventsStart = $rawContent.IndexOf('"Events":[')
        if ($eventsStart -lt 0) {
            throw "Could not locate the Events array."
        }

        $eventsStart += 10
        $eventsEnd = $rawContent.LastIndexOf('],"EventCount"')
        if ($eventsEnd -lt 0) {
            $eventsEnd = $rawContent.LastIndexOf(']}')
        }

        if ($eventsEnd -lt $eventsStart) {
            throw "Could not determine the end of the Events array."
        }

        return $rawContent.Substring($eventsStart, $eventsEnd - $eventsStart)
    }
    catch {
        if ($AllowPartial) {
            Write-Warning "Skipping unreadable endpoint timeline chunk file '$($File.Name)': $($_.Exception.Message)"
            return $null
        }

        throw
    }
}

function Get-XdrEndpointTimelineContinuationPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Response
    )

    if ($Response.PSObject.Properties['Prev']) {
        $value = [string]$Response.Prev
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return $null
}

function Get-XdrEndpointTimelineNextUri {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [object]$Response
    )

    $continuationPath = Get-XdrEndpointTimelineContinuationPath -Response $Response
    if ([string]::IsNullOrWhiteSpace($continuationPath)) {
        return $null
    }

    if ($continuationPath -match '^https?://') {
        return $continuationPath
    }

    if ($continuationPath.StartsWith('/')) {
        return "$BaseUrl/apiproxy/mtp/mdeTimelineExperience$continuationPath"
    }

    return "$BaseUrl/apiproxy/mtp/mdeTimelineExperience/$continuationPath"
}

function Get-XdrEndpointTimelineEventTypeName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$TimelineEvent
    )

    foreach ($propertyName in @('ActionType', 'Type', 'EventType')) {
        if ($TimelineEvent.PSObject.Properties[$propertyName]) {
            $value = [string]$TimelineEvent.$propertyName
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                return $value
            }
        }
    }

    return $null
}

function Test-XdrEndpointTimelineEventTypeMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [object]$TimelineEvent,

        [Parameter()]
        [string]$EventType
    )

    if ([string]::IsNullOrWhiteSpace($EventType)) {
        return $true
    }

    $eventTypeName = Get-XdrEndpointTimelineEventTypeName -TimelineEvent $TimelineEvent
    if ([string]::IsNullOrWhiteSpace($eventTypeName)) {
        return $false
    }

    return ($eventTypeName -like $EventType)
}

function Get-XdrEndpointTimelineEventTimestamp {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory)]
        [object]$TimelineEvent
    )

    foreach ($propertyName in @('Timestamp', 'timestamp')) {
        if (-not $TimelineEvent.PSObject.Properties[$propertyName]) {
            continue
        }

        $value = $TimelineEvent.$propertyName
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
            continue
        }

        try {
            return ([datetime]$value).ToUniversalTime()
        }
        catch {
            continue
        }
    }

    return $null
}

function Get-XdrEndpointTimelineChunkEvent {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object]$ChunkData,

        [Parameter()]
        [string]$EventType
    )

    $events = @($ChunkData.Events)
    if ([string]::IsNullOrWhiteSpace($EventType) -or $events.Count -eq 0) {
        return $events
    }

    $filteredEvents = [System.Collections.Generic.List[object]]::new()
    foreach ($eventItem in $events) {
        if (Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent $eventItem -EventType $EventType) {
            $filteredEvents.Add($eventItem)
        }
    }

    return $filteredEvents.ToArray()
}

function Get-XdrEndpointTimelineSortedEvent {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Events = @()
    )

    if ($Events.Count -le 1) {
        return $Events
    }

    $sortableEvents = $Events | Where-Object { $null -ne (Get-XdrEndpointTimelineEventTimestamp -TimelineEvent $_) }
    if (@($sortableEvents).Count -eq 0) {
        return $Events
    }

    return @(
        $Events | Sort-Object -Property @{
            Expression = {
                $timestamp = Get-XdrEndpointTimelineEventTimestamp -TimelineEvent $_
                if ($null -eq $timestamp) { return [datetime]::MinValue }
                return $timestamp
            }
            Descending = $true
        }
    )
}

function Write-XdrEndpointTimelineDiagnosticFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Diagnostics
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -Path $parentPath)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }

    $Diagnostics | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

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
        Maximum is 180 days.

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

    .PARAMETER PaginationDelayMinMilliseconds
        Minimum delay in milliseconds between continuation-page requests. Defaults to 500.

    .PARAMETER PaginationDelayMaxMilliseconds
        Maximum delay in milliseconds between continuation-page requests. Defaults to 1500.

    .PARAMETER ChunkHours
        The size of each time chunk in hours for parallel processing. Defaults to 4 hours.
        For time windows of 24 hours or less, 1-hour chunks are used automatically. For time windows
        up to 48 hours, chunk size is calculated toward roughly 24 chunks to improve parallel saturation
        without requiring manual tuning.
        Larger chunks reduce overhead but may increase individual request times.

    .PARAMETER OutputPath
        Optional. Writes results directly to the specified output file. The legacy ExportPath
        parameter name is still accepted as an alias.

    .PARAMETER WorkingDirectory
        Optional. Directory used for temporary chunk files. Defaults to a temp folder.

    .PARAMETER KeepTempFiles
        If specified, keeps the temporary JSON files after merging.

    .PARAMETER ExportFormat
        Export file format. Json preserves the traditional array output; Ndjson writes
        one event per line and is preferred for large exports.

    .PARAMETER RequestTimeoutSeconds
        Timeout in seconds for individual HTTP requests. Defaults to 60.

    .PARAMETER AllowPartial
        Returns completed chunks instead of terminating when one or more chunks fail.

    .PARAMETER DiagnosticsPath
        Optional. Writes structured diagnostics about chunking, request timing, retries, and merge phases to a JSON file.

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
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -LastNDays 7 -OutputPath "C:\Reports\timeline.json"
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
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
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
        [ValidateRange(0, 10000)]
        [int]$PaginationDelayMinMilliseconds = 500,

        [Parameter()]
        [ValidateRange(0, 10000)]
        [int]$PaginationDelayMaxMilliseconds = 1500,

        [Parameter()]
        [ValidateRange(1, 24)]
        [int]$ChunkHours = 4,

        [Parameter()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            $parentDir = Split-Path -Path $_ -Parent
            if ([string]::IsNullOrWhiteSpace($parentDir)) { return $true }
            return $true
        })]
        [Alias('ExportPath')]
        [string]$OutputPath,

        [Parameter()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            if (-not (Test-Path -Path $_ -PathType Container)) {
                throw "WorkingDirectory '$_' does not exist or is not a directory."
            }
            return $true
        })]
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
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            $parentDir = Split-Path -Path $_ -Parent
            if ([string]::IsNullOrWhiteSpace($parentDir)) { return $true }
            return $true
        })]
        [string]$DiagnosticsPath
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

        if ($PaginationDelayMaxMilliseconds -lt $PaginationDelayMinMilliseconds) {
            throw "PaginationDelayMaxMilliseconds must be greater than or equal to PaginationDelayMinMilliseconds."
        }

        $deviceLookupSeconds = 0.0
        $chunkPlanningSeconds = 0.0
        $downloadWallClockSeconds = 0.0
        $mergePhaseSeconds = 0.0
        $sortPhaseSeconds = 0.0
        $exportPhaseSeconds = 0.0
        $cleanupSeconds = 0.0
        $chunkStrategy = if ($PSBoundParameters.ContainsKey('ChunkHours')) { 'Explicit' } else { 'DefaultStatic' }
        $results = @()
        $jsonFiles = @()
        $failures = @()
        $totalElapsed = 0.0
        $totalEvents = 0
        $totalSizeKB = 0.0
        $overallEventsPerSec = 0.0
        $exportedEvents = 0
        $returnMode = if ($OutputPath) { 'Export' } else { 'InMemory' }
        $usedRawJsonExport = $false
        $resultSummary = $null
        $returnedEventsCount = 0
        $capturedError = $null
        $runCompleted = $false
        $wallClockSeconds = 0.0

        # Determine the device identifier with proper error handling
        $deviceLookup = $null
        $deviceLookupStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
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
        }
        finally {
            $deviceLookupStopwatch.Stop()
            $deviceLookupSeconds = [math]::Round($deviceLookupStopwatch.Elapsed.TotalSeconds, 4)
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

        # Set up temporary working directory using cross-platform temp path
        $baseTempPath = if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            $WorkingDirectory
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
            RequestTimeoutSeconds  = $RequestTimeoutSeconds
            PaginationDelayMinMilliseconds = $PaginationDelayMinMilliseconds
            PaginationDelayMaxMilliseconds = $PaginationDelayMaxMilliseconds
            CollectDiagnostics     = [bool]$PSBoundParameters.ContainsKey('DiagnosticsPath')
        }

        # Generate date chunks using configurable chunk size
        $chunkPlanningStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $dateChunks = [System.Collections.Generic.List[hashtable]]::new()
        $totalDays = ($ToDate - $FromDate).TotalDays
        $totalHours = $totalDays * 24

        # For shorter time windows (≤48 hours), keep common 1-day investigations at 1-hour chunks
        # and scale toward roughly 24 chunks for longer windows without requiring manual tuning.
        if (-not $PSBoundParameters.ContainsKey('ChunkHours') -and $totalHours -le 48) {
            $ChunkHours = if ($totalHours -le 24) {
                $chunkStrategy = 'Auto24HourOneHourChunks'
                1
            } else {
                $chunkStrategy = 'Auto48HourBalanced'
                [math]::Max(1, [math]::Ceiling($totalHours / 24))
            }
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
        $chunkPlanningStopwatch.Stop()
        $chunkPlanningSeconds = [math]::Round($chunkPlanningStopwatch.Elapsed.TotalSeconds, 4)

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

        Write-Information "Split $([math]::Round($totalHours, 1)) hours into $($dateChunks.Count) chunks ($ChunkHours hour$(if($ChunkHours -gt 1){'s'}) each)" -InformationAction Continue

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
                            $retryCount = 0
                            $throttleRetryCount = 0
                            $backoffSeconds = 0.0
                            $interPageDelaySeconds = 0.0
                            $requestSeconds = 0.0
                            $requestSecondsMax = 0.0
                            $pageProcessingSeconds = 0.0
                            $pageProcessingSecondsMax = 0.0
                            $itemsPerPageMin = $null
                            $itemsPerPageMax = 0
                            $itemsPerPageTotal = 0

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
                                        $requestStopwatch = if ($baseParams.CollectDiagnostics) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
                                        $response = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $webSession -Headers $headerInfo -TimeoutSec $baseParams.RequestTimeoutSeconds -ErrorAction Stop
                                        if ($requestStopwatch) {
                                            $requestStopwatch.Stop()
                                            $requestSeconds += $requestStopwatch.Elapsed.TotalSeconds
                                            if ($requestStopwatch.Elapsed.TotalSeconds -gt $requestSecondsMax) {
                                                $requestSecondsMax = $requestStopwatch.Elapsed.TotalSeconds
                                            }
                                        }
                                        $success = $true
                                        $pagesRetrieved++
                                    } catch {
                                        if ($requestStopwatch -and $requestStopwatch.IsRunning) {
                                            $requestStopwatch.Stop()
                                            $requestSeconds += $requestStopwatch.Elapsed.TotalSeconds
                                            if ($requestStopwatch.Elapsed.TotalSeconds -gt $requestSecondsMax) {
                                                $requestSecondsMax = $requestStopwatch.Elapsed.TotalSeconds
                                            }
                                        }
                                        $statusCode = $null
                                        if ($_.Exception.Response) {
                                            $statusCode = [int]$_.Exception.Response.StatusCode
                                        }

                                        if ($statusCode -eq 429 -or $statusCode -eq 403) {
                                            # Rate limited - use exponential backoff
                                            $delay = $baseDelay * [Math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 1 -Maximum 10)
                                            $delay = [Math]::Min($delay, 300) # Cap at 5 minutes
                                            if ($attempt -ge $maxRetries) {
                                                throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                            }
                                            if ($baseParams.CollectDiagnostics) {
                                                $retryCount++
                                                $throttleRetryCount++
                                                $backoffSeconds += $delay
                                            }
                                            Start-Sleep -Seconds $delay
                                        } elseif ($attempt -lt $maxRetries) {
                                            $delay = Get-Random -Minimum 5 -Maximum 15
                                            if ($baseParams.CollectDiagnostics) {
                                                $retryCount++
                                                $backoffSeconds += $delay
                                            }
                                            Start-Sleep -Seconds $delay
                                        } else {
                                            throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                        }
                                    }
                                }

                                # Stream events directly to file instead of accumulating in memory
                                $nextUri = $null
                                if ($response) {
                                    $pageProcessingStopwatch = if ($baseParams.CollectDiagnostics) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
                                    $itemsThisPage = @($response.Items).Count
                                    if ($baseParams.CollectDiagnostics) {
                                        if ($null -eq $itemsPerPageMin -or $itemsThisPage -lt $itemsPerPageMin) {
                                            $itemsPerPageMin = $itemsThisPage
                                        }
                                        if ($itemsThisPage -gt $itemsPerPageMax) {
                                            $itemsPerPageMax = $itemsThisPage
                                        }
                                        $itemsPerPageTotal += $itemsThisPage
                                    }
                                    if ($response.Items) {
                                        foreach ($item in $response.Items) {
                                            if (-not $isFirstEvent) { $streamWriter.Write(',') }
                                            $streamWriter.Write(($item | ConvertTo-Json -Depth 20 -Compress))
                                            $isFirstEvent = $false
                                            $eventCount++
                                        }
                                    }
                                    # Capture next page URL before clearing response
                                    $continuationPath = if (-not [string]::IsNullOrWhiteSpace([string]$response.Prev)) {
                                        [string]$response.Prev
                                    } else {
                                        $null
                                    }
                                    if ($continuationPath) {
                                        if ($continuationPath -match '^https?://') {
                                            $nextUri = $continuationPath
                                        } elseif ($continuationPath.StartsWith('/')) {
                                            $nextUri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience$continuationPath"
                                        } else {
                                            $nextUri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience/$continuationPath"
                                        }
                                    }
                                    # Clear response to free memory immediately
                                    $response = $null
                                    if ($pageProcessingStopwatch) {
                                        $pageProcessingStopwatch.Stop()
                                        $pageProcessingSeconds += $pageProcessingStopwatch.Elapsed.TotalSeconds
                                        if ($pageProcessingStopwatch.Elapsed.TotalSeconds -gt $pageProcessingSecondsMax) {
                                            $pageProcessingSecondsMax = $pageProcessingStopwatch.Elapsed.TotalSeconds
                                        }
                                    }
                                }

                                if (-not $nextUri) {
                                    break
                                } else {
                                    $Uri = $nextUri
                                    $paginationDelayMilliseconds = if ($baseParams.PaginationDelayMaxMilliseconds -le $baseParams.PaginationDelayMinMilliseconds) {
                                        [int]$baseParams.PaginationDelayMinMilliseconds
                                    } else {
                                        Get-Random -Minimum $baseParams.PaginationDelayMinMilliseconds -Maximum ($baseParams.PaginationDelayMaxMilliseconds + 1)
                                    }
                                    if ($baseParams.CollectDiagnostics -and $paginationDelayMilliseconds -gt 0) {
                                        $interPageDelaySeconds += ($paginationDelayMilliseconds / 1000)
                                    }
                                    if ($paginationDelayMilliseconds -gt 0) {
                                        Start-Sleep -Milliseconds $paginationDelayMilliseconds
                                    }
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
                                RetryCount     = $retryCount
                                ThrottleRetryCount = $throttleRetryCount
                                BackoffSeconds = [math]::Round($backoffSeconds, 2)
                                InterPageDelaySeconds = [math]::Round($interPageDelaySeconds, 2)
                                RequestSeconds = [math]::Round($requestSeconds, 2)
                                RequestSecondsMax = [math]::Round($requestSecondsMax, 2)
                                PageProcessingSeconds = [math]::Round($pageProcessingSeconds, 2)
                                PageProcessingSecondsMax = [math]::Round($pageProcessingSecondsMax, 2)
                                ItemsPerPageAverage = if ($pagesRetrieved -gt 0) { [math]::Round($itemsPerPageTotal / $pagesRetrieved, 2) } else { 0 }
                                ItemsPerPageMin = if ($null -ne $itemsPerPageMin) { [int]$itemsPerPageMin } else { 0 }
                                ItemsPerPageMax = [int]$itemsPerPageMax
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
                                RetryCount     = if ($null -ne $retryCount) { $retryCount } else { 0 }
                                ThrottleRetryCount = if ($null -ne $throttleRetryCount) { $throttleRetryCount } else { 0 }
                                BackoffSeconds = if ($null -ne $backoffSeconds) { [math]::Round($backoffSeconds, 2) } else { 0 }
                                InterPageDelaySeconds = if ($null -ne $interPageDelaySeconds) { [math]::Round($interPageDelaySeconds, 2) } else { 0 }
                                RequestSeconds = if ($null -ne $requestSeconds) { [math]::Round($requestSeconds, 2) } else { 0 }
                                RequestSecondsMax = if ($null -ne $requestSecondsMax) { [math]::Round($requestSecondsMax, 2) } else { 0 }
                                PageProcessingSeconds = if ($null -ne $pageProcessingSeconds) { [math]::Round($pageProcessingSeconds, 2) } else { 0 }
                                PageProcessingSecondsMax = if ($null -ne $pageProcessingSecondsMax) { [math]::Round($pageProcessingSecondsMax, 2) } else { 0 }
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
                if ($parallelJob.State -eq 'Completed') {
                    $results = Receive-Job -Job $parallelJob -Wait
                } else {
                    $results = Receive-Job -Job $parallelJob -ErrorAction SilentlyContinue
                }
                Remove-Job -Job $parallelJob -Force

                if (@($results).Count -eq 0 -and $chunkFiles.Count -gt 0) {
                    $results = foreach ($file in ($chunkFiles | Sort-Object Name)) {
                        $chunkData = Read-XdrEndpointTimelineChunkFile -File $file -AllowPartial:$AllowPartial
                        [PSCustomObject]@{
                            ChunkIndex     = if ($file.BaseName -match '^chunk_(\d+)_') { [int]$Matches[1] } else { 0 }
                            FilePath       = $file.FullName
                            EventCount     = if ($chunkData) { @($chunkData.Events).Count } else { 0 }
                            FromDate       = if ($chunkData -and $chunkData.FromDate) { [datetime]$chunkData.FromDate } else { $null }
                            ToDate         = if ($chunkData -and $chunkData.ToDate) { [datetime]$chunkData.ToDate } else { $null }
                            Success        = $true
                            ElapsedSeconds = 0
                            PagesRetrieved = 0
                            FileSizeKB     = [math]::Round($file.Length / 1KB, 2)
                        }
                    }
                }

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
                        $retryCount = 0
                        $throttleRetryCount = 0
                        $backoffSeconds = 0.0
                        $interPageDelaySeconds = 0.0
                        $requestSeconds = 0.0
                        $requestSecondsMax = 0.0
                        $pageProcessingSeconds = 0.0
                        $pageProcessingSecondsMax = 0.0
                        $itemsPerPageMin = $null
                        $itemsPerPageMax = 0
                        $itemsPerPageTotal = 0

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
                                    $requestStopwatch = if ($baseParams.CollectDiagnostics) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
                                    $response = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $webSession -Headers $headerInfo -TimeoutSec $baseParams.RequestTimeoutSeconds -ErrorAction Stop
                                    if ($requestStopwatch) {
                                        $requestStopwatch.Stop()
                                        $requestSeconds += $requestStopwatch.Elapsed.TotalSeconds
                                        if ($requestStopwatch.Elapsed.TotalSeconds -gt $requestSecondsMax) {
                                            $requestSecondsMax = $requestStopwatch.Elapsed.TotalSeconds
                                        }
                                    }
                                    $success = $true
                                    $pagesRetrieved++
                                } catch {
                                    if ($requestStopwatch -and $requestStopwatch.IsRunning) {
                                        $requestStopwatch.Stop()
                                        $requestSeconds += $requestStopwatch.Elapsed.TotalSeconds
                                        if ($requestStopwatch.Elapsed.TotalSeconds -gt $requestSecondsMax) {
                                            $requestSecondsMax = $requestStopwatch.Elapsed.TotalSeconds
                                        }
                                    }
                                    $statusCode = $null
                                    if ($_.Exception.Response) {
                                        $statusCode = [int]$_.Exception.Response.StatusCode
                                    }

                                    if ($statusCode -eq 429 -or $statusCode -eq 403) {
                                        # Rate limited - use exponential backoff
                                        $delay = $baseDelay * [Math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 1 -Maximum 10)
                                        $delay = [Math]::Min($delay, 300) # Cap at 5 minutes
                                        if ($attempt -ge $maxRetries) {
                                            throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                        }
                                        if ($baseParams.CollectDiagnostics) {
                                            $retryCount++
                                            $throttleRetryCount++
                                            $backoffSeconds += $delay
                                        }
                                        Start-Sleep -Seconds $delay
                                    } elseif ($attempt -lt $maxRetries) {
                                        $delay = Get-Random -Minimum 5 -Maximum 15
                                        if ($baseParams.CollectDiagnostics) {
                                            $retryCount++
                                            $backoffSeconds += $delay
                                        }
                                        Start-Sleep -Seconds $delay
                                    } else {
                                        throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                    }
                                }
                            }

                            # Stream events directly to file instead of accumulating in memory
                            $nextUri = $null
                            if ($response) {
                                $pageProcessingStopwatch = if ($baseParams.CollectDiagnostics) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
                                $itemsThisPage = @($response.Items).Count
                                if ($baseParams.CollectDiagnostics) {
                                    if ($null -eq $itemsPerPageMin -or $itemsThisPage -lt $itemsPerPageMin) {
                                        $itemsPerPageMin = $itemsThisPage
                                    }
                                    if ($itemsThisPage -gt $itemsPerPageMax) {
                                        $itemsPerPageMax = $itemsThisPage
                                    }
                                    $itemsPerPageTotal += $itemsThisPage
                                }
                                if ($response.Items) {
                                    foreach ($item in $response.Items) {
                                        if (-not $isFirstEvent) { $streamWriter.Write(',') }
                                        $streamWriter.Write(($item | ConvertTo-Json -Depth 20 -Compress))
                                        $isFirstEvent = $false
                                        $eventCount++
                                    }
                                }
                                # Capture next page URL before clearing response
                                $continuationPath = if (-not [string]::IsNullOrWhiteSpace([string]$response.Prev)) {
                                    [string]$response.Prev
                                } else {
                                    $null
                                }
                                if ($continuationPath) {
                                    if ($continuationPath -match '^https?://') {
                                        $nextUri = $continuationPath
                                    } elseif ($continuationPath.StartsWith('/')) {
                                        $nextUri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience$continuationPath"
                                    } else {
                                        $nextUri = "$baseUrl/apiproxy/mtp/mdeTimelineExperience/$continuationPath"
                                    }
                                }
                                # Clear response to free memory immediately
                                $response = $null
                                if ($pageProcessingStopwatch) {
                                    $pageProcessingStopwatch.Stop()
                                    $pageProcessingSeconds += $pageProcessingStopwatch.Elapsed.TotalSeconds
                                    if ($pageProcessingStopwatch.Elapsed.TotalSeconds -gt $pageProcessingSecondsMax) {
                                        $pageProcessingSecondsMax = $pageProcessingStopwatch.Elapsed.TotalSeconds
                                    }
                                }
                            }

                            if (-not $nextUri) {
                                break
                            } else {
                                $Uri = $nextUri
                                $paginationDelayMilliseconds = if ($baseParams.PaginationDelayMaxMilliseconds -le $baseParams.PaginationDelayMinMilliseconds) {
                                    [int]$baseParams.PaginationDelayMinMilliseconds
                                } else {
                                    Get-Random -Minimum $baseParams.PaginationDelayMinMilliseconds -Maximum ($baseParams.PaginationDelayMaxMilliseconds + 1)
                                }
                                if ($baseParams.CollectDiagnostics -and $paginationDelayMilliseconds -gt 0) {
                                    $interPageDelaySeconds += ($paginationDelayMilliseconds / 1000)
                                }
                                if ($paginationDelayMilliseconds -gt 0) {
                                    Start-Sleep -Milliseconds $paginationDelayMilliseconds
                                }
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
                            RetryCount     = $retryCount
                            ThrottleRetryCount = $throttleRetryCount
                            BackoffSeconds = [math]::Round($backoffSeconds, 2)
                            InterPageDelaySeconds = [math]::Round($interPageDelaySeconds, 2)
                            RequestSeconds = [math]::Round($requestSeconds, 2)
                            RequestSecondsMax = [math]::Round($requestSecondsMax, 2)
                            PageProcessingSeconds = [math]::Round($pageProcessingSeconds, 2)
                            PageProcessingSecondsMax = [math]::Round($pageProcessingSecondsMax, 2)
                            ItemsPerPageAverage = if ($pagesRetrieved -gt 0) { [math]::Round($itemsPerPageTotal / $pagesRetrieved, 2) } else { 0 }
                            ItemsPerPageMin = if ($null -ne $itemsPerPageMin) { [int]$itemsPerPageMin } else { 0 }
                            ItemsPerPageMax = [int]$itemsPerPageMax
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
                            RetryCount     = if ($null -ne $retryCount) { $retryCount } else { 0 }
                            ThrottleRetryCount = if ($null -ne $throttleRetryCount) { $throttleRetryCount } else { 0 }
                            BackoffSeconds = if ($null -ne $backoffSeconds) { [math]::Round($backoffSeconds, 2) } else { 0 }
                            InterPageDelaySeconds = if ($null -ne $interPageDelaySeconds) { [math]::Round($interPageDelaySeconds, 2) } else { 0 }
                            RequestSeconds = if ($null -ne $requestSeconds) { [math]::Round($requestSeconds, 2) } else { 0 }
                            RequestSecondsMax = if ($null -ne $requestSecondsMax) { [math]::Round($requestSecondsMax, 2) } else { 0 }
                            PageProcessingSeconds = if ($null -ne $pageProcessingSeconds) { [math]::Round($pageProcessingSeconds, 2) } else { 0 }
                            PageProcessingSecondsMax = if ($null -ne $pageProcessingSecondsMax) { [math]::Round($pageProcessingSecondsMax, 2) } else { 0 }
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
            $downloadWallClockSeconds = [math]::Round($operationStartTime.Elapsed.TotalSeconds, 2)

            # Check for timeout in PS7
            if ($PSVersionTable.PSVersion.Major -ge 7 -and $operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                Write-Warning "Operation took longer than expected timeout of $TimeoutSeconds seconds."
            }

            # Check for failures
            $failures = @($results | Where-Object { -not $_.Success })
            if ($failures.Count -gt 0 -and -not $AllowPartial) {
                $failureDetails = $failures | Sort-Object ChunkIndex | ForEach-Object {
                    "chunk $($_.ChunkIndex): $($_.Error)"
                }
                throw "Failed to retrieve endpoint device timeline chunks: $($failureDetails -join '; '). Re-run with -AllowPartial to return completed chunks."
            } elseif ($failures.Count -gt 0) {
                $failureDetails = $failures | Sort-Object ChunkIndex | ForEach-Object {
                    "chunk $($_.ChunkIndex): $($_.Error)"
                }
                Write-Warning "Returning partial endpoint device timeline data; failed chunks: $($failureDetails -join '; ')"
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
            $mergeStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            $jsonFiles = @(
                $results |
                    Where-Object { $_.Success -and $_.FilePath -and (Test-Path -LiteralPath $_.FilePath) } |
                    ForEach-Object { Get-Item -LiteralPath $_.FilePath } |
                    Sort-Object Name
            )
            if ($jsonFiles.Count -eq 0) {
                $jsonFiles = @(Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue | Sort-Object Name)
            }

            if ($jsonFiles.Count -lt $dateChunks.Count) {
                $missingChunkCount = $dateChunks.Count - $jsonFiles.Count
                if (-not $AllowPartial) {
                    throw "Only $($jsonFiles.Count) of $($dateChunks.Count) chunk files completed. Re-run with -AllowPartial to return completed chunks."
                }

                Write-Warning "Returning partial endpoint device timeline data; $missingChunkCount chunk file(s) were missing from the final merge."
            }

            # If OutputPath is specified, use streaming export without fragile raw string slicing
            if ($OutputPath) {
                Write-Verbose "Exporting to file using structural streaming merge..."
                $exportDir = Split-Path -Parent $OutputPath
                if ($exportDir -and -not (Test-Path $exportDir)) {
                    New-Item -Path $exportDir -ItemType Directory -Force | Out-Null
                }

                $resultByPath = @{}
                foreach ($resultItem in ($results | Where-Object { $_.FilePath })) {
                    $resultByPath[[string]$resultItem.FilePath] = [int]$resultItem.EventCount
                }

                $exportWriter = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)
                $exportedEvents = 0
                try {
                    $useRawJsonExport = $ExportFormat -eq 'Json' -and [string]::IsNullOrWhiteSpace($EventType)
                    $usedRawJsonExport = $useRawJsonExport
                    if ($ExportFormat -eq 'Json') {
                        $exportWriter.Write('[')
                    }
                    $isFirstEvent = $true
                    $fileIndex = 0
                    $totalFiles = $jsonFiles.Count

                    foreach ($file in ($jsonFiles | Sort-Object Name -Descending)) {
                        $fileIndex++
                        $percentComplete = [math]::Round(($fileIndex / [math]::Max(1, $totalFiles)) * 100)
                        Write-Progress -Activity "Processing Results" -Status "Merging file $fileIndex of $totalFiles to export" -PercentComplete $percentComplete -Id 2

                        if ($useRawJsonExport) {
                            $eventsJson = Get-XdrEndpointTimelineChunkEventsJson -File $file -AllowPartial:$AllowPartial
                            if ($null -eq $eventsJson) {
                                continue
                            }

                            if ($eventsJson.Length -gt 0) {
                                if (-not $isFirstEvent) { $exportWriter.Write(',') }
                                $exportWriter.Write($eventsJson)
                                $isFirstEvent = $false
                            }

                            if ($resultByPath.ContainsKey($file.FullName)) {
                                $exportedEvents += $resultByPath[$file.FullName]
                            }
                            continue
                        }

                        $chunkData = Read-XdrEndpointTimelineChunkFile -File $file -AllowPartial:$AllowPartial
                        if ($null -eq $chunkData) {
                            continue
                        }

                        $chunkEvents = Get-XdrEndpointTimelineChunkEvent -ChunkData $chunkData -EventType $EventType
                        $orderedChunkEvents = Get-XdrEndpointTimelineSortedEvent -Events @($chunkEvents)
                        foreach ($eventItem in $orderedChunkEvents) {
                            if ($ExportFormat -eq 'Ndjson') {
                                $exportWriter.WriteLine(($eventItem | ConvertTo-Json -Depth 20 -Compress))
                            } else {
                                if (-not $isFirstEvent) { $exportWriter.Write(',') }
                                $exportWriter.Write(($eventItem | ConvertTo-Json -Depth 20 -Compress))
                                $isFirstEvent = $false
                            }
                            $exportedEvents++
                        }
                    }
                    if ($ExportFormat -eq 'Json') {
                        $exportWriter.Write(']')
                    }
                } finally {
                    $exportWriter.Close()
                    $exportWriter.Dispose()
                }
                Write-Progress -Activity "Processing Results" -Completed -Id 2
                $mergeStopwatch.Stop()
                $mergePhaseSeconds = [math]::Round($mergeStopwatch.Elapsed.TotalSeconds, 4)
                $exportPhaseSeconds = $mergePhaseSeconds
                Write-Information "Exported $exportedEvents events to: $OutputPath" -InformationAction Continue

                [System.GC]::Collect()

                # Return summary info instead of all events when exporting
                $resultSummary = [PSCustomObject]@{
                    ExportPath       = $OutputPath
                    ExportFormat     = $ExportFormat
                    TotalEvents      = $exportedEvents
                    TotalChunks      = $dateChunks.Count
                    FailedChunks     = $failures.Count
                    TotalSizeMB      = [math]::Round($totalSizeKB / 1024, 2)
                    WallClockSeconds = [math]::Round($wallClockSeconds, 2)
                    EffectiveRate    = $overallEventsPerSec
                    DiagnosticsPath  = $DiagnosticsPath
                }
                $runCompleted = $true
                return $resultSummary
            }

            # For in-memory return, load events but with aggressive memory management
            $allEvents = [System.Collections.Generic.List[object]]::new([math]::Max(10000, $totalEvents))

            $fileIndex = 0
            $totalFiles = $jsonFiles.Count
            foreach ($file in $jsonFiles) {
                $fileIndex++
                $percentComplete = [math]::Round(($fileIndex / [math]::Max(1, $totalFiles)) * 100)
                Write-Progress -Activity "Processing Results" -Status "Merging file $fileIndex of $totalFiles" -PercentComplete $percentComplete -Id 2

                $chunkData = Read-XdrEndpointTimelineChunkFile -File $file -AllowPartial:$AllowPartial
                if ($null -eq $chunkData) {
                    continue
                }

                $chunkEvents = @((Get-XdrEndpointTimelineChunkEvent -ChunkData $chunkData -EventType $EventType))
                if ($chunkEvents.Count -gt 0) {
                    $allEvents.AddRange($chunkEvents)
                }
                $chunkData = $null  # Free parsed object memory

                # Force garbage collection every 100 files to prevent memory buildup
                if ($fileIndex % 100 -eq 0) {
                    [System.GC]::Collect()
                    [System.GC]::WaitForPendingFinalizers()
                }
            }
            $mergeStopwatch.Stop()
            $mergePhaseSeconds = [math]::Round($mergeStopwatch.Elapsed.TotalSeconds, 4)
            Write-Progress -Activity "Processing Results" -Completed -Id 2

            Write-Verbose "Total events retrieved: $($allEvents.Count)"

            # Sort events in-place by timestamp (if available) to avoid creating a copy
            if ($allEvents.Count -gt 0) {
                Write-Verbose "Sorting $($allEvents.Count) events by timestamp..."
                $sortStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $orderedEvents = @((Get-XdrEndpointTimelineSortedEvent -Events $allEvents.ToArray()))
                $sortStopwatch.Stop()
                $sortPhaseSeconds = [math]::Round($sortStopwatch.Elapsed.TotalSeconds, 4)
                $allEvents.Clear()
                $allEvents.AddRange($orderedEvents)
            }

            # Return results and clean up
            $result = $allEvents.ToArray()
            $returnedEventsCount = @($result).Count
            $allEvents.Clear()
            $allEvents = $null
            [System.GC]::Collect()

            $runCompleted = $true
            return $result
        } catch {
            $capturedError = $_.ToString()
            Write-Progress -Activity "Retrieving Device Timeline" -Completed -Id 1
            Write-Progress -Activity "Processing Results" -Completed -Id 2
            throw "Failed to retrieve endpoint device timeline: $_"
        } finally {
            $cleanupStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            if (-not $KeepTempFiles -and (Test-Path $runTempPath)) {
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            } elseif ($KeepTempFiles) {
                Write-Information "Temporary device timeline files preserved in: $runTempPath" -InformationAction Continue
            }
            $cleanupStopwatch.Stop()
            $cleanupSeconds = [math]::Round($cleanupStopwatch.Elapsed.TotalSeconds, 4)

            if ($PSBoundParameters.ContainsKey('DiagnosticsPath')) {
                $diagnostics = [ordered]@{
                    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                    Command        = 'Get-XdrEndpointDeviceTimeline'
                    Status         = if ($capturedError) { 'Failed' } elseif ($runCompleted) { 'Succeeded' } else { 'Incomplete' }
                    Error          = $capturedError
                    Device         = [ordered]@{
                        ParameterSetName = $PSCmdlet.ParameterSetName
                        DeviceId         = $deviceIdentifier
                        MachineDnsName   = if ($PSBoundParameters.ContainsKey('MachineDnsName')) { $MachineDnsName } else { $computerDnsName }
                    }
                    Request        = [ordered]@{
                        FromDate              = $FromDate.ToUniversalTime().ToString('o')
                        ToDate                = $ToDate.ToUniversalTime().ToString('o')
                        TotalHours            = [math]::Round($totalHours, 2)
                        ChunkHours            = $ChunkHours
                        ChunkStrategy         = $chunkStrategy
                        TotalChunksPlanned    = $dateChunks.Count
                        PageSize              = $PageSize
                        ThrottleLimit         = $ThrottleLimit
                        TimeoutSeconds        = $TimeoutSeconds
                        MaxRetries            = $MaxRetries
                        RetryDelaySeconds     = $RetryDelaySeconds
                        RequestTimeoutSeconds = $RequestTimeoutSeconds
                        PaginationDelayMinMilliseconds = $PaginationDelayMinMilliseconds
                        PaginationDelayMaxMilliseconds = $PaginationDelayMaxMilliseconds
                        AllowPartial          = [bool]$AllowPartial
                        ReturnMode            = $returnMode
                        ExportFormat          = $ExportFormat
                        UsedRawJsonExport     = $usedRawJsonExport
                    }
                    Phases         = [ordered]@{
                        DeviceLookupSeconds     = $deviceLookupSeconds
                        ChunkPlanningSeconds    = $chunkPlanningSeconds
                        DownloadWallClockSeconds = $downloadWallClockSeconds
                        MergePhaseSeconds       = $mergePhaseSeconds
                        SortPhaseSeconds        = $sortPhaseSeconds
                        ExportPhaseSeconds      = $exportPhaseSeconds
                        CleanupSeconds          = $cleanupSeconds
                    }
                    Totals         = [ordered]@{
                        ReturnedEvents            = if ($OutputPath) { $exportedEvents } else { $returnedEventsCount }
                        DownloadedEvents          = $totalEvents
                        SuccessfulChunkCount      = @($results | Where-Object { $_.Success }).Count
                        FailedChunkCount          = @($results | Where-Object { -not $_.Success }).Count
                        MergedChunkFileCount      = @($jsonFiles).Count
                        TotalSizeMB               = [math]::Round($totalSizeKB / 1024, 2)
                        DownloadWallClockSeconds  = [math]::Round($wallClockSeconds, 2)
                        EffectiveRate             = $overallEventsPerSec
                        TotalRetryCount           = [int](@($results | Measure-Object -Property RetryCount -Sum).Sum)
                        TotalThrottleRetryCount   = [int](@($results | Measure-Object -Property ThrottleRetryCount -Sum).Sum)
                        TotalBackoffSeconds       = [math]::Round([double](@($results | Measure-Object -Property BackoffSeconds -Sum).Sum), 2)
                        TotalInterPageDelaySeconds = [math]::Round([double](@($results | Measure-Object -Property InterPageDelaySeconds -Sum).Sum), 2)
                        TotalRequestSeconds       = [math]::Round([double](@($results | Measure-Object -Property RequestSeconds -Sum).Sum), 2)
                        TotalPageProcessingSeconds = [math]::Round([double](@($results | Measure-Object -Property PageProcessingSeconds -Sum).Sum), 2)
                    }
                    Chunks         = @(
                        $results |
                            Sort-Object ChunkIndex |
                            ForEach-Object {
                                [ordered]@{
                                    ChunkIndex               = $_.ChunkIndex
                                    FromDate                 = if ($_.FromDate) { ([datetime]$_.FromDate).ToUniversalTime().ToString('o') } else { $null }
                                    ToDate                   = if ($_.ToDate) { ([datetime]$_.ToDate).ToUniversalTime().ToString('o') } else { $null }
                                    Success                  = [bool]$_.Success
                                    EventCount               = [int]($_.EventCount)
                                    PagesRetrieved           = [int]($_.PagesRetrieved)
                                    FileSizeKB               = [double]($_.FileSizeKB)
                                    ElapsedSeconds           = [double]($_.ElapsedSeconds)
                                    RetryCount               = [int]($_.RetryCount)
                                    ThrottleRetryCount       = [int]($_.ThrottleRetryCount)
                                    BackoffSeconds           = [double]($_.BackoffSeconds)
                                    InterPageDelaySeconds    = [double]($_.InterPageDelaySeconds)
                                    RequestSeconds           = [double]($_.RequestSeconds)
                                    RequestSecondsMax        = [double]($_.RequestSecondsMax)
                                    PageProcessingSeconds    = [double]($_.PageProcessingSeconds)
                                    PageProcessingSecondsMax = [double]($_.PageProcessingSecondsMax)
                                    ItemsPerPageAverage      = [double]($_.ItemsPerPageAverage)
                                    ItemsPerPageMin          = [int]($_.ItemsPerPageMin)
                                    ItemsPerPageMax          = [int]($_.ItemsPerPageMax)
                                    Error                    = $_.Error
                                }
                            }
                    )
                }

                try {
                    Write-XdrEndpointTimelineDiagnosticFile -Path $DiagnosticsPath -Diagnostics $diagnostics
                    Write-Verbose "Wrote endpoint timeline diagnostics to: $DiagnosticsPath"
                } catch {
                    Write-Warning "Failed to write endpoint timeline diagnostics to '$DiagnosticsPath': $($_.Exception.Message)"
                }
            }
        }
    }

    end {
    }
}
