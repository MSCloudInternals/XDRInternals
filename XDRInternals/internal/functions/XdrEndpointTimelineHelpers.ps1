function Get-XdrEndpointTimelineContinuationPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Response,

        [Parameter()]
        [ValidateSet('Forward', 'Backward')]
        [string]$Direction = 'Forward'
    )

    $propertyOrder = if ($Direction -eq 'Backward') { @('Prev', 'Next') } else { @('Next', 'Prev') }
    foreach ($propertyName in $propertyOrder) {
        if (-not $Response.PSObject.Properties[$propertyName]) { continue }
        $value = [string]$Response.$propertyName
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
        [object]$Response,

        [Parameter()]
        [ValidateSet('Forward', 'Backward')]
        [string]$Direction = 'Forward'
    )

    $continuationPath = Get-XdrEndpointTimelineContinuationPath -Response $Response -Direction $Direction
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

    return @(
        foreach ($eventItem in $events) {
            if (Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent $eventItem -EventType $EventType) {
                $eventItem
            }
        }
    )
}

function Resolve-XdrEndpointTimelineOutputTarget {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [string]$ExportPath,

        [Parameter()]
        [string]$WorkingDirectory
    )

    $exportFile = $null
    $workingRoot = $WorkingDirectory

    if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
        $exportFile = $ExportPath
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $extension = [System.IO.Path]::GetExtension($OutputPath)
        $looksLikeFile = $extension -match '^\.(json|jsonl|ndjson)$'
        if ($looksLikeFile) {
            if ($exportFile -and $exportFile -ne $OutputPath) {
                throw 'OutputPath and ExportPath cannot both specify different export files.'
            }
            $exportFile = $OutputPath
        }
        elseif (-not $workingRoot) {
            $workingRoot = $OutputPath
        }
        else {
            Write-Warning 'OutputPath was supplied but WorkingDirectory already controls temporary files; ignoring OutputPath as a working directory.'
        }
    }

    if ([string]::IsNullOrWhiteSpace($workingRoot)) {
        $workingRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'XdrTimeline'
    }

    [PSCustomObject]@{
        ExportPath       = $exportFile
        WorkingDirectory = $workingRoot
    }
}

function New-XdrEndpointTimelineChunkWorkerScript {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory worker scriptblock and does not mutate state')]
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()

    return {
        param($Chunk, $SharedParameters)

        function Invoke-EndpointTimelineRequest {
            param(
                [string]$Uri,
                [string]$Method = 'GET',
                [hashtable]$Headers,
                $WebSession,
                [int]$MaxRetries,
                [int]$RetryDelaySeconds,
                [int]$TimeoutSeconds
            )

            $attempt = 0
            while ($attempt -lt $MaxRetries) {
                $attempt++
                try {
                    $parsedResponse = Invoke-RestMethod -Uri $Uri -Method $Method -ContentType 'application/json' -WebSession $WebSession -Headers $Headers -TimeoutSec $TimeoutSeconds -ErrorAction Stop
                    if ($parsedResponse -is [string]) {
                        if ($parsedResponse -match '(?is)<html|ConvergedSignIn|Sign in to your account|login\.microsoftonline\.com') {
                            throw 'Endpoint timeline request returned an interactive sign-in page.'
                        }
                        try {
                            $parsedResponse = $parsedResponse | ConvertFrom-Json -Depth 100 -ErrorAction Stop
                        }
                        catch {
                            throw "Endpoint timeline request returned non-JSON content: $($_.Exception.Message)"
                        }
                    }
                    return [PSCustomObject]@{
                        Parsed     = $parsedResponse
                        StatusCode = 200
                    }
                }
                catch {
                    $statusCode = $null
                    if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
                    if ($_.Exception.Message -match 'status\s+(\d{3})') { $statusCode = [int]$Matches[1] }
                    $failureClass = Get-EndpointTimelineFailureClass -ErrorRecord $_ -StatusCode $statusCode
                    $retryable = $failureClass -in @('RateLimited', 'Transient', 'Timeout')
                    if (-not $retryable -or $attempt -ge $MaxRetries) {
                        throw
                    }

                    $delay = [math]::Min(30, [int]($RetryDelaySeconds * [math]::Pow(2, $attempt - 1)) + (Get-Random -Minimum 0 -Maximum 3))
                    if ($delay -gt 0) { Start-Sleep -Seconds $delay }
                }
            }
        }

        function Get-EndpointTimelineFailureClass {
            param($ErrorRecord, [Nullable[int]]$StatusCode, [string]$Message)

            if ($ErrorRecord) {
                if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Response) {
                    try { $StatusCode = [int]$ErrorRecord.Exception.Response.StatusCode } catch { Write-Verbose "Could not read endpoint timeline HTTP status: $($_.Exception.Message)" }
                }
                if ([string]::IsNullOrWhiteSpace($Message)) { $Message = $ErrorRecord.ToString() }
            }

            $text = [string]$Message
            if ($text -match '(?i)(interactive sign.?in|sign in to your account|ConvergedSignIn|login\.microsoftonline\.com)') { return 'AuthExpired' }
            if ($StatusCode -in @(401, 419, 440)) { return 'AuthExpired' }
            if ($StatusCode -eq 403) {
                if ($text -match '(?i)(xsrf|csrf|session|token|expired|sign.?in|login)') { return 'AuthExpired' }
                return 'Authz'
            }
            if ($StatusCode -eq 429) { return 'RateLimited' }
            if ($StatusCode -ge 500 -and $StatusCode -lt 600) { return 'Transient' }
            if ($text -match '(?i)(exceeded MaxPagesPerChunk|duplicate continuation URI|no-progress|DensePageThreshold|EarlyDensityThreshold)') { return 'Fatal' }
            if ($text -match '(?i)(timeout|timed out|operation has timed out|task was canceled)') { return 'Timeout' }
            if ($text -match '(?i)(disk|space|quota|path too long|access.*path)') { return 'Disk' }
            if ($null -eq $StatusCode -and -not [string]::IsNullOrWhiteSpace($text)) { return 'Transient' }
            return 'Fatal'
        }

        function Get-EndpointTimelineContinuationPath {
            param($Response)

            foreach ($propertyName in @('Next', 'Prev')) {
                if (-not $Response.PSObject.Properties[$propertyName]) { continue }
                $value = [string]$Response.$propertyName
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    return $value
                }
            }

            return $null
        }

        function Get-EndpointTimelineNextUri {
            param([string]$BaseUrl, $Response)

            $continuationPath = Get-EndpointTimelineContinuationPath -Response $Response
            if ([string]::IsNullOrWhiteSpace($continuationPath)) { return $null }
            if ($continuationPath -match '^https?://') { return $continuationPath }
            if ($continuationPath.StartsWith('/')) { return "$BaseUrl/apiproxy/mtp/mdeTimelineExperience$continuationPath" }
            return "$BaseUrl/apiproxy/mtp/mdeTimelineExperience/$continuationPath"
        }

        function Get-EndpointTimelineQueryDateTime {
            param([string]$Uri, [string]$Name)

            if ([string]::IsNullOrWhiteSpace($Uri)) { return $null }
            try {
                $query = ([uri]$Uri).Query
                if ([string]::IsNullOrWhiteSpace($query)) { return $null }
                foreach ($part in $query.TrimStart('?').Split('&')) {
                    $pair = $part.Split('=', 2)
                    if ($pair.Count -ne 2 -or $pair[0] -ne $Name) { continue }
                    $value = [System.Uri]::UnescapeDataString($pair[1])
                    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
                    return ([datetime]$value).ToUniversalTime()
                }
            }
            catch {
                return $null
            }

            return $null
        }

        function Get-EndpointTimelineHash {
            param([string]$Value)

            if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                return [System.BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))).Replace('-', '')
            }
            finally {
                $sha256.Dispose()
            }
        }

        function Get-EndpointTimelineLinkShape {
            param([string]$Value)

            if ([string]::IsNullOrWhiteSpace($Value)) { return 'None' }
            if ($Value -match '^https?://') { return 'Absolute' }
            if ($Value.StartsWith('/')) { return 'RelativeRooted' }
            return 'Relative'
        }

        function Get-EndpointTimelineEventTimestamp {
            param($TimelineEvent)

            $timestamp = Get-EndpointTimelineEventDateTime -TimelineEvent $TimelineEvent
            if ($null -ne $timestamp) { return $timestamp.ToString('o') }

            return $null
        }

        function Get-EndpointTimelineEventDateTime {
            param($TimelineEvent)

            foreach ($propertyName in @('Timestamp', 'timestamp', 'EventTime', 'eventTime', 'ActionTimeIsoString', 'TimeGenerated', 'date')) {
                if (-not $TimelineEvent.PSObject.Properties[$propertyName]) { continue }
                $value = $TimelineEvent.$propertyName
                if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { continue }
                try { return ([datetime]$value).ToUniversalTime() } catch { continue }
            }

            return $null
        }

        function Get-EndpointTimelineStableEventKey {
            param($TimelineEvent, [string]$SerializedEvent)

            foreach ($propertyName in @('Id', 'id', '_id', 'EventId', 'eventId', 'ReportId', 'recordId')) {
                if ($TimelineEvent.PSObject.Properties[$propertyName] -and -not [string]::IsNullOrWhiteSpace([string]$TimelineEvent.$propertyName)) {
                    return [string]$TimelineEvent.$propertyName
                }
            }

            return Get-EndpointTimelineHash -Value $SerializedEvent
        }

        function Get-EndpointTimelineItemJson {
            param($Items)

            $rawItems = [System.Collections.Generic.List[string]]::new()
            if ($null -eq $Items) {
                return @()
            }

            foreach ($item in @($Items)) {
                if ($null -eq $item) { continue }
                [void]$rawItems.Add(($item | ConvertTo-Json -Depth 100 -Compress))
            }
            return $rawItems.ToArray()
        }

        function Get-EndpointTimelineResponseItem {
            param($Response)

            foreach ($propertyName in @('Items', 'items', 'Events', 'events', 'Data', 'data', 'Results', 'results')) {
                if ($Response -and $Response.PSObject.Properties[$propertyName]) {
                    return @($Response.$propertyName)
                }
            }

            return @()
        }

        function Test-EndpointTimelineEarlyDensityStop {
            param(
                [object[]]$Pages,
                [int]$PageSize,
                [int]$SamplePages,
                [double]$MaxSpanSeconds,
                [datetime]$OwnerFromDate,
                [datetime]$OwnerToDate
            )

            if ($SamplePages -lt 2 -or $MaxSpanSeconds -le 0 -or @($Pages).Count -lt $SamplePages) {
                return [pscustomobject]@{ ShouldStop = $false; SpanSeconds = $null }
            }

            $allPages = @($Pages)
            for ($startIndex = 0; $startIndex -le ($allPages.Count - $SamplePages); $startIndex++) {
                $sample = @($allPages[$startIndex..($startIndex + $SamplePages - 1)])
                $isFullContinuingWindow = $true
                foreach ($page in $sample) {
                    if (-not $page.HasNext -or [int]$page.RawItemCount -lt $PageSize) {
                        $isFullContinuingWindow = $false
                        break
                    }
                }
                if (-not $isFullContinuingWindow) { continue }

                $timestamps = [System.Collections.Generic.List[datetime]]::new()
                $hasUsableTimestampWindow = $true
                foreach ($page in $sample) {
                    foreach ($propertyName in @('FirstEventTimestamp', 'LastEventTimestamp')) {
                        $value = if ($page.PSObject.Properties[$propertyName]) { $page.$propertyName } else { $null }
                        if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
                        try {
                            $timestamp = ([datetimeoffset]::Parse(
                                [string]$value,
                                [System.Globalization.CultureInfo]::InvariantCulture,
                                [System.Globalization.DateTimeStyles]::AssumeUniversal
                            )).UtcDateTime
                        }
                        catch {
                            $hasUsableTimestampWindow = $false
                            break
                        }

                        if ($timestamp -lt $OwnerFromDate -or $timestamp -gt $OwnerToDate) {
                            $hasUsableTimestampWindow = $false
                            break
                        }

                        $timestamps.Add($timestamp)
                    }
                    if (-not $hasUsableTimestampWindow) { break }
                }
                if (-not $hasUsableTimestampWindow -or $timestamps.Count -lt 2) { continue }

                $minTimestamp = $timestamps | Sort-Object | Select-Object -First 1
                $maxTimestamp = $timestamps | Sort-Object | Select-Object -Last 1
                $spanSeconds = [math]::Round(($maxTimestamp - $minTimestamp).TotalSeconds, 3)
                if ($spanSeconds -le $MaxSpanSeconds) {
                    return [pscustomobject]@{
                        ShouldStop = $true
                        SpanSeconds = $spanSeconds
                    }
                }
            }

            return [pscustomobject]@{ ShouldStop = $false; SpanSeconds = $null }
        }

        $chunkFromDate = ([datetime]$Chunk.FromDate).ToUniversalTime()
        $chunkToDate = ([datetime]$Chunk.ToDate).ToUniversalTime()
        $ownerFromDate = if ($Chunk.PSObject.Properties['OwnerFromDate']) { ([datetime]$Chunk.OwnerFromDate).ToUniversalTime() } else { $chunkFromDate }
        $ownerToDate = if ($Chunk.PSObject.Properties['OwnerToDate']) { ([datetime]$Chunk.OwnerToDate).ToUniversalTime() } else { $chunkToDate }
        $adaptiveMinimumChunkMinutes = if ($SharedParameters.AdaptiveMinimumChunkMinutes) { [double]$SharedParameters.AdaptiveMinimumChunkMinutes } else { 0 }
        $isMinimumAdaptiveChunk = ($adaptiveMinimumChunkMinutes -gt 0 -and (($ownerToDate - $ownerFromDate).TotalMinutes -le ($adaptiveMinimumChunkMinutes + 0.001)))
        $chunkIndex = [int]$Chunk.Index
        $chunkTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $writer = $null

        $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        foreach ($cookieInfo in @($SharedParameters.CookieData)) {
            $webSession.Cookies.Add([System.Net.Cookie]::new($cookieInfo.Name, $cookieInfo.Value, $cookieInfo.Path, $cookieInfo.Domain))
        }

        $headers = @{}
        foreach ($key in $SharedParameters.HeadersData.Keys) {
            $headers[$key] = $SharedParameters.HeadersData[$key]
        }

        $fileName = 'chunk_{0:D4}_{1:yyyyMMdd_HHmmss}_{2:yyyyMMdd_HHmmss}.json' -f $chunkIndex, $chunkFromDate, $chunkToDate
        $filePath = Join-Path $SharedParameters.TempPath $fileName

        $eventCount = 0
        $pagesRetrieved = 0
        $retryCount = 0
        $nextCount = 0
        $prevCount = 0
        $continuationLoopCount = 0
        $initialUriHash = $null
        $initialUriShape = $null
        $missingTimestampCount = 0
        $chunkFirstTimestamp = $null
        $chunkLastTimestamp = $null
        $seenUris = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $seenEventKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $pageDiagnostics = [System.Collections.Generic.List[object]]::new()

        try {
            $queryParams = [System.Collections.Generic.List[string]]::new()
            [void]$queryParams.Add("generateIdentityEvents=$($SharedParameters.GenerateIdentityEvents.ToString().ToLowerInvariant())")
            [void]$queryParams.Add("includeIdentityEvents=$($SharedParameters.IncludeIdentityEvents.ToString().ToLowerInvariant())")
            [void]$queryParams.Add("supportMdiOnlyEvents=$($SharedParameters.SupportMdiOnlyEvents.ToString().ToLowerInvariant())")
            [void]$queryParams.Add("fromDate=$([System.Uri]::EscapeDataString($chunkFromDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))")
            [void]$queryParams.Add("toDate=$([System.Uri]::EscapeDataString($chunkToDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))")
            [void]$queryParams.Add("correlationId=$([guid]::NewGuid().ToString())")
            [void]$queryParams.Add("doNotUseCache=$($SharedParameters.DoNotUseCache.ToString().ToLowerInvariant())")
            [void]$queryParams.Add("forceUseCache=$($SharedParameters.ForceUseCache.ToString().ToLowerInvariant())")
            [void]$queryParams.Add("pageSize=$($SharedParameters.PageSize)")
            [void]$queryParams.Add("includeSentinelEvents=$($SharedParameters.IncludeSentinelEvents.ToString().ToLowerInvariant())")
            [void]$queryParams.Add('IsScrollingForward=true')

            if ($SharedParameters.MachineDnsName) {
                $queryParams.Insert(0, "machineDnsName=$([System.Uri]::EscapeDataString([string]$SharedParameters.MachineDnsName))")
            }
            if ($SharedParameters.SenseClientVersion) {
                $queryParams.Insert(0, "SenseClientVersion=$([System.Uri]::EscapeDataString([string]$SharedParameters.SenseClientVersion))")
            }
            if ($SharedParameters.MarkedEventsOnly) {
                $queryParams.Insert(0, 'markedEventsOnly=true')
            }
            foreach ($value in @($SharedParameters.EventsGroups)) {
                if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
                [void]$queryParams.Add("eventsGroups=$([System.Uri]::EscapeDataString([string]$value))")
            }
            foreach ($value in @($SharedParameters.DataTypes)) {
                if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
                [void]$queryParams.Add("dataTypes=$([System.Uri]::EscapeDataString([string]$value))")
            }
            foreach ($value in @($SharedParameters.SourceProviders)) {
                if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
                [void]$queryParams.Add("sourceProviders=$([System.Uri]::EscapeDataString([string]$value))")
            }

            $uri = "$($SharedParameters.BaseUrl)/apiproxy/mtp/mdeTimelineExperience/machines/$($SharedParameters.DeviceId)/events/?$($queryParams -join '&')"
            $initialUriHash = Get-EndpointTimelineHash -Value $uri
            $initialUriShape = 'EndpointDeviceTimelineInitialRequest'
            $writer = [System.IO.StreamWriter]::new($filePath, $false, [System.Text.Encoding]::UTF8)
            $writer.Write('{"ChunkIndex":' + $chunkIndex + ',"FromDate":"' + $ownerFromDate.ToString('o') + '","ToDate":"' + $ownerToDate.ToString('o') + '","RequestFromDate":"' + $chunkFromDate.ToString('o') + '","RequestToDate":"' + $chunkToDate.ToString('o') + '","Events":[')
            $writer.Flush()
            $isFirstEvent = $true

            while ($uri) {
                if (-not $seenUris.Add($uri)) {
                    throw "Chunk $chunkIndex reached a duplicate continuation URI after $pagesRetrieved page(s)."
                }
                if ($pagesRetrieved -ge $SharedParameters.MaxPagesPerChunk) {
                    throw "Chunk $chunkIndex exceeded MaxPagesPerChunk=$($SharedParameters.MaxPagesPerChunk)."
                }
                if (-not $isMinimumAdaptiveChunk -and $SharedParameters.DensePageThreshold -gt 0 -and $pagesRetrieved -ge $SharedParameters.DensePageThreshold) {
                    throw "Chunk $chunkIndex reached DensePageThreshold=$($SharedParameters.DensePageThreshold)."
                }

                $pageIndex = $pagesRetrieved
                $pageTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $timelineResponse = Invoke-EndpointTimelineRequest -Uri $uri -Headers $headers -WebSession $webSession -MaxRetries $SharedParameters.MaxRetries -RetryDelaySeconds $SharedParameters.RetryDelaySeconds -TimeoutSeconds $SharedParameters.RequestTimeoutSeconds
                $response = $timelineResponse.Parsed
                $pageTimer.Stop()
                $pagesRetrieved++

                $pageItemCount = 0
                $pageRawItemCount = 0
                $pageEventBytes = 0
                $pageDuplicateCount = 0
                $pageFilteredOutOfChunkCount = 0
                $pageReachedChunkEnd = $false
                $firstEventTimestamp = $null
                $lastEventTimestamp = $null
                $responseItems = @(Get-EndpointTimelineResponseItem -Response $response)
                foreach ($serializedEvent in @(Get-EndpointTimelineItemJson -Items $responseItems)) {
                    $pageRawItemCount++
                    $item = $serializedEvent | ConvertFrom-Json -Depth 100
                    $timestampDate = Get-EndpointTimelineEventDateTime -TimelineEvent $item
                    $timestamp = if ($null -ne $timestampDate) { $timestampDate.ToString('o') } else { $null }
                    if ($null -eq $firstEventTimestamp -and $null -ne $timestamp) { $firstEventTimestamp = $timestamp }
                    if ($null -ne $timestamp) { $lastEventTimestamp = $timestamp }
                    if ($null -eq $timestampDate) { $missingTimestampCount++ }

                    if ($null -ne $timestampDate) {
                        if ($timestampDate -ge $ownerToDate) { $pageReachedChunkEnd = $true }
                        if ($timestampDate -lt $ownerFromDate -or $timestampDate -ge $ownerToDate) {
                            $pageFilteredOutOfChunkCount++
                            continue
                        }
                    }

                    $stableKey = Get-EndpointTimelineStableEventKey -TimelineEvent $item -SerializedEvent $serializedEvent
                    if (-not $seenEventKeys.Add($stableKey)) { $pageDuplicateCount++ }
                    if (-not $isFirstEvent) { $writer.Write(',') }
                    $writer.Write($serializedEvent)
                    $isFirstEvent = $false
                    $eventCount++
                    $pageItemCount++
                    $pageEventBytes += [System.Text.Encoding]::UTF8.GetByteCount($serializedEvent)
                    if ($null -ne $timestampDate) {
                        if ($null -eq $chunkFirstTimestamp -or $timestampDate -lt $chunkFirstTimestamp) { $chunkFirstTimestamp = $timestampDate }
                        if ($null -eq $chunkLastTimestamp -or $timestampDate -gt $chunkLastTimestamp) { $chunkLastTimestamp = $timestampDate }
                    }
                }
                $writer.Flush()

                $nextValue = if ($response.PSObject.Properties['Next']) { [string]$response.Next } else { $null }
                $prevValue = if ($response.PSObject.Properties['Prev']) { [string]$response.Prev } else { $null }
                $hasNext = -not [string]::IsNullOrWhiteSpace($nextValue)
                $hasPrev = -not [string]::IsNullOrWhiteSpace($prevValue)
                if ($hasNext) { $nextCount++ }
                if ($hasPrev) { $prevCount++ }
                [void]$pageDiagnostics.Add([PSCustomObject]@{
                        ChunkIndex                = $chunkIndex
                        PageIndex                 = $pageIndex
                        ElapsedMilliseconds       = [math]::Round($pageTimer.Elapsed.TotalMilliseconds, 2)
                        RawItemCount              = $pageRawItemCount
                        ItemCount                 = $pageItemCount
                        FilteredOutOfChunkCount   = $pageFilteredOutOfChunkCount
                        ReachedChunkEnd           = $pageReachedChunkEnd
                        EventPayloadBytes         = $pageEventBytes
                        HasNext                   = $hasNext
                        HasPrev                   = $hasPrev
                        NextShape                 = Get-EndpointTimelineLinkShape -Value $nextValue
                        PrevShape                 = Get-EndpointTimelineLinkShape -Value $prevValue
                        NextHash                  = Get-EndpointTimelineHash -Value $nextValue
                        PrevHash                  = Get-EndpointTimelineHash -Value $prevValue
                        RequestUriHash            = Get-EndpointTimelineHash -Value $uri
                        FirstEventTimestamp       = $firstEventTimestamp
                        LastEventTimestamp        = $lastEventTimestamp
                        DuplicateWithinChunkCount = $pageDuplicateCount
                    })

                $earlyDensitySamplePages = if ($SharedParameters.EarlyDensitySamplePages) { [int]$SharedParameters.EarlyDensitySamplePages } else { 0 }
                $earlyDensityMaxSpanSeconds = if ($SharedParameters.EarlyDensityMaxTimestampSpanSeconds) { [double]$SharedParameters.EarlyDensityMaxTimestampSpanSeconds } else { 0 }
                $earlyDensity = Test-EndpointTimelineEarlyDensityStop -Pages $pageDiagnostics.ToArray() -PageSize ([int]$SharedParameters.PageSize) -SamplePages $earlyDensitySamplePages -MaxSpanSeconds $earlyDensityMaxSpanSeconds -OwnerFromDate $ownerFromDate -OwnerToDate $ownerToDate
                if (-not $isMinimumAdaptiveChunk -and $hasNext -and $earlyDensity.ShouldStop) {
                    throw "Chunk $chunkIndex reached EarlyDensityThreshold after $pagesRetrieved page(s); observed timestamp span $($earlyDensity.SpanSeconds)s."
                }

                $nextUri = Get-EndpointTimelineNextUri -BaseUrl $SharedParameters.BaseUrl -Response $response
                if ([string]::IsNullOrWhiteSpace($nextUri)) {
                    break
                }
                if ($pageRawItemCount -eq 0) {
                    $nextFromDate = Get-EndpointTimelineQueryDateTime -Uri $nextUri -Name 'fromDate'
                    if ($nextFromDate -and $nextFromDate -ge $chunkToDate) {
                        break
                    }
                }
                if ($pageReachedChunkEnd) {
                    break
                }

                $uri = $nextUri
                $continuationLoopCount++
                if ($SharedParameters.PaginationDelayMilliseconds -gt 0) {
                    Start-Sleep -Milliseconds $SharedParameters.PaginationDelayMilliseconds
                }
            }

            $writer.Write('],"EventCount":' + $eventCount + ',"Partial":false}')
            $writer.Close()
            $writer.Dispose()
            $writer = $null
            $fileSha256 = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash
            $keySetHash = Get-EndpointTimelineHash -Value ((@($seenEventKeys) | Sort-Object) -join "`n")

            $chunkTimer.Stop()
            [PSCustomObject]@{
                ChunkIndex            = $chunkIndex
                RequestShapeHash      = $initialUriHash
                RequestShape          = $initialUriShape
                FilePath              = $filePath
                FileSha256            = $fileSha256
                EventCount            = $eventCount
                UniqueKeyCount        = $seenEventKeys.Count
                KeySetHash            = $keySetHash
                FirstTimestamp        = if ($chunkFirstTimestamp) { $chunkFirstTimestamp.ToString('o') } else { $null }
                LastTimestamp         = if ($chunkLastTimestamp) { $chunkLastTimestamp.ToString('o') } else { $null }
                MissingTimestampCount = $missingTimestampCount
                FromDate              = $chunkFromDate
                ToDate                = $chunkToDate
                OwnerFromDate         = $ownerFromDate
                OwnerToDate           = $ownerToDate
                Success               = $true
                FailureClass          = $null
                ElapsedSeconds        = [math]::Round($chunkTimer.Elapsed.TotalSeconds, 2)
                PagesRetrieved        = $pagesRetrieved
                ContinuationPageCount = $continuationLoopCount
                NextLinkCount         = $nextCount
                PrevLinkCount         = $prevCount
                RetryCount            = $retryCount
                Pages                 = $pageDiagnostics.ToArray()
                FileSizeKB            = [math]::Round((Get-Item -LiteralPath $filePath).Length / 1KB, 2)
            }
        }
        catch {
            if ($writer) {
                try {
                    $errorJson = $_.ToString() | ConvertTo-Json -Compress
                    $writer.Write('],"EventCount":' + $eventCount + ',"Partial":true,"Error":' + $errorJson + '}')
                    $writer.Close()
                    $writer.Dispose()
                }
                catch {
                    Write-Verbose "Failed to dispose endpoint timeline chunk writer: $($_.Exception.Message)"
                }
            }
            $chunkTimer.Stop()
            $partialFileSizeKB = if (Test-Path -LiteralPath $filePath) { [math]::Round((Get-Item -LiteralPath $filePath).Length / 1KB, 2) } else { 0 }
            $failureClass = Get-EndpointTimelineFailureClass -ErrorRecord $_
            [PSCustomObject]@{
                ChunkIndex            = $chunkIndex
                RequestShapeHash       = $initialUriHash
                RequestShape           = $initialUriShape
                FilePath               = if (Test-Path -LiteralPath $filePath) { $filePath } else { $null }
                FileSha256             = if (Test-Path -LiteralPath $filePath) { (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash } else { $null }
                Success                = $false
                Error                  = $_.ToString()
                FailureClass           = $failureClass
                FromDate               = $chunkFromDate
                ToDate                 = $chunkToDate
                OwnerFromDate          = $ownerFromDate
                OwnerToDate            = $ownerToDate
                EventCount             = $eventCount
                UniqueKeyCount         = $seenEventKeys.Count
                KeySetHash             = Get-EndpointTimelineHash -Value ((@($seenEventKeys) | Sort-Object) -join "`n")
                FirstTimestamp         = if ($chunkFirstTimestamp) { $chunkFirstTimestamp.ToString('o') } else { $null }
                LastTimestamp          = if ($chunkLastTimestamp) { $chunkLastTimestamp.ToString('o') } else { $null }
                MissingTimestampCount  = $missingTimestampCount
                PagesRetrieved         = $pagesRetrieved
                ContinuationPageCount  = $continuationLoopCount
                NextLinkCount          = $nextCount
                PrevLinkCount          = $prevCount
                ElapsedSeconds         = [math]::Round($chunkTimer.Elapsed.TotalSeconds, 2)
                RetryCount             = $retryCount
                Pages                  = $pageDiagnostics.ToArray()
                Partial                = $true
                FileSizeKB             = $partialFileSizeKB
            }
        }
    }
}
