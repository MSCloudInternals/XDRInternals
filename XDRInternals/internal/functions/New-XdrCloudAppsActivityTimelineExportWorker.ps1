function New-XdrCloudAppsActivityTimelineExportWorker {
    <#
    .SYNOPSIS
        Creates the self-contained Cloud Apps activity timeline export worker.

    .DESCRIPTION
        Returns a scriptblock that downloads one bounded recent or archived activity
        interval, validates it against the count API, uses endpoint-specific keyset and
        dense-timestamp pagination, and writes UTF-8 NDJSON without retaining the complete
        interval in memory.

    .EXAMPLE
        $worker = New-XdrCloudAppsActivityTimelineExportWorker
        Creates the worker used by Export-XdrCloudAppsActivityTimeline.
    #>
    [OutputType([scriptblock])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private factory that only returns a worker scriptblock.')]
    [CmdletBinding()]
    param ()

    return {
        param($chunk, $sharedParameters, $statusMap)

        $chunkIndex = [int]$chunk.Index
        $chunkFromDate = ([datetime]$chunk.FromDate).ToUniversalTime()
        $chunkToDate = ([datetime]$chunk.ToDate).ToUniversalTime()
        $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
        $partialPath = "$filePath.partial"
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $eventCount = 0L
        $pageCount = 0
        $rewindCount = 0
        $missingTimestampCount = 0L
        $boundaryTimestampCount = 0L
        $duplicateRepresentationCount = 0L
        $expectedEventCount = 0L
        $countIsLowerBound = $false
        $state = @{
            RetryCount  = 0
            FailureClass = 'Protocol'
        }

        $getValue = {
            param($InputObject, [string]$Name)

            if ($null -eq $InputObject) { return $null }
            if ($InputObject -is [System.Collections.IDictionary]) {
                if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
                foreach ($key in $InputObject.Keys) {
                    if ([string]$key -ceq $Name) { return $InputObject[$key] }
                }
                foreach ($key in $InputObject.Keys) {
                    if ([string]$key -ieq $Name) { return $InputObject[$key] }
                }
                return $null
            }
            $property = $InputObject.PSObject.Properties | Where-Object Name -CEQ $Name | Select-Object -First 1
            if ($property) { return $property.Value }
            $property = $InputObject.PSObject.Properties | Where-Object Name -IEQ $Name | Select-Object -First 1
            if ($property) { return $property.Value }
            return $null
        }

        $hasProperty = {
            param($InputObject, [string]$Name)

            if ($null -eq $InputObject) { return $false }
            if ($InputObject -is [System.Collections.IDictionary]) {
                foreach ($key in $InputObject.Keys) {
                    if ([string]$key -ieq $Name) { return $true }
                }
                return $false
            }
            return $null -ne ($InputObject.PSObject.Properties | Where-Object Name -IEQ $Name | Select-Object -First 1)
        }

        $parseResponse = {
            param($Response)

            if ($Response -is [string]) {
                if ([string]::IsNullOrWhiteSpace($Response)) { return $null }
                $convertFromJson = Get-Command ConvertFrom-Json -ErrorAction Stop
                if ($convertFromJson.Parameters.ContainsKey('AsHashtable')) {
                    return $Response | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop
                }

                Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
                $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                $serializer.MaxJsonLength = [int]::MaxValue
                return $serializer.DeserializeObject($Response)
            }
            return $Response
        }

        $getCeilingUnixMillisecond = {
            param([datetime]$Value)

            $utc = $Value.ToUniversalTime()
            $offset = [datetimeoffset]::new($utc)
            $milliseconds = $offset.ToUnixTimeMilliseconds()
            if (($utc.Ticks % [timespan]::TicksPerMillisecond) -ne 0) { $milliseconds++ }
            return [long]$milliseconds
        }

        $parseTimeValue = {
            param($Value)

            if ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value)) {
                $numericTimestamp = 0L
                if ([long]::TryParse([string]$Value, [ref]$numericTimestamp)) {
                    try {
                        if ([math]::Abs($numericTimestamp) -gt 9999999999L) {
                            return [PSCustomObject]@{
                                DateTime = [datetimeoffset]::FromUnixTimeMilliseconds($numericTimestamp).UtcDateTime
                                UnixMilliseconds = $numericTimestamp
                            }
                        }
                        $dateTime = [datetimeoffset]::FromUnixTimeSeconds($numericTimestamp).UtcDateTime
                        return [PSCustomObject]@{
                            DateTime = $dateTime
                            UnixMilliseconds = [datetimeoffset]::new($dateTime).ToUnixTimeMilliseconds()
                        }
                    }
                    catch { return $null }
                }
                $parsed = [datetimeoffset]::MinValue
                $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
                if ([datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
                    return [PSCustomObject]@{
                        DateTime = $parsed.UtcDateTime
                        UnixMilliseconds = $parsed.ToUnixTimeMilliseconds()
                    }
                }
            }
            return $null
        }

        $parseTimestamp = {
            param($Activity)

            $timestamp = & $parseTimeValue (& $getValue $Activity 'timestamp')
            if ($null -ne $timestamp) { return $timestamp }
            return & $parseTimeValue (& $getValue $Activity 'date')
        }

        $getStableKey = {
            param([string]$Json)

            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Json))
                return "payload:$([System.BitConverter]::ToString($hashBytes).Replace('-', ''))"
            }
            finally {
                $sha256.Dispose()
            }
        }

        $invokeRequest = {
            param([string]$Uri, [hashtable]$Body)

            $response = $null
            for ($attempt = 1; $attempt -le [int]$sharedParameters.MaxRetries; $attempt++) {
                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method POST -ContentType 'application/json' `
                        -Body ($Body | ConvertTo-Json -Depth 20 -Compress) -WebSession $webSession `
                        -Headers $sharedParameters.HeadersData -TimeoutSec $sharedParameters.RequestTimeoutSeconds -ErrorAction Stop
                    return & $parseResponse $response
                }
                catch {
                    $statusCode = $null
                    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    }
                    $isTransient = $null -eq $statusCode -or $statusCode -in @(408, 429, 500, 502, 503, 504)
                    if (-not $isTransient -or $attempt -eq [int]$sharedParameters.MaxRetries) {
                        $state.FailureClass = if ($statusCode -in @(401, 403)) {
                            'Authentication'
                        }
                        elseif ($isTransient -and $null -eq $statusCode) {
                            'Transport'
                        }
                        elseif ($isTransient) {
                            'TransientHttp'
                        }
                        else {
                            'PermanentHttp'
                        }
                        throw
                    }

                    $state.RetryCount++
                    $baseDelaySeconds = if ($sharedParameters.ContainsKey('RetryDelaySeconds')) {
                        [double]$sharedParameters.RetryDelaySeconds
                    }
                    else { 1.0 }
                    $delaySeconds = [math]::Min(300, $baseDelaySeconds * [math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 0 -Maximum 3))
                    if ($statusCode -eq 429 -and $_.Exception.Response -and $_.Exception.Response.Headers -and
                        $_.Exception.Response.Headers.RetryAfter) {
                        $retryAfter = $_.Exception.Response.Headers.RetryAfter
                        $retryAfterSeconds = if ($retryAfter.Delta) {
                            [math]::Ceiling($retryAfter.Delta.TotalSeconds)
                        }
                        elseif ($retryAfter.Date) {
                            [math]::Ceiling(($retryAfter.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds)
                        }
                        else { 0 }
                        $delaySeconds = [math]::Max($delaySeconds, [math]::Min(300, $retryAfterSeconds))
                    }
                    Start-Sleep -Seconds $delaySeconds
                }
            }
        }

        try {
            if (Test-Path -LiteralPath $partialPath) {
                Remove-Item -LiteralPath $partialPath -Force
            }
            [System.IO.File]::WriteAllBytes($partialPath, [byte[]]@())

            $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            foreach ($cookieInfo in $sharedParameters.CookieData) {
                $cookie = [System.Net.Cookie]::new(
                    [string]$cookieInfo.Name,
                    [string]$cookieInfo.Value,
                    [string]$cookieInfo.Path,
                    [string]$cookieInfo.Domain
                )
                $webSession.Cookies.Add($cookie)
            }

            $requestFromMilliseconds = & $getCeilingUnixMillisecond $chunkFromDate
            $requestToMilliseconds = (& $getCeilingUnixMillisecond $chunkToDate) - 1L
            if ($requestFromMilliseconds -gt $requestToMilliseconds) {
                throw "Chunk $chunkIndex does not contain a complete API timestamp millisecond."
            }

            $activityPath = if ([bool]$chunk.Archived) { 'archived_activities' } else { 'activities' }
            $activityUri = "$($sharedParameters.BaseUrl)/apiproxy/mcas/cas/api/v1/$activityPath/"
            $countUri = "$($sharedParameters.BaseUrl)/apiproxy/mcas/cas/api/v1/$activityPath/count/"
            $newFilter = {
                param([long]$EndMilliseconds)

                $filters = $sharedParameters.Filters.Clone()
                if ([bool]$chunk.Archived) {
                    $filters.date = @{ range = @(@{ start = $requestFromMilliseconds; end = $EndMilliseconds }) }
                }
                else {
                    $filters.date = @{ gte = $requestFromMilliseconds; lte = $EndMilliseconds }
                }
                return $filters
            }

            $countResponse = & $invokeRequest $countUri @{ filters = (& $newFilter $requestToMilliseconds) }
            if (-not (& $hasProperty $countResponse 'total') -or -not (& $hasProperty $countResponse 'moreThanTotal')) {
                $state.FailureClass = 'PartialResponse'
                throw "Chunk $chunkIndex received an incomplete count response."
            }
            $expectedEventCount = [long](& $getValue $countResponse 'total')
            $countIsLowerBound = [bool](& $getValue $countResponse 'moreThanTotal')

            $partStream = $null
            $partWriter = $null
            try {
                $partStream = [System.IO.FileStream]::new(
                    $partialPath,
                    [System.IO.FileMode]::Append,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None,
                    1MB,
                    [System.IO.FileOptions]::SequentialScan
                )
                $partWriter = [System.IO.StreamWriter]::new($partStream, [System.Text.UTF8Encoding]::new($false), 1MB, $true)
                $partWriter.NewLine = "`n"
                $seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

                while ($true) {
                    if ($pageCount -ge [int]$sharedParameters.MaxPagesPerChunk) {
                        throw "Chunk $chunkIndex exceeded the page safety limit."
                    }

                    $requestBody = @{
                        distributedId     = [guid]::NewGuid().ToString()
                        filters           = & $newFilter $requestToMilliseconds
                        limit             = [int]$sharedParameters.PageSize
                        performAsyncTotal = $true
                        skip              = 0
                        sortDirection     = 'desc'
                        sortField         = 'date'
                    }
                    $response = & $invokeRequest $activityUri $requestBody
                    $hasData = & $hasProperty $response 'data'
                    $dataValue = if ($hasData) { & $getValue $response 'data' } else { $null }
                    $responseData = if ($null -eq $dataValue) { @() } else { @($dataValue) }

                    if (-not $hasData -and ($eventCount -lt $expectedEventCount -or $countIsLowerBound)) {
                        $state.FailureClass = 'PartialResponse'
                        throw "Chunk $chunkIndex received an activity response without data before the counted events were retrieved."
                    }
                    if ($responseData.Count -gt [int]$sharedParameters.PageSize) {
                        throw "Chunk $chunkIndex received more rows than its requested page size."
                    }

                    $pageCount++
                    $previousTimestamp = $null
                    $pageRows = [System.Collections.Generic.List[object]]::new()
                    $pageNewestMilliseconds = $null
                    $pageOldestMilliseconds = $null
                    foreach ($activity in $responseData) {
                        if ($null -eq $activity) {
                            $state.FailureClass = 'PartialResponse'
                            throw "Chunk $chunkIndex received a null activity record."
                        }
                        $timestamp = & $parseTimestamp $activity
                        if ($null -eq $timestamp) {
                            $missingTimestampCount++
                            throw "Chunk $chunkIndex received an activity without a parseable timestamp."
                        }
                        if ($timestamp.DateTime -lt $chunkFromDate -or $timestamp.DateTime -ge $chunkToDate) {
                            throw "Chunk $chunkIndex received an activity outside its logical interval: $($timestamp.DateTime.ToString('o'))."
                        }
                        if ($timestamp.UnixMilliseconds -lt $requestFromMilliseconds -or
                            $timestamp.UnixMilliseconds -gt $requestToMilliseconds) {
                            throw "Chunk $chunkIndex received an activity outside its requested API interval."
                        }
                        if ($null -ne $previousTimestamp -and $timestamp.UnixMilliseconds -gt $previousTimestamp) {
                            throw "Chunk $chunkIndex received activities outside descending timestamp order."
                        }
                        $previousTimestamp = $timestamp.UnixMilliseconds
                        if ($null -eq $pageNewestMilliseconds) { $pageNewestMilliseconds = $timestamp.UnixMilliseconds }
                        $pageOldestMilliseconds = $timestamp.UnixMilliseconds
                        if ($timestamp.DateTime -eq $chunkFromDate -or $timestamp.DateTime -eq $chunkToDate) {
                            $boundaryTimestampCount++
                        }
                        $json = $activity | ConvertTo-Json -Depth 100 -Compress
                        $pageRows.Add([PSCustomObject]@{
                                UnixMilliseconds = $timestamp.UnixMilliseconds
                                StableKey = & $getStableKey $json
                                Json = $json
                            })
                    }

                    $pageIsFull = $responseData.Count -eq [int]$sharedParameters.PageSize
                    $hasNext = & $getValue $response 'hasNext'
                    $pageHasMore = $pageIsFull -or $hasNext -eq $true
                    if ($pageHasMore -and $pageNewestMilliseconds -eq $pageOldestMilliseconds) {
                        $denseTimestampMilliseconds = [long]$pageOldestMilliseconds
                        $rewindCount++

                        if ([bool]$chunk.Archived) {
                            $denseFilters = $sharedParameters.Filters.Clone()
                            $denseFilters.date = @{ range = @(@{ start = $denseTimestampMilliseconds; end = $denseTimestampMilliseconds }) }
                            $denseCountResponse = & $invokeRequest $countUri @{ filters = $denseFilters }
                            if (-not (& $hasProperty $denseCountResponse 'total') -or -not (& $hasProperty $denseCountResponse 'moreThanTotal')) {
                                $state.FailureClass = 'PartialResponse'
                                throw "Chunk $chunkIndex received an incomplete dense timestamp count response."
                            }
                            $denseExpectedCount = [long](& $getValue $denseCountResponse 'total')
                            $denseCountIsLowerBound = [bool](& $getValue $denseCountResponse 'moreThanTotal')

                            $denseSeenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                            $densePayloadKeyById = @{}
                            $denseDirectionConverged = @{ desc = $false; asc = $false }
                            $denseCountSatisfied = $false
                            for ($denseSweep = 0; $denseSweep -lt 6; $denseSweep++) {
                                $denseSweepDirection = if ($denseSweep % 2 -eq 0) { 'desc' } else { 'asc' }
                                $denseCountBeforeSweep = $denseSeenIds.Count
                                $denseSkip = 0
                                while ($true) {
                                    if ($pageCount -ge [int]$sharedParameters.MaxPagesPerChunk) {
                                        throw "Chunk $chunkIndex exceeded the page safety limit."
                                    }
                                    $secondaryResponse = & $invokeRequest $activityUri @{
                                        distributedId     = [guid]::NewGuid().ToString()
                                        filters           = $denseFilters
                                        limit             = [int]$sharedParameters.PageSize
                                        performAsyncTotal = $true
                                        skip              = $denseSkip
                                        sortDirection     = $denseSweepDirection
                                        sortField         = 'created'
                                    }
                                    $secondaryHasData = & $hasProperty $secondaryResponse 'data'
                                    $secondaryDataValue = if ($secondaryHasData) { & $getValue $secondaryResponse 'data' } else { $null }
                                    $secondaryData = if ($null -eq $secondaryDataValue) { @() } else { @($secondaryDataValue) }
                                    if (-not $secondaryHasData -or $secondaryData.Count -eq 0) {
                                        $state.FailureClass = 'PartialResponse'
                                        throw "Chunk $chunkIndex received an incomplete archived dense timestamp response."
                                    }
                                    if ($secondaryData.Count -gt [int]$sharedParameters.PageSize) {
                                        throw "Chunk $chunkIndex received more rows than its requested page size."
                                    }

                                    $pageCount++
                                    $secondaryPreviousMilliseconds = $null
                                    foreach ($activity in $secondaryData) {
                                        if ($null -eq $activity) {
                                            $state.FailureClass = 'PartialResponse'
                                            throw "Chunk $chunkIndex received a null activity record."
                                        }
                                        $timestamp = & $parseTimestamp $activity
                                        if ($null -eq $timestamp) {
                                            $missingTimestampCount++
                                            throw "Chunk $chunkIndex received an activity without a parseable timestamp."
                                        }
                                        if ($timestamp.UnixMilliseconds -ne $denseTimestampMilliseconds) {
                                            throw "Chunk $chunkIndex received an activity outside its dense timestamp interval."
                                        }
                                        $created = & $parseTimeValue (& $getValue $activity 'created')
                                        if ($null -eq $created) {
                                            $state.FailureClass = 'UnpageableBoundary'
                                            throw "Chunk $chunkIndex received an archived dense timestamp activity without a parseable created value."
                                        }
                                        $outOfOrder = $null -ne $secondaryPreviousMilliseconds -and (
                                            ($denseSweepDirection -eq 'desc' -and $created.UnixMilliseconds -gt $secondaryPreviousMilliseconds) -or
                                            ($denseSweepDirection -eq 'asc' -and $created.UnixMilliseconds -lt $secondaryPreviousMilliseconds)
                                        )
                                        if ($outOfOrder) {
                                            throw "Chunk $chunkIndex received activities outside $denseSweepDirection created order."
                                        }
                                        $secondaryPreviousMilliseconds = $created.UnixMilliseconds

                                        $activityId = $null
                                        foreach ($idName in @('_id', 'id', 'recordId')) {
                                            $candidateId = & $getValue $activity $idName
                                            if (-not [string]::IsNullOrWhiteSpace([string]$candidateId)) {
                                                $activityId = [string]$candidateId
                                                break
                                            }
                                        }
                                        if ($null -eq $activityId) {
                                            $state.FailureClass = 'UnpageableBoundary'
                                            throw "Chunk $chunkIndex received an archived dense timestamp activity without a stable identifier."
                                        }

                                        $json = $activity | ConvertTo-Json -Depth 100 -Compress
                                        $payloadKey = & $getStableKey $json
                                        if ($densePayloadKeyById.ContainsKey($activityId) -and
                                            [string]$densePayloadKeyById[$activityId] -ne [string]$payloadKey) {
                                            $state.FailureClass = 'UnpageableBoundary'
                                            throw "Chunk $chunkIndex received different archived dense-timestamp payloads for stable activity identifier '$activityId'."
                                        }
                                        $densePayloadKeyById[$activityId] = $payloadKey

                                        if ($denseSeenIds.Add($activityId)) {
                                            $partWriter.WriteLine($json)
                                            $eventCount++
                                        }
                                    }
                                    $partWriter.Flush()
                                    $statusMap[$chunkIndex] = [PSCustomObject]@{
                                        Pages = $pageCount; Events = $eventCount; Bytes = $partStream.Position
                                        Rewinds = $rewindCount; UpdatedUtc = [datetime]::UtcNow
                                    }

                                    $secondaryPageIsFull = $secondaryData.Count -eq [int]$sharedParameters.PageSize
                                    $secondaryHasNext = & $getValue $secondaryResponse 'hasNext'
                                    if ($secondaryHasNext -ne $true -and -not $secondaryPageIsFull) { break }
                                    if ($secondaryHasNext -eq $false) { break }
                                    $denseSkip += $secondaryData.Count
                                }
                                if ($denseSeenIds.Count -eq $denseCountBeforeSweep) {
                                    $denseDirectionConverged[$denseSweepDirection] = $true
                                }
                                if (-not $denseCountIsLowerBound -and $denseSeenIds.Count -ge $denseExpectedCount) {
                                    $denseCountSatisfied = $true
                                    break
                                }
                                if ($denseDirectionConverged.desc -and $denseDirectionConverged.asc) { break }
                            }
                            if (-not $denseCountSatisfied -and (-not $denseDirectionConverged.desc -or -not $denseDirectionConverged.asc)) {
                                $state.FailureClass = 'PartialResponse'
                                throw "Chunk $chunkIndex could not converge archived dense timestamp pagination after six alternating sweeps; retrieved $($denseSeenIds.Count) stable activities and the count snapshot reported $denseExpectedCount."
                            }

                            $requestToMilliseconds = $denseTimestampMilliseconds - 1L
                            if ($requestToMilliseconds -lt $requestFromMilliseconds) { break }
                            continue
                        }

                        $createdCursorMilliseconds = $null

                        while ($true) {
                            if ($pageCount -ge [int]$sharedParameters.MaxPagesPerChunk) {
                                throw "Chunk $chunkIndex exceeded the page safety limit."
                            }

                            $secondaryFilters = $sharedParameters.Filters.Clone()
                            if ([bool]$chunk.Archived) {
                                $secondaryFilters.date = @{ range = @(@{ start = $denseTimestampMilliseconds; end = $denseTimestampMilliseconds }) }
                            }
                            else {
                                $secondaryFilters.date = @{ gte = $denseTimestampMilliseconds; lte = $denseTimestampMilliseconds }
                            }
                            if ($null -ne $createdCursorMilliseconds) {
                                $existingCreatedFilter = & $getValue $secondaryFilters 'created'
                                if ($null -ne $existingCreatedFilter -and $existingCreatedFilter -isnot [System.Collections.IDictionary]) {
                                    $state.FailureClass = 'UnpageableBoundary'
                                    throw "Chunk $chunkIndex cannot refine the caller-supplied created filter for dense timestamp pagination."
                                }
                                $createdFilter = @{}
                                if ($existingCreatedFilter -is [System.Collections.IDictionary]) {
                                    foreach ($key in $existingCreatedFilter.Keys) { $createdFilter[$key] = $existingCreatedFilter[$key] }
                                }
                                $existingUpperBound = & $getValue $createdFilter 'lte'
                                if ($null -ne $existingUpperBound) {
                                    $parsedUpperBound = & $parseTimeValue $existingUpperBound
                                    if ($null -eq $parsedUpperBound) {
                                        $state.FailureClass = 'UnpageableBoundary'
                                        throw "Chunk $chunkIndex cannot parse the caller-supplied created upper bound."
                                    }
                                    $createdFilter.lte = [math]::Min($parsedUpperBound.UnixMilliseconds, $createdCursorMilliseconds)
                                }
                                else {
                                    $createdFilter.lte = $createdCursorMilliseconds
                                }
                                $secondaryFilters.created = $createdFilter
                            }

                            $secondaryResponse = & $invokeRequest $activityUri @{
                                distributedId     = [guid]::NewGuid().ToString()
                                filters           = $secondaryFilters
                                limit             = [int]$sharedParameters.PageSize
                                performAsyncTotal = $true
                                skip              = 0
                                sortDirection     = 'desc'
                                sortField         = 'created'
                            }
                            $secondaryHasData = & $hasProperty $secondaryResponse 'data'
                            $secondaryDataValue = if ($secondaryHasData) { & $getValue $secondaryResponse 'data' } else { $null }
                            $secondaryData = if ($null -eq $secondaryDataValue) { @() } else { @($secondaryDataValue) }
                            if (-not $secondaryHasData -or $secondaryData.Count -eq 0) {
                                $state.FailureClass = 'PartialResponse'
                                throw "Chunk $chunkIndex received an incomplete dense timestamp response."
                            }
                            if ($secondaryData.Count -gt [int]$sharedParameters.PageSize) {
                                throw "Chunk $chunkIndex received more rows than its requested page size."
                            }

                            $pageCount++
                            $secondaryPreviousMilliseconds = $null
                            $secondaryNewestMilliseconds = $null
                            $secondaryOldestMilliseconds = $null
                            $secondaryRows = [System.Collections.Generic.List[object]]::new()
                            foreach ($activity in $secondaryData) {
                                if ($null -eq $activity) {
                                    $state.FailureClass = 'PartialResponse'
                                    throw "Chunk $chunkIndex received a null activity record."
                                }
                                $timestamp = & $parseTimestamp $activity
                                if ($null -eq $timestamp) {
                                    $missingTimestampCount++
                                    throw "Chunk $chunkIndex received an activity without a parseable timestamp."
                                }
                                if ($timestamp.UnixMilliseconds -ne $denseTimestampMilliseconds) {
                                    throw "Chunk $chunkIndex received an activity outside its dense timestamp interval."
                                }
                                $created = & $parseTimeValue (& $getValue $activity 'created')
                                if ($null -eq $created) {
                                    $state.FailureClass = 'UnpageableBoundary'
                                    throw "Chunk $chunkIndex received a dense timestamp activity without a parseable created value."
                                }
                                if ($null -ne $secondaryPreviousMilliseconds -and $created.UnixMilliseconds -gt $secondaryPreviousMilliseconds) {
                                    throw "Chunk $chunkIndex received activities outside descending created order."
                                }
                                $secondaryPreviousMilliseconds = $created.UnixMilliseconds
                                if ($null -eq $secondaryNewestMilliseconds) { $secondaryNewestMilliseconds = $created.UnixMilliseconds }
                                $secondaryOldestMilliseconds = $created.UnixMilliseconds
                                $json = $activity | ConvertTo-Json -Depth 100 -Compress
                                $secondaryRows.Add([PSCustomObject]@{
                                        UnixMilliseconds = $created.UnixMilliseconds
                                        StableKey = & $getStableKey $json
                                        Json = $json
                                    })
                            }

                            $secondaryPageIsFull = $secondaryData.Count -eq [int]$sharedParameters.PageSize
                            $secondaryHasNext = & $getValue $secondaryResponse 'hasNext'
                            $secondaryPageHasMore = $secondaryPageIsFull -or $secondaryHasNext -eq $true
                            if ($secondaryPageHasMore -and $secondaryNewestMilliseconds -eq $secondaryOldestMilliseconds) {
                                $state.FailureClass = 'UnpageableBoundary'
                                throw "Chunk $chunkIndex cannot prove completeness because one created timestamp millisecond filled a complete $([int]$sharedParameters.PageSize)-row page."
                            }

                            foreach ($row in $secondaryRows) {
                                if ($secondaryPageHasMore -and $row.UnixMilliseconds -eq $secondaryOldestMilliseconds) { continue }
                                if ($seenKeys.Add([string]$row.StableKey)) {
                                    $partWriter.WriteLine($row.Json)
                                    $eventCount++
                                }
                                else {
                                    $duplicateRepresentationCount++
                                }
                            }
                            $partWriter.Flush()
                            $statusMap[$chunkIndex] = [PSCustomObject]@{
                                Pages = $pageCount; Events = $eventCount; Bytes = $partStream.Position
                                Rewinds = $rewindCount; UpdatedUtc = [datetime]::UtcNow
                            }

                            if (-not $secondaryPageHasMore) { break }
                            if ($null -ne $createdCursorMilliseconds -and $secondaryOldestMilliseconds -ge $createdCursorMilliseconds) {
                                $state.FailureClass = 'UnpageableBoundary'
                                throw "Chunk $chunkIndex cannot advance beyond its oldest created timestamp."
                            }
                            $createdCursorMilliseconds = [long]$secondaryOldestMilliseconds
                            $rewindCount++
                        }

                        $requestToMilliseconds = $denseTimestampMilliseconds - 1L
                        if ($requestToMilliseconds -lt $requestFromMilliseconds) { break }
                        continue
                    }

                    foreach ($row in $pageRows) {
                        if ($pageHasMore -and $row.UnixMilliseconds -eq $pageOldestMilliseconds) { continue }
                        if ($seenKeys.Add([string]$row.StableKey)) {
                            $partWriter.WriteLine($row.Json)
                            $eventCount++
                        }
                        else {
                            $duplicateRepresentationCount++
                        }
                    }
                    $partWriter.Flush()

                    $statusMap[$chunkIndex] = [PSCustomObject]@{
                        Pages      = $pageCount
                        Events     = $eventCount
                        Bytes      = $partStream.Position
                        Rewinds    = $rewindCount
                        UpdatedUtc = [datetime]::UtcNow
                    }

                    if (-not $pageHasMore) { break }
                    if ($pageOldestMilliseconds -ge $requestToMilliseconds) {
                        $state.FailureClass = 'UnpageableBoundary'
                        throw "Chunk $chunkIndex cannot advance beyond its oldest activity timestamp."
                    }
                    $requestToMilliseconds = $pageOldestMilliseconds
                    $rewindCount++
                }
            }
            finally {
                if ($partWriter) { $partWriter.Dispose() }
                if ($partStream) { $partStream.Dispose() }
            }

            $countDelta = $eventCount - $expectedEventCount
            $countMismatchRestartLimit = if ($sharedParameters.ContainsKey('MaxCountMismatchRestarts')) {
                [int]$sharedParameters.MaxCountMismatchRestarts
            }
            else { 2 }
            if ($countDelta -lt 0 -and [int]$chunk.Attempt -lt $countMismatchRestartLimit) {
                $state.FailureClass = 'PartialResponse'
                throw "Chunk $chunkIndex retrieved $eventCount activities but the count snapshot reported $expectedEventCount."
            }

            $fileBytes = (Get-Item -LiteralPath $partialPath).Length
            $fileSha256 = (Get-FileHash -LiteralPath $partialPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if (Test-Path -LiteralPath $filePath) {
                Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop
            }
            [System.IO.File]::Move($partialPath, $filePath)
            $stopwatch.Stop()

            return [PSCustomObject]@{
                Success                = $true
                ChunkIndex             = $chunkIndex
                FromDate               = $chunkFromDate
                ToDate                 = $chunkToDate
                Archived               = [bool]$chunk.Archived
                FilePath               = $filePath
                FileSha256             = $fileSha256
                FileBytes              = $fileBytes
                EventCount             = $eventCount
                ExpectedEventCount     = $expectedEventCount
                CountIsLowerBound      = $countIsLowerBound
                CountDelta             = $countDelta
                PageCount              = $pageCount
                RetryCount             = [int]$state.RetryCount
                RewindCount            = $rewindCount
                MissingTimestampCount  = $missingTimestampCount
                BoundaryTimestampCount = $boundaryTimestampCount
                DuplicateRepresentationCount = $duplicateRepresentationCount
                ElapsedSeconds         = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
                Error                  = $null
                FailureClass           = $null
            }
        }
        catch {
            $stopwatch.Stop()
            $errorText = $_.Exception.Message
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = $_.Exception.GetType().FullName }
            elseif ($errorText -match '<html|<!doctype|var __ADALLOM_CONSTS') { $errorText = 'The service returned an HTML portal error page.' }
            elseif ($errorText.Length -gt 1000) { $errorText = $errorText.Substring(0, 1000) + '...' }
            return [PSCustomObject]@{
                Success                = $false
                ChunkIndex             = $chunkIndex
                FromDate               = $chunkFromDate
                ToDate                 = $chunkToDate
                Archived               = [bool]$chunk.Archived
                FilePath               = $filePath
                FileSha256             = $null
                FileBytes              = 0L
                EventCount             = $eventCount
                ExpectedEventCount     = $expectedEventCount
                CountIsLowerBound      = $countIsLowerBound
                CountDelta             = $eventCount - $expectedEventCount
                PageCount              = $pageCount
                RetryCount             = [int]$state.RetryCount
                RewindCount            = $rewindCount
                MissingTimestampCount  = $missingTimestampCount
                BoundaryTimestampCount = $boundaryTimestampCount
                DuplicateRepresentationCount = $duplicateRepresentationCount
                ElapsedSeconds         = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
                Error                  = $errorText
                FailureClass           = [string]$state.FailureClass
            }
        }
        finally {
            if (Test-Path -LiteralPath $partialPath) {
                Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
            }
            [void]$statusMap.TryRemove($chunkIndex, [ref]$null)
        }
    }
}
