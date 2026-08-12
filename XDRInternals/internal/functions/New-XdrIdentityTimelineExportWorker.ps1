function New-XdrIdentityTimelineExportWorker {
    <#
    .SYNOPSIS
        Creates the self-contained identity timeline export worker.

    .DESCRIPTION
        Returns a scriptblock that downloads one bounded identity timeline interval,
        validates timestamp-keyset pages, advances safely across tied API-second groups,
        and writes UTF-8 NDJSON without retaining the complete interval in memory.

    .EXAMPLE
        $worker = New-XdrIdentityTimelineExportWorker
        Creates the worker used by Export-XdrIdentityUserTimeline.
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
        $retryCount = 0
        $rewindCount = 0
        $missingTimestampCount = 0L
        $boundaryTimestampCount = 0L
        $duplicateRepresentationCount = 0L
        $failureClass = 'Protocol'
        $lastCommittedTimestamp = $null

        $parseTimestamp = {
            param($Value)

            if ($Value -is [datetime]) {
                return ([datetime]$Value).ToUniversalTime()
            }
            if ($Value -is [datetimeoffset]) {
                return ([datetimeoffset]$Value).UtcDateTime
            }

            $parsed = [datetimeoffset]::MinValue
            $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
            if (-not [string]::IsNullOrWhiteSpace([string]$Value) -and
                [datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
                return $parsed.UtcDateTime
            }
            return $null
        }

        $getCeilingUnixSecond = {
            param([datetime]$Value)

            $utc = $Value.ToUniversalTime()
            $offset = [datetimeoffset]::new($utc)
            $seconds = $offset.ToUnixTimeSeconds()
            if (($utc.Ticks % [timespan]::TicksPerSecond) -ne 0) {
                $seconds++
            }
            return [long]$seconds
        }

        $canonicalizePayload = {
            param($Value)

            if ($Value -is [System.Collections.IDictionary]) {
                $ordered = [ordered]@{}
                foreach ($name in @($Value.Keys | Sort-Object)) {
                    $ordered[[string]$name] = & $canonicalizePayload $Value[$name]
                }
                return $ordered
            }
            if ($Value -is [System.Management.Automation.PSCustomObject]) {
                $ordered = [ordered]@{}
                foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) {
                    $ordered[$property.Name] = & $canonicalizePayload $property.Value
                }
                return $ordered
            }
            if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
                return @($Value | ForEach-Object { & $canonicalizePayload $_ })
            }
            return $Value
        }

        $getEventKey = {
            param($EventItem, [datetime]$Timestamp)

            # Live responses showed that EventId is reused over time and that the
            # same EventId/Timestamp representation can recur with request-volatile
            # Id, RowNumber, and Description values. Include the stable payload so
            # genuinely distinct records sharing EventId/Timestamp remain distinct.
            $stablePayload = [ordered]@{}
            foreach ($property in ($EventItem.PSObject.Properties | Sort-Object Name)) {
                if ($property.Name -notin @('Id', 'RowNumber', 'Description')) {
                    $stablePayload[$property.Name] = & $canonicalizePayload $property.Value
                }
            }
            $json = $stablePayload | ConvertTo-Json -Depth 100 -Compress
            $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($json))
            $idPrefix = if ($EventItem.PSObject.Properties['EventId'] -and
                -not [string]::IsNullOrWhiteSpace([string]$EventItem.EventId)) {
                "EventId:$([string]$EventItem.EventId)"
            } else {
                'NoEventId'
            }
            return "$($Timestamp.ToString('o'))|$idPrefix|Payload:$([Convert]::ToHexString($hashBytes))"
        }

        try {
            foreach ($stalePath in @($partialPath)) {
                if (Test-Path -LiteralPath $stalePath) {
                    Remove-Item -LiteralPath $stalePath -Force
                }
            }
            [System.IO.File]::WriteAllBytes($partialPath, [byte[]]::new(0))

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

            $requestFromUnix = (& $getCeilingUnixSecond $chunkFromDate) - 1L
            $requestToUnix = & $getCeilingUnixSecond $chunkToDate
            $uri = "$($sharedParameters.BaseUrl)/apiproxy/mdi/identity/userapiservice/timeline/mtp"
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

                while ($true) {
                    $requestBody = @{
                        count           = [int]$sharedParameters.PageSize
                        skip            = 0
                        userIdentifiers = $sharedParameters.UserIdentifiers
                        filters         = @{ Timeframe = @{ between = @($requestFromUnix, $requestToUnix) } }
                    }

                    $response = $null
                    for ($attempt = 1; $attempt -le [int]$sharedParameters.MaxRetries; $attempt++) {
                        try {
                            $response = Invoke-RestMethod -Uri $uri -Method POST -ContentType 'application/json' `
                                -Body ($requestBody | ConvertTo-Json -Depth 20) -WebSession $webSession `
                                -Headers $sharedParameters.HeadersData -TimeoutSec $sharedParameters.RequestTimeoutSeconds -ErrorAction Stop
                            break
                        }
                        catch {
                            $statusCode = $null
                            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                                $statusCode = [int]$_.Exception.Response.StatusCode
                            }
                            $isTransient = $null -eq $statusCode -or $statusCode -in @(408, 429, 500, 502, 503, 504)
                            if (-not $isTransient -or $attempt -eq [int]$sharedParameters.MaxRetries) {
                                $failureClass = if ($statusCode -in @(401, 403)) {
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

                            $retryCount++
                            $retryAfterSeconds = $null
                            if ($statusCode -eq 429 -and $_.Exception.Response.Headers.RetryAfter) {
                                $retryAfter = $_.Exception.Response.Headers.RetryAfter
                                if ($null -ne $retryAfter.Delta) {
                                    $retryAfterSeconds = [math]::Ceiling($retryAfter.Delta.TotalSeconds)
                                }
                                elseif ($null -ne $retryAfter.Date) {
                                    $retryAfterSeconds = [math]::Ceiling(
                                        ($retryAfter.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds
                                    )
                                }
                            }
                            $delaySeconds = if ($null -ne $retryAfterSeconds) {
                                [math]::Min(300, [math]::Max(0, $retryAfterSeconds))
                            }
                            else {
                                [math]::Min(30, [math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 0 -Maximum 3))
                            }
                            if ($delaySeconds -gt 0) {
                                Start-Sleep -Seconds $delaySeconds
                            }
                        }
                    }

                    foreach ($requiredProperty in @('count', 'data', 'errors')) {
                        if (-not $response.PSObject.Properties[$requiredProperty]) {
                            $failureClass = 'PartialResponse'
                            throw "Chunk $chunkIndex received a timeline response without '$requiredProperty'."
                        }
                    }
                    $errorPropertyCount = if ($null -eq $response.errors) { 0 } else { @($response.errors.PSObject.Properties).Count }
                    if ($errorPropertyCount -gt 0) {
                        $failureClass = 'PartialResponse'
                        throw "Chunk $chunkIndex received a timeline response containing service errors."
                    }

                    $responseData = if ($null -eq $response.data) { @() } else { @($response.data) }
                    if ([int]$response.count -ne $responseData.Count) {
                        $failureClass = 'PartialResponse'
                        throw "Chunk $chunkIndex received count=$($response.count) but data contained $($responseData.Count) event(s)."
                    }

                    $pageCount++
                    $requestFromDate = [datetimeoffset]::FromUnixTimeSeconds($requestFromUnix).UtcDateTime
                    $requestToDate = [datetimeoffset]::FromUnixTimeSeconds($requestToUnix).UtcDateTime
                    $previousTimestamp = $null
                    $pageRows = [System.Collections.Generic.List[object]]::new()
                    $pageKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                    $pageNewestTimestamp = $null
                    $pageOldestTimestamp = $null
                    $pageNewestUnixSecond = $null
                    $pageOldestUnixSecond = $null

                    foreach ($eventItem in $responseData) {
                        $timestamp = & $parseTimestamp $eventItem.Timestamp
                        if ($null -eq $timestamp) {
                            $missingTimestampCount++
                            throw "Chunk $chunkIndex received an event without a parseable Timestamp."
                        }
                        if ($timestamp -le $requestFromDate -or $timestamp -ge $requestToDate) {
                            throw "Chunk $chunkIndex received an event outside the API's exclusive interval: $($timestamp.ToString('o'))."
                        }
                        if ($timestamp -lt $chunkFromDate -or $timestamp -ge $chunkToDate) {
                            throw "Chunk $chunkIndex received an event outside its logical interval: $($timestamp.ToString('o'))."
                        }
                        if ($null -ne $previousTimestamp -and $timestamp -gt $previousTimestamp) {
                            throw "Chunk $chunkIndex received events outside descending timestamp order."
                        }
                        $previousTimestamp = $timestamp
                        $timestampUnixSecond = [datetimeoffset]::new($timestamp).ToUnixTimeSeconds()
                        if ($null -eq $pageNewestTimestamp) {
                            $pageNewestTimestamp = $timestamp
                            $pageNewestUnixSecond = $timestampUnixSecond
                        }
                        $pageOldestTimestamp = $timestamp
                        $pageOldestUnixSecond = $timestampUnixSecond
                        if ($timestamp -eq $chunkFromDate -or $timestamp -eq $chunkToDate) {
                            $boundaryTimestampCount++
                        }

                        $eventKey = & $getEventKey $eventItem $timestamp
                        if (-not $pageKeys.Add($eventKey)) {
                            $duplicateRepresentationCount++
                            continue
                        }
                        $pageRows.Add([PSCustomObject]@{
                                Timestamp = $timestamp
                                UnixSecond = $timestampUnixSecond
                                Json = ($eventItem | ConvertTo-Json -Depth 100 -Compress)
                            })
                    }

                    $pageIsFull = $responseData.Count -eq [int]$sharedParameters.PageSize
                    if ($pageIsFull -and $pageNewestUnixSecond -eq $pageOldestUnixSecond) {
                        $failureClass = 'UnpageableBoundary'
                        throw "Chunk $chunkIndex cannot prove completeness because one API timestamp second filled a complete $([int]$sharedParameters.PageSize)-row page at $($pageOldestTimestamp.ToString('o'))."
                    }

                    foreach ($row in $pageRows) {
                        if ($pageIsFull -and $row.UnixSecond -eq $pageOldestUnixSecond) {
                            continue
                        }
                        if ($null -ne $lastCommittedTimestamp -and $row.Timestamp -gt $lastCommittedTimestamp) {
                            throw "Chunk $chunkIndex received overlapping keyset pages outside descending timestamp order."
                        }
                        $partWriter.WriteLine($row.Json)
                        $lastCommittedTimestamp = $row.Timestamp
                        $eventCount++
                    }
                    $partWriter.Flush()

                    $statusMap[$chunkIndex] = [PSCustomObject]@{
                        Pages      = $pageCount
                        Events     = $eventCount
                        Bytes      = $partStream.Position
                        Rewinds    = $rewindCount
                        UpdatedUtc = [datetime]::UtcNow
                    }

                    if (-not $pageIsFull) {
                        break
                    }

                    $nextRequestToUnix = $pageOldestUnixSecond + 1L
                    if ($nextRequestToUnix -ge $requestToUnix) {
                        $failureClass = 'UnpageableBoundary'
                        throw "Chunk $chunkIndex cannot advance beyond timestamp $($pageOldestTimestamp.ToString('o'))."
                    }
                    $requestToUnix = $nextRequestToUnix
                    $rewindCount++
                }
            }
            finally {
                if ($partWriter) { $partWriter.Dispose() }
                if ($partStream) { $partStream.Dispose() }
            }

            $fileBytes = (Get-Item -LiteralPath $partialPath).Length
            $fileSha256 = (Get-FileHash -LiteralPath $partialPath -Algorithm SHA256).Hash.ToLowerInvariant()
            [System.IO.File]::Move($partialPath, $filePath, $true)
            $stopwatch.Stop()

            return [PSCustomObject]@{
                Success                = $true
                ChunkIndex             = $chunkIndex
                FromDate               = $chunkFromDate
                ToDate                 = $chunkToDate
                FilePath               = $filePath
                FileSha256             = $fileSha256
                FileBytes              = $fileBytes
                EventCount             = $eventCount
                PageCount              = $pageCount
                RetryCount             = $retryCount
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
            return [PSCustomObject]@{
                Success                = $false
                ChunkIndex             = $chunkIndex
                FromDate               = $chunkFromDate
                ToDate                 = $chunkToDate
                FilePath               = $filePath
                FileSha256             = $null
                FileBytes              = 0L
                EventCount             = $eventCount
                PageCount              = $pageCount
                RetryCount             = $retryCount
                RewindCount            = $rewindCount
                MissingTimestampCount  = $missingTimestampCount
                BoundaryTimestampCount = $boundaryTimestampCount
                DuplicateRepresentationCount = $duplicateRepresentationCount
                ElapsedSeconds         = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
                Error                  = $_.ToString()
                FailureClass           = $failureClass
            }
        }
        finally {
            foreach ($stalePath in @($partialPath)) {
                if (Test-Path -LiteralPath $stalePath) {
                    Remove-Item -LiteralPath $stalePath -Force -ErrorAction SilentlyContinue
                }
            }
            [void]$statusMap.TryRemove($chunkIndex, [ref]$null)
        }
    }
}
