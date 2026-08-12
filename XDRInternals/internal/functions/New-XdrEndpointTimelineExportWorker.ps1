function New-XdrEndpointTimelineExportWorker {
    <#
    .SYNOPSIS
        Creates the self-contained endpoint timeline export worker.

    .DESCRIPTION
        Returns a scriptblock that downloads one bounded timeline interval, follows only
        Prev continuation links, and writes UTF-8 NDJSON with an in-flight SHA-256 hash.

    .EXAMPLE
        $worker = New-XdrEndpointTimelineExportWorker
        Creates the worker used by Export-XdrEndpointDeviceTimeline.
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
        $fileStream = $null
        $fileHasher = $null
        $hashingStream = $null
        $writer = $null
        $eventCount = 0L
        $pageCount = 0
        $retryCount = 0
        $missingTimestampCount = 0L
        $boundaryTimestampCount = 0L
        $previousTimestampUtc = $null
        $failureClass = 'Protocol'
        $failureMessage = $null

        try {
            if (Test-Path -LiteralPath $partialPath) {
                Remove-Item -LiteralPath $partialPath -Force
            }

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

            $queryParameters = @(
                'generateIdentityEvents=true'
                'includeIdentityEvents=true'
                'supportMdiOnlyEvents=true'
                "fromDate=$([System.Uri]::EscapeDataString($chunkFromDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
                "toDate=$([System.Uri]::EscapeDataString($chunkToDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
                "correlationId=$([guid]::NewGuid())"
                'doNotUseCache=false'
                'forceUseCache=false'
                "pageSize=$($sharedParameters.PageSize)"
                "includeSentinelEvents=$($sharedParameters.IncludeSentinelEvents.ToString().ToLowerInvariant())"
            )
            $requestUri = "$($sharedParameters.BaseUrl)/apiproxy/mtp/mdeTimelineExperience/machines/$($sharedParameters.DeviceId)/events/?$($queryParameters -join '&')"
            $seenUris = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $currentRequestToUtc = $chunkToDate

            $fileStream = [System.IO.FileStream]::new(
                $partialPath,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None,
                1MB,
                [System.IO.FileOptions]::SequentialScan
            )
            $fileHasher = [System.Security.Cryptography.SHA256]::Create()
            $hashingStream = [System.Security.Cryptography.CryptoStream]::new(
                $fileStream,
                $fileHasher,
                [System.Security.Cryptography.CryptoStreamMode]::Write,
                $true
            )
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            $writer = [System.IO.StreamWriter]::new($hashingStream, $utf8NoBom, 1MB, $true)
            $writer.NewLine = "`n"

            while ($requestUri) {
                if (-not $seenUris.Add($requestUri)) {
                    throw "Chunk $chunkIndex encountered a repeated pagination URI."
                }
                if ($pageCount -ge [int]$sharedParameters.MaxPagesPerChunk) {
                    throw "Chunk $chunkIndex exceeded the internal page limit of $($sharedParameters.MaxPagesPerChunk)."
                }

                $response = $null
                $partialResponseAttempts = 2
                for ($attempt = 1; $attempt -le [int]$sharedParameters.MaxRetries; $attempt++) {
                    try {
                        $response = Invoke-RestMethod -Uri $requestUri -ContentType 'application/json' -WebSession $webSession -Headers $sharedParameters.HeadersData -TimeoutSec $sharedParameters.RequestTimeoutSeconds -ErrorAction Stop
                        $partialReasons = @($response.PartialResponseReasons | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                        if ($partialReasons.Count -gt 0) {
                            if ($attempt -ge $partialResponseAttempts -or $attempt -eq [int]$sharedParameters.MaxRetries) {
                                $failureClass = 'PartialResponse'
                                $failureMessage = "Chunk $chunkIndex received a partial API response after $attempt attempt(s)."
                                throw $failureMessage
                            }
                            $retryCount++
                            $delaySeconds = [math]::Min(30, [math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 0 -Maximum 3))
                            Start-Sleep -Seconds $delaySeconds
                            $response = $null
                            continue
                        }
                        $failureClass = 'Protocol'
                        break
                    }
                    catch {
                        $statusCode = $null
                        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                            $statusCode = [int]$_.Exception.Response.StatusCode
                        }
                        if ($failureClass -eq 'PartialResponse') {
                            throw
                        }

                        $exceptionCursor = $_.Exception
                        $isMalformedJson = $false
                        while ($exceptionCursor) {
                            if ($exceptionCursor -is [System.Text.Json.JsonException] -or
                                $exceptionCursor.GetType().FullName -in @(
                                    'Newtonsoft.Json.JsonReaderException',
                                    'Newtonsoft.Json.JsonSerializationException'
                                )) {
                                $isMalformedJson = $true
                                break
                            }
                            $exceptionCursor = $exceptionCursor.InnerException
                        }
                        if ($isMalformedJson) {
                            $failureClass = 'Protocol'
                            $failureMessage = "Chunk $chunkIndex received malformed JSON from the endpoint timeline API."
                            throw
                        }

                        $isTransportFailure = $false
                        if ($null -eq $statusCode) {
                            $exceptionCursor = $_.Exception
                            while ($exceptionCursor) {
                                if ($exceptionCursor -is [System.Net.Http.HttpRequestException] -or
                                    $exceptionCursor -is [System.Net.WebException] -or
                                    $exceptionCursor -is [System.Net.Sockets.SocketException] -or
                                    $exceptionCursor -is [System.Threading.Tasks.TaskCanceledException] -or
                                    $exceptionCursor -is [System.TimeoutException]) {
                                    $isTransportFailure = $true
                                    break
                                }
                                $exceptionCursor = $exceptionCursor.InnerException
                            }
                        }

                        $isTransientHttp = $statusCode -in @(408, 429) -or
                            ($null -ne $statusCode -and $statusCode -ge 500 -and $statusCode -le 599)
                        $isTransient = $isTransientHttp -or $isTransportFailure
                        if (-not $isTransient -or $attempt -eq [int]$sharedParameters.MaxRetries) {
                            $failureClass = if ($statusCode -in @(401, 403)) {
                                'Authentication'
                            }
                            elseif ($isTransportFailure) {
                                'Transport'
                            }
                            elseif ($isTransient) {
                                'TransientHttp'
                            }
                            elseif ($null -eq $statusCode) {
                                'Protocol'
                            }
                            else {
                                'PermanentHttp'
                            }
                            $failureMessage = switch ($failureClass) {
                                'Authentication' { "Chunk $chunkIndex endpoint timeline authentication failed (HTTP $statusCode)." }
                                'PermanentHttp' { "Chunk $chunkIndex endpoint timeline request failed permanently (HTTP $statusCode)." }
                                'TransientHttp' { "Chunk $chunkIndex endpoint timeline request failed after $attempt attempt(s) (HTTP $statusCode)." }
                                'Transport' { "Chunk $chunkIndex endpoint timeline transport failed after $attempt attempt(s)." }
                                default { "Chunk $chunkIndex endpoint timeline request failed with a protocol error." }
                            }
                            throw
                        }

                        $retryCount++
                        $delaySeconds = $null
                        if ($statusCode -eq 429 -and $_.Exception.Response.Headers.RetryAfter) {
                            $retryAfter = $_.Exception.Response.Headers.RetryAfter
                            if ($null -ne $retryAfter.Delta) {
                                $delaySeconds = [math]::Ceiling($retryAfter.Delta.TotalSeconds)
                            }
                            elseif ($null -ne $retryAfter.Date) {
                                $delaySeconds = [math]::Ceiling(($retryAfter.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds)
                            }
                        }
                        if ($null -eq $delaySeconds) {
                            $delaySeconds = [math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 0 -Maximum 3)
                        }
                        $delaySeconds = [math]::Max(0, [math]::Min(30, $delaySeconds))
                        Start-Sleep -Seconds $delaySeconds
                    }
                }

                $pageCount++

                $oldestPageTimestampUtc = $null
                foreach ($eventItem in @($response.Items)) {
                    $timestampValue = if ($eventItem.ActionTimeIsoString) { $eventItem.ActionTimeIsoString } else { $eventItem.ActionTime }
                    $timestampParsed = $false
                    $utcTimestamp = [datetime]::MinValue
                    if ($timestampValue -is [datetime]) {
                        $utcTimestamp = ([datetime]$timestampValue).ToUniversalTime()
                        $timestampParsed = $true
                    }
                    elseif ($timestampValue -is [datetimeoffset]) {
                        $utcTimestamp = ([datetimeoffset]$timestampValue).UtcDateTime
                        $timestampParsed = $true
                    }
                    else {
                        $parsedTimestamp = [datetimeoffset]::MinValue
                        $dateStyles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
                        $timestampParsed = $timestampValue -and [datetimeoffset]::TryParse(
                            [string]$timestampValue,
                            [System.Globalization.CultureInfo]::InvariantCulture,
                            $dateStyles,
                            [ref]$parsedTimestamp
                        )
                        if ($timestampParsed) {
                            $utcTimestamp = $parsedTimestamp.UtcDateTime
                        }
                    }

                    if (-not $timestampParsed) {
                        $missingTimestampCount++
                        throw "Chunk $chunkIndex received an event without a parseable timestamp."
                    }
                    if ($utcTimestamp -lt $chunkFromDate -or $utcTimestamp -gt $chunkToDate) {
                        throw "Chunk $chunkIndex received an event outside its requested interval: $($utcTimestamp.ToString('o'))."
                    }
                    if ($null -ne $previousTimestampUtc -and $utcTimestamp -gt $previousTimestampUtc) {
                        throw "Chunk $chunkIndex received events that were not in newest-first order: $($utcTimestamp.ToString('o')) followed $($previousTimestampUtc.ToString('o'))."
                    }
                    $previousTimestampUtc = $utcTimestamp
                    $oldestPageTimestampUtc = $utcTimestamp
                    if ($utcTimestamp -eq $chunkFromDate -or $utcTimestamp -eq $chunkToDate) {
                        $boundaryTimestampCount++
                    }
                    if ($utcTimestamp -eq $chunkToDate) {
                        continue
                    }

                    $writer.WriteLine(($eventItem | ConvertTo-Json -Depth 100 -Compress))
                    $eventCount++
                }

                $statusMap[$chunkIndex] = [PSCustomObject]@{
                    Pages      = $pageCount
                    Events     = $eventCount
                    Bytes      = $fileStream.Position
                    UpdatedUtc = [datetime]::UtcNow
                }

                if ([string]::IsNullOrWhiteSpace([string]$response.Prev)) {
                    $requestUri = $null
                }
                else {
                    $previousReference = [string]$response.Prev
                    $expectedPath = "/machines/$($sharedParameters.DeviceId)/events"
                    $expectedQueryKeys = @(
                        'generateIdentityEvents'
                        'includeIdentityEvents'
                        'supportMdiOnlyEvents'
                        'fromDate'
                        'toDate'
                        'doNotUseCache'
                        'forceUseCache'
                        'pageSize'
                        'includeSentinelEvents'
                        'IsScrollingForward'
                        'ReportIdForScrolling'
                    )
                    $allowedQueryKeys = [System.Collections.Generic.HashSet[string]]::new(
                        [string[]]$expectedQueryKeys,
                        [System.StringComparer]::OrdinalIgnoreCase
                    )
                    $querySeparator = $previousReference.IndexOf('?')
                    $previousPath = if ($querySeparator -ge 0) { $previousReference.Substring(0, $querySeparator) } else { $previousReference }
                    $previousQuery = if ($querySeparator -ge 0) { $previousReference.Substring($querySeparator + 1) } else { '' }
                    $queryParts = @($previousQuery -split '&')
                    $queryKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    $queryValues = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    $queryIsValid = -not [string]::IsNullOrWhiteSpace($previousQuery) -and $previousQuery -notmatch '%(?![0-9A-Fa-f]{2})'
                    foreach ($queryPart in $queryParts) {
                        if ($queryPart -notmatch '^(?<Key>[A-Za-z][A-Za-z0-9._-]*)=.+$' -or
                            -not $allowedQueryKeys.Contains($Matches.Key) -or
                            -not $queryKeys.Add($Matches.Key)) {
                            $queryIsValid = $false
                            break
                        }
                        try {
                            $queryValues[$Matches.Key] = [System.Uri]::UnescapeDataString(
                                $queryPart.Substring($queryPart.IndexOf('=') + 1)
                            )
                        }
                        catch {
                            $queryIsValid = $false
                            break
                        }
                    }
                    if ($queryKeys.Count -ne $expectedQueryKeys.Count) {
                        $queryIsValid = $false
                    }

                    $expectedStaticValues = @{
                        generateIdentityEvents = 'true'
                        includeIdentityEvents  = 'true'
                        supportMdiOnlyEvents   = 'true'
                        doNotUseCache          = 'false'
                        forceUseCache          = 'false'
                        pageSize               = [string]$sharedParameters.PageSize
                        includeSentinelEvents  = $sharedParameters.IncludeSentinelEvents.ToString().ToLowerInvariant()
                        IsScrollingForward     = 'false'
                    }
                    foreach ($expectedValue in $expectedStaticValues.GetEnumerator()) {
                        if (-not $queryValues.ContainsKey($expectedValue.Key) -or
                            -not $queryValues[$expectedValue.Key].Equals([string]$expectedValue.Value, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $queryIsValid = $false
                            break
                        }
                    }

                    $continuationFromUtc = [datetimeoffset]::MinValue
                    $continuationToUtc = [datetimeoffset]::MinValue
                    $continuationDateStyles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
                    $fromDateIsValid = $queryValues.ContainsKey('fromDate') -and [datetimeoffset]::TryParse(
                        $queryValues['fromDate'],
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        $continuationDateStyles,
                        [ref]$continuationFromUtc
                    ) -and $continuationFromUtc.UtcDateTime -eq $chunkFromDate
                    $toDateWasParsed = $queryValues.ContainsKey('toDate') -and [datetimeoffset]::TryParse(
                        $queryValues['toDate'],
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        $continuationDateStyles,
                        [ref]$continuationToUtc
                    )
                    $toDateIsValid = $toDateWasParsed -and
                        $continuationToUtc.UtcDateTime -lt $chunkToDate -and
                        $continuationToUtc.UtcDateTime -le $currentRequestToUtc
                    if ($toDateIsValid) {
                        if ($null -ne $oldestPageTimestampUtc) {
                            $toDateIsValid = $oldestPageTimestampUtc -gt [datetime]::MinValue -and
                                $continuationToUtc.UtcDateTime -eq $oldestPageTimestampUtc.AddTicks(-1)
                        }
                        else {
                            $toDateIsValid = $continuationToUtc.UtcDateTime -ge $chunkFromDate
                        }
                    }
                    $reportIdIsValid = $queryValues.ContainsKey('ReportIdForScrolling') -and
                        -not [string]::IsNullOrWhiteSpace($queryValues['ReportIdForScrolling'])
                    if (-not $fromDateIsValid -or -not $toDateIsValid -or -not $reportIdIsValid) {
                        $queryIsValid = $false
                    }

                    if (-not $previousReference.StartsWith('/', [System.StringComparison]::Ordinal) -or
                        $previousReference.StartsWith('//', [System.StringComparison]::Ordinal) -or
                        $previousReference.Contains('#') -or
                        $previousReference.Contains('\') -or
                        -not $previousPath.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase) -or
                        -not $queryIsValid) {
                        throw "Chunk $chunkIndex received an invalid pagination URI."
                    }
                    $continuationUri = "$($sharedParameters.BaseUrl)/apiproxy/mtp/mdeTimelineExperience$previousReference"
                    $requestUri = $continuationUri
                    $currentRequestToUtc = $continuationToUtc.UtcDateTime
                }

                $response = $null
            }

            $writer.Flush()
            $writer.Dispose()
            $writer = $null
            $hashingStream.FlushFinalBlock()
            $hashingStream.Dispose()
            $hashingStream = $null
            $fileStream.Flush($true)
            $fileStream.Dispose()
            $fileStream = $null

            $fileSha256 = [Convert]::ToHexString($fileHasher.Hash).ToLowerInvariant()
            $fileHasher.Dispose()
            $fileHasher = $null
            [System.IO.File]::Move($partialPath, $filePath, $true)
            $stopwatch.Stop()

            return [PSCustomObject]@{
                Success                = $true
                ChunkIndex             = $chunkIndex
                FromDate               = $chunkFromDate
                ToDate                 = $chunkToDate
                FilePath               = $filePath
                FileSha256             = $fileSha256
                FileBytes              = (Get-Item -LiteralPath $filePath).Length
                EventCount             = $eventCount
                PageCount              = $pageCount
                RetryCount             = $retryCount
                MissingTimestampCount  = $missingTimestampCount
                BoundaryTimestampCount = $boundaryTimestampCount
                ElapsedSeconds         = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
                Error                  = $null
                FailureClass           = $null
            }
        }
        catch {
            $errorText = if (-not [string]::IsNullOrWhiteSpace($failureMessage)) {
                $failureMessage
            }
            elseif ($_.Exception -and -not [string]::IsNullOrWhiteSpace($_.Exception.Message)) {
                $_.Exception.Message
            }
            else {
                "Chunk $chunkIndex endpoint timeline worker failed."
            }
            if (-not [string]::IsNullOrWhiteSpace($requestUri)) {
                $errorText = $errorText.Replace($requestUri, '[request URI redacted]')
            }
            $errorText = [regex]::Replace(
                $errorText,
                '(?i)(ReportIdForScrolling=)[^&\s"''<>]+',
                '$1[redacted]'
            )
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
                MissingTimestampCount  = $missingTimestampCount
                BoundaryTimestampCount = $boundaryTimestampCount
                ElapsedSeconds         = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
                Error                  = $errorText
                FailureClass           = $failureClass
            }
        }
        finally {
            if ($writer) { $writer.Dispose() }
            if ($hashingStream) { $hashingStream.Dispose() }
            if ($fileHasher) { $fileHasher.Dispose() }
            if ($fileStream) { $fileStream.Dispose() }
            if (Test-Path -LiteralPath $partialPath) {
                Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
            }
            [void]$statusMap.TryRemove($chunkIndex, [ref]$null)
        }
    }
}
