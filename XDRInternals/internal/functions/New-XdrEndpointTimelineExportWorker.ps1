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
        $failureClass = 'Protocol'

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
                                throw "Chunk $chunkIndex received a partial API response after $attempt attempt(s): $($partialReasons -join '; ')"
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
                        $delaySeconds = [math]::Min(30, [math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 0 -Maximum 3))
                        Start-Sleep -Seconds $delaySeconds
                    }
                }

                $pageCount++

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
                    $continuationUri = "$($sharedParameters.BaseUrl)/apiproxy/mtp/mdeTimelineExperience$($response.Prev)"
                    $parsedContinuationUri = [uri]$continuationUri
                    if ($parsedContinuationUri.Host -ne ([uri]$sharedParameters.BaseUrl).Host -or
                        -not $parsedContinuationUri.AbsolutePath.StartsWith('/apiproxy/mtp/mdeTimelineExperience/', [System.StringComparison]::Ordinal)) {
                        throw "Chunk $chunkIndex received an invalid pagination URI."
                    }
                    $requestUri = $continuationUri
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
            $errorText = $_.ToString()
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
