function Export-XdrIdentityUserTimeline {
    <#
    .SYNOPSIS
        Exports a Microsoft Defender for Identity user timeline to NDJSON.

    .DESCRIPTION
        Exports a bounded identity timeline through the Defender XDR portal API. The
        requested range is divided into fixed, newest-first intervals and written to
        resumable, hash-validated NDJSON parts. The final path is published only after
        every interval succeeds and the complete byte stream is independently verified.

        This cmdlet is intended for large incident-response collections. Use
        Get-XdrIdentityUserTimeline for smaller in-memory retrieval.

    .PARAMETER AadId
        The Entra object ID of the user.

    .PARAMETER Upn
        The user principal name of the user.

    .PARAMETER Sid
        The security identifier of the user.

    .PARAMETER RadiusUserId
        The Defender for Identity RADIUS user identifier.

    .PARAMETER FromDate
        Inclusive beginning of the export range. The value is converted to UTC.

    .PARAMETER ToDate
        Exclusive end of the export range. The value is converted to UTC.

    .PARAMETER Path
        Destination NDJSON file. The path must end in .ndjson.

    .PARAMETER Force
        Starts a replacement export when Path or incompatible resumable state exists.
        An existing final file remains available until the replacement is complete.

    .EXAMPLE
        Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $from -ToDate $to -Path '.\identity.ndjson'
        Exports the requested identity timeline and returns a compact summary.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'ByUpn')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByAadId')]
        [Alias('aad', 'ObjectId')]
        [string]$AadId,

        [Parameter(Mandatory, ParameterSetName = 'ByUpn')]
        [Alias('UserPrincipalName', 'Email')]
        [string]$Upn,

        [Parameter(Mandatory, ParameterSetName = 'BySid')]
        [string]$Sid,

        [Parameter(Mandatory, ParameterSetName = 'ByRadiusUserId')]
        [string]$RadiusUserId,

        [Parameter(Mandatory)]
        [datetime]$FromDate,

        [Parameter(Mandatory)]
        [datetime]$ToDate,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [switch]$Force
    )

    begin {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            throw 'Export-XdrIdentityUserTimeline requires PowerShell 7 or later.'
        }
        Update-XdrConnectionSettings
    }

    process {
        $operationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $rangeStart = $FromDate.ToUniversalTime()
        $rangeEnd = $ToDate.ToUniversalTime()
        if ($rangeStart -ge $rangeEnd) {
            throw 'FromDate must be before ToDate.'
        }
        if (($rangeEnd - $rangeStart).TotalDays -gt 180) {
            throw 'The time range between FromDate and ToDate cannot exceed 180 days.'
        }

        $selectorName = $PSCmdlet.ParameterSetName.Substring(2)
        $selectorValue = switch ($selectorName) {
            'AadId' { $AadId }
            'Upn' { $Upn }
            'Sid' { $Sid }
            'RadiusUserId' { $RadiusUserId }
        }
        try {
            $resolveParameters = @{ ErrorAction = 'Stop' }
            $resolveParameters[$selectorName] = $selectorValue
            $resolvedUser = Get-XdrIdentityUser @resolveParameters | Select-Object -First 1
        }
        catch {
            $selectorHint = if ($selectorName -eq 'Upn') {
                ' If the Defender user URL contains aad or sid values, retry with -AadId or -Sid; sending an unresolved UPN directly can return an empty timeline.'
            } else { '' }
            throw "Failed to resolve identity by $selectorName '$selectorValue': $($_.Exception.Message)$selectorHint"
        }
        if ($null -eq $resolvedUser) {
            throw "Could not resolve identity by $selectorName '$selectorValue'."
        }

        $userIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $resolvedUser
        if ($null -eq $userIdentifiers -or $userIdentifiers.Count -eq 0) {
            throw 'The resolved identity did not contain identifiers usable by the timeline API.'
        }

        $canonicalize = {
            param($Value)

            if ($Value -is [System.Collections.IDictionary]) {
                $ordered = [ordered]@{}
                foreach ($key in @($Value.Keys | Sort-Object)) {
                    $ordered[[string]$key] = & $canonicalize $Value[$key]
                }
                return $ordered
            }
            if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
                return @($Value | ForEach-Object { & $canonicalize $_ })
            }
            return $Value
        }
        $canonicalIdentifiers = & $canonicalize $userIdentifiers
        $identityJson = $canonicalIdentifiers | ConvertTo-Json -Depth 20 -Compress
        $identityFingerprint = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($identityJson))
        ).ToLowerInvariant()

        $outputPath = [System.IO.Path]::GetFullPath($Path)
        if ([System.IO.Path]::GetExtension($outputPath) -ine '.ndjson') {
            throw "Path '$Path' must use the .ndjson extension."
        }
        if (Test-Path -LiteralPath $outputPath -PathType Container) {
            throw "Path '$Path' resolves to a directory."
        }
        $outputDirectory = Split-Path -Parent $outputPath
        if (-not (Test-Path -LiteralPath $outputDirectory)) {
            New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        $manifestPath = "$outputPath.manifest.json"
        $manifestPartialPath = "$manifestPath.partial"
        $partsPath = "$outputPath.parts"
        $outputPartialPath = "$outputPath.partial"
        $writeManifest = {
            param($Manifest)

            $Manifest.UpdatedUtc = [datetime]::UtcNow.ToString('o')
            [System.IO.File]::WriteAllText(
                $manifestPartialPath,
                ($Manifest | ConvertTo-Json -Depth 20),
                [System.Text.UTF8Encoding]::new($false)
            )
            [System.IO.File]::Move($manifestPartialPath, $manifestPath, $true)
        }

        $chunkHours = 24
        $pageSize = 1000
        $paginationStrategy = 'TimestampKeysetV2'
        $throttleLimit = 8
        $requestTimeoutSeconds = 120
        $maxRetries = 5
        $maxChunkRestarts = 2
        $baseUrl = 'https://security.microsoft.com'
        $manifest = $null
        $resumedChunkCount = 0
        $existingOutputAtStart = Test-Path -LiteralPath $outputPath -PathType Leaf

        if ($Force) {
            foreach ($staleFile in @($manifestPath, $manifestPartialPath, $outputPartialPath)) {
                if (Test-Path -LiteralPath $staleFile) {
                    Remove-Item -LiteralPath $staleFile -Force -ErrorAction Stop
                }
            }
            if (Test-Path -LiteralPath $partsPath) {
                Remove-Item -LiteralPath $partsPath -Recurse -Force -ErrorAction Stop
            }
        }
        elseif (Test-Path -LiteralPath $manifestPath) {
            try {
                $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop |
                    ConvertFrom-Json -AsHashtable -Depth 20 -ErrorAction Stop
            }
            catch {
                throw "Manifest '$manifestPath' could not be read. Use -Force to start a new export. $($_.Exception.Message)"
            }
        }
        elseif ($existingOutputAtStart) {
            throw "Path '$outputPath' already exists without resumable state. Use -Force to replace it."
        }

        $compatible = $false
        if ($manifest) {
            $compatible =
                [int]$manifest.SchemaVersion -eq 2 -and
                [string]$manifest.IdentityFingerprint -eq $identityFingerprint -and
                ([datetime]$manifest.FromDateUtc).ToUniversalTime().Ticks -eq $rangeStart.Ticks -and
                ([datetime]$manifest.ToDateUtc).ToUniversalTime().Ticks -eq $rangeEnd.Ticks -and
                [int]$manifest.ChunkHours -eq $chunkHours -and
                [int]$manifest.PageSize -eq $pageSize -and
                [string]$manifest.PaginationStrategy -eq $paginationStrategy
            if (-not $compatible) {
                throw "Manifest '$manifestPath' does not match this request. Use -Force to discard it or choose another Path."
            }
        }

        if ($manifest -and [string]$manifest.State -in @('Publishing', 'Complete')) {
            $expectedBytes = [long]$manifest.Summary.FileBytes
            $expectedHash = [string]$manifest.Summary.FileSha256
            $validOutput = $false
            if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
                $validOutput = (Get-Item -LiteralPath $outputPath).Length -eq $expectedBytes
                if ($validOutput) {
                    $validOutput = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expectedHash
                }
            }

            if (-not $validOutput -and [string]$manifest.State -eq 'Publishing' -and
                (Test-Path -LiteralPath $outputPartialPath -PathType Leaf)) {
                $validPartial = (Get-Item -LiteralPath $outputPartialPath).Length -eq $expectedBytes
                if ($validPartial) {
                    $validPartial = (Get-FileHash -LiteralPath $outputPartialPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expectedHash
                }
                if ($validPartial) {
                    [System.IO.File]::Move($outputPartialPath, $outputPath, $true)
                    $validOutput = $true
                }
            }

            if ($validOutput) {
                $partsRetained = $false
                if (Test-Path -LiteralPath $partsPath) {
                    try { Remove-Item -LiteralPath $partsPath -Recurse -Force -ErrorAction Stop }
                    catch { $partsRetained = $true }
                }
                $manifest.State = 'Complete'
                $manifest.Summary.PartsRetained = $partsRetained
                & $writeManifest $manifest
                return [PSCustomObject]@{
                    OutputPath = $outputPath; ManifestPath = $manifestPath
                    TotalEvents = [long]$manifest.Summary.EventCount; TotalPages = [long]$manifest.Summary.PageCount
                    TotalRetries = [long]$manifest.Summary.RetryCount; TotalChunkRestarts = [long]$manifest.Summary.ChunkRestartCount
                    TotalPaginationRewinds = [long]$manifest.Summary.PaginationRewindCount
                    TotalChunks = @($manifest.Chunks).Count; ResumedChunks = @($manifest.Chunks).Count
                    FileBytes = $expectedBytes; FileSha256 = $expectedHash
                    MissingTimestampCount = [long]$manifest.Summary.MissingTimestampCount
                    BoundaryTimestampCount = [long]$manifest.Summary.BoundaryTimestampCount
                    DuplicateRepresentationCount = [long]$manifest.Summary.DuplicateRepresentationCount
                    MergeSeconds = [double]$manifest.Summary.MergeSeconds
                    ElapsedSeconds = [double]$manifest.Summary.ElapsedSeconds
                    TemporaryPartsRetained = $partsRetained
                }
            }
            if ([string]$manifest.State -eq 'Complete') {
                throw "Completed export '$outputPath' failed validation. Use -Force to replace it."
            }
            $manifest.State = 'InProgress'
            if (Test-Path -LiteralPath $outputPartialPath) {
                Remove-Item -LiteralPath $outputPartialPath -Force -ErrorAction SilentlyContinue
            }
        }

        if (-not $manifest) {
            $chunks = [System.Collections.Generic.List[object]]::new()
            $chunkEnd = $rangeEnd
            $index = 0
            while ($chunkEnd -gt $rangeStart) {
                $chunkStart = $chunkEnd.AddHours(-$chunkHours)
                if ($chunkStart -lt $rangeStart) { $chunkStart = $rangeStart }
                $chunks.Add([PSCustomObject]@{
                        Index = $index; FromDate = $chunkStart; ToDate = $chunkEnd
                        DurationTicks = ($chunkEnd - $chunkStart).Ticks
                        FileName = ('chunk_{0:D4}_{1:yyyyMMddTHHmmssfffZ}_{2:yyyyMMddTHHmmssfffZ}.ndjson' -f $index, $chunkStart, $chunkEnd)
                    })
                $index++
                $chunkEnd = $chunkStart
            }

            $manifestChunks = @(
                foreach ($plannedChunk in $chunks) {
                    [ordered]@{
                        Index = $plannedChunk.Index; FromDateUtc = $plannedChunk.FromDate.ToString('o')
                        ToDateUtc = $plannedChunk.ToDate.ToString('o'); DurationTicks = $plannedChunk.DurationTicks
                        FileName = $plannedChunk.FileName; Status = 'Pending'; EventCount = 0L; PageCount = 0
                        RetryCount = 0; RewindCount = 0; AttemptCount = 0; FileBytes = 0L; FileSha256 = $null
                        MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.0; Error = $null
                        DuplicateRepresentationCount = 0L
                    }
                }
            )
            $manifest = [ordered]@{
                SchemaVersion = 2; State = 'InProgress'; IdentityFingerprint = $identityFingerprint
                IdentitySelector = $selectorName; FromDateUtc = $rangeStart.ToString('o'); ToDateUtc = $rangeEnd.ToString('o')
                ChunkHours = $chunkHours; PageSize = $pageSize; PaginationStrategy = $paginationStrategy
                Ordering = 'NewestTimeWindowFirst;ApiTimestampDescending'; ReplaceExisting = $existingOutputAtStart
                CreatedUtc = [datetime]::UtcNow.ToString('o'); UpdatedUtc = [datetime]::UtcNow.ToString('o')
                Chunks = $manifestChunks; Summary = $null
            }
        }

        New-Item -Path $partsPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        foreach ($manifestChunk in @($manifest.Chunks)) {
            if ([string]$manifestChunk.Status -eq 'Completed') {
                $partPath = Join-Path $partsPath ([string]$manifestChunk.FileName)
                $validPart = Test-Path -LiteralPath $partPath -PathType Leaf
                if ($validPart) { $validPart = (Get-Item -LiteralPath $partPath).Length -eq [long]$manifestChunk.FileBytes }
                if ($validPart) {
                    $validPart = (Get-FileHash -LiteralPath $partPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$manifestChunk.FileSha256
                }
                if ($validPart) {
                    $resumedChunkCount++
                    continue
                }
                if (Test-Path -LiteralPath $partPath) { Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue }
            }

            $manifestChunk.Status = 'Pending'; $manifestChunk.EventCount = 0L; $manifestChunk.PageCount = 0
            $manifestChunk.RetryCount = 0; $manifestChunk.RewindCount = 0; $manifestChunk.AttemptCount = 0
            $manifestChunk.FileBytes = 0L; $manifestChunk.FileSha256 = $null; $manifestChunk.MissingTimestampCount = 0L
            $manifestChunk.BoundaryTimestampCount = 0L; $manifestChunk.ElapsedSeconds = 0.0; $manifestChunk.Error = $null
            $manifestChunk.DuplicateRepresentationCount = 0L
        }
        $manifest.State = 'InProgress'
        & $writeManifest $manifest

        $cookieData = @(
            foreach ($cookie in $script:session.Cookies.GetCookies([uri]$baseUrl)) {
                [PSCustomObject]@{ Name = $cookie.Name; Value = $cookie.Value; Domain = $cookie.Domain; Path = $cookie.Path }
            }
        )
        $identityHeaders = Get-XdrIdentityHeaders
        $headersData = @{}
        foreach ($headerName in $identityHeaders.Keys) { $headersData[$headerName] = $identityHeaders[$headerName] }

        $sharedParameters = @{
            BaseUrl = $baseUrl; UserIdentifiers = $userIdentifiers; PageSize = $pageSize
            MaxRetries = $maxRetries; RequestTimeoutSeconds = $requestTimeoutSeconds; PartsPath = $partsPath
            CookieData = $cookieData; HeadersData = $headersData
        }
        $pendingChunks = @(
            foreach ($manifestChunk in @($manifest.Chunks | Where-Object Status -eq 'Pending' | Sort-Object { [int]$_.Index })) {
                [PSCustomObject]@{
                    Index = [int]$manifestChunk.Index; FromDate = [datetime]$manifestChunk.FromDateUtc
                    ToDate = [datetime]$manifestChunk.ToDateUtc; DurationTicks = [long]$manifestChunk.DurationTicks
                    FileName = [string]$manifestChunk.FileName; Attempt = [int]$manifestChunk.AttemptCount
                }
            }
        )

        $totalChunkCount = @($manifest.Chunks).Count
        $totalDurationTicks = [long](($manifest.Chunks | ForEach-Object { [long]$_.DurationTicks } | Measure-Object -Sum).Sum)
        $initialCompletedTicks = [long](($manifest.Chunks | Where-Object Status -eq 'Completed' | ForEach-Object { [long]$_.DurationTicks } | Measure-Object -Sum).Sum)
        Write-Information "Identity timeline export: $totalChunkCount $chunkHours-hour window(s), $resumedChunkCount resumed, throttle=$throttleLimit, output='$outputPath'." -InformationAction Continue

        $workerScriptText = (New-XdrIdentityTimelineExportWorker).ToString()
        $statusMap = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()
        $chunkQueue = [System.Collections.Generic.Queue[object]]::new()
        foreach ($pendingChunk in $pendingChunks) { $chunkQueue.Enqueue($pendingChunk) }
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $throttleLimit)
        $activeJobs = [System.Collections.Generic.List[object]]::new()
        $failureResults = [System.Collections.Generic.List[object]]::new()
        $completedDuringRunTicks = 0L
        $lastProgressUpdate = [datetime]::MinValue
        $lastHeartbeat = [datetime]::UtcNow
        $stopScheduling = $false
        $capturedError = $null

        $startChunkJob = {
            param($Chunk)
            $powerShell = [powershell]::Create()
            $powerShell.RunspacePool = $runspacePool
            [void]$powerShell.AddScript($workerScriptText)
            [void]$powerShell.AddParameter('chunk', $Chunk)
            [void]$powerShell.AddParameter('sharedParameters', $sharedParameters)
            [void]$powerShell.AddParameter('statusMap', $statusMap)
            [PSCustomObject]@{ PowerShell = $powerShell; Handle = $powerShell.BeginInvoke(); Chunk = $Chunk }
        }

        try {
            $runspacePool.Open()
            while ($chunkQueue.Count -gt 0 -and $activeJobs.Count -lt $throttleLimit) {
                $activeJobs.Add((& $startChunkJob $chunkQueue.Dequeue()))
            }
            while ($activeJobs.Count -gt 0) {
                $completedJobs = @($activeJobs | Where-Object { $_.Handle.IsCompleted })
                foreach ($job in $completedJobs) {
                    try {
                        $jobOutput = @($job.PowerShell.EndInvoke($job.Handle))
                        $result = $jobOutput | Select-Object -Last 1
                        if (-not $result) { throw "Chunk $($job.Chunk.Index) returned no result." }
                    }
                    catch {
                        $result = [PSCustomObject]@{
                            Success = $false; ChunkIndex = [int]$job.Chunk.Index; EventCount = 0L; PageCount = 0
                            RetryCount = 0; RewindCount = 0; FileBytes = 0L; FileSha256 = $null
                            MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.0
                            DuplicateRepresentationCount = 0L
                            Error = $_.ToString(); FailureClass = 'WorkerFailure'
                        }
                    }
                    finally {
                        $job.PowerShell.Dispose()
                        [void]$activeJobs.Remove($job)
                    }

                    $manifestChunk = @($manifest.Chunks | Where-Object { [int]$_.Index -eq [int]$result.ChunkIndex })[0]
                    $manifestChunk.RetryCount = [int]$manifestChunk.RetryCount + [int]$result.RetryCount
                    $manifestChunk.RewindCount = [int]$manifestChunk.RewindCount + [int]$result.RewindCount
                    $manifestChunk.DuplicateRepresentationCount = [long]$manifestChunk.DuplicateRepresentationCount + [long]$result.DuplicateRepresentationCount
                    $manifestChunk.AttemptCount = [int]$job.Chunk.Attempt
                    $manifestChunk.ElapsedSeconds = [double]$manifestChunk.ElapsedSeconds + [double]$result.ElapsedSeconds

                    if ($result.Success) {
                        $manifestChunk.Status = 'Completed'; $manifestChunk.EventCount = [long]$result.EventCount
                        $manifestChunk.PageCount = [int]$result.PageCount; $manifestChunk.FileBytes = [long]$result.FileBytes
                        $manifestChunk.FileSha256 = [string]$result.FileSha256
                        $manifestChunk.MissingTimestampCount = [long]$result.MissingTimestampCount
                        $manifestChunk.BoundaryTimestampCount = [long]$result.BoundaryTimestampCount
                        $manifestChunk.Error = $null
                        $completedDuringRunTicks += [long]$manifestChunk.DurationTicks
                    }
                    elseif ([string]$result.FailureClass -in @('PartialResponse', 'TransientHttp', 'Transport', 'Protocol') -and
                        [int]$job.Chunk.Attempt -lt $maxChunkRestarts) {
                        $nextAttempt = [int]$job.Chunk.Attempt + 1
                        $manifestChunk.Status = 'Pending'; $manifestChunk.AttemptCount = $nextAttempt
                        $manifestChunk.EventCount = 0L; $manifestChunk.PageCount = 0; $manifestChunk.FileBytes = 0L
                        $manifestChunk.FileSha256 = $null; $manifestChunk.MissingTimestampCount = 0L
                        $manifestChunk.BoundaryTimestampCount = 0L; $manifestChunk.Error = $result.Error
                        $manifestChunk.DuplicateRepresentationCount = 0L
                        $chunkQueue.Enqueue([PSCustomObject]@{
                                Index = [int]$manifestChunk.Index; FromDate = [datetime]$manifestChunk.FromDateUtc
                                ToDate = [datetime]$manifestChunk.ToDateUtc; DurationTicks = [long]$manifestChunk.DurationTicks
                                FileName = [string]$manifestChunk.FileName; Attempt = $nextAttempt
                            })
                        Write-Information "Restarting identity timeline window $($manifestChunk.Index) with a fresh request context after $($result.FailureClass)." -InformationAction Continue
                    }
                    else {
                        $manifestChunk.Status = 'Failed'; $manifestChunk.Error = $result.Error
                        $failureResults.Add($result); $stopScheduling = $true
                    }
                    & $writeManifest $manifest

                    while (-not $stopScheduling -and $chunkQueue.Count -gt 0 -and $activeJobs.Count -lt $throttleLimit) {
                        $activeJobs.Add((& $startChunkJob $chunkQueue.Dequeue()))
                    }
                }

                $now = [datetime]::UtcNow
                if (($now - $lastProgressUpdate).TotalSeconds -ge 2) {
                    $completedTicks = $initialCompletedTicks + $completedDuringRunTicks
                    $percent = if ($totalDurationTicks -gt 0) { [math]::Min(100, [math]::Round(100 * $completedTicks / $totalDurationTicks, 1)) } else { 100 }
                    $completedCount = @($manifest.Chunks | Where-Object Status -eq 'Completed').Count
                    $activeEvents = [long](($statusMap.Values | ForEach-Object { [long]$_.Events } | Measure-Object -Sum).Sum)
                    Write-Progress -Activity 'Exporting XDR identity user timeline' -Status "Completed $completedCount/$totalChunkCount windows; active events $activeEvents" -PercentComplete $percent
                    $lastProgressUpdate = $now
                }
                if (($now - $lastHeartbeat).TotalSeconds -ge 30) {
                    $completedCount = @($manifest.Chunks | Where-Object Status -eq 'Completed').Count
                    Write-Information "Identity timeline heartbeat: windows $completedCount/$totalChunkCount; active $($activeJobs.Count); queued $($chunkQueue.Count); elapsed $($operationStopwatch.Elapsed.ToString('c'))." -InformationAction Continue
                    $lastHeartbeat = $now
                }
                if ($completedJobs.Count -eq 0) { Start-Sleep -Milliseconds 200 }
            }
        }
        catch { $capturedError = $_ }
        finally {
            foreach ($job in @($activeJobs)) {
                try { $job.PowerShell.Stop() } catch { Write-Verbose "Could not stop chunk $($job.Chunk.Index): $_" }
                $job.PowerShell.Dispose()
            }
            $activeJobs.Clear(); $runspacePool.Close(); $runspacePool.Dispose()
            Write-Progress -Activity 'Exporting XDR identity user timeline' -Completed
        }

        if ($capturedError) {
            $manifest.State = 'Failed'; $manifest.Summary = [ordered]@{ Error = $capturedError.ToString() }
            & $writeManifest $manifest
            throw $capturedError
        }
        if ($failureResults.Count -gt 0 -or $chunkQueue.Count -gt 0) {
            $manifest.State = 'Failed'
            $manifest.Summary = [ordered]@{
                FailedChunkCount = $failureResults.Count
                Errors = @($failureResults | ForEach-Object { "chunk $($_.ChunkIndex): $($_.Error)" })
            }
            & $writeManifest $manifest
            throw "Identity timeline export failed. Completed parts were preserved for resume. $($manifest.Summary.Errors -join '; ')"
        }
        if (@($manifest.Chunks | Where-Object Status -ne 'Completed').Count -gt 0) {
            throw 'Identity timeline export has incomplete windows; the final file was not published.'
        }

        $orderedParts = @(
            foreach ($manifestChunk in @($manifest.Chunks | Sort-Object { [int]$_.Index })) {
                [PSCustomObject]@{
                    FilePath = Join-Path $partsPath ([string]$manifestChunk.FileName)
                    FileSha256 = [string]$manifestChunk.FileSha256; EventCount = [long]$manifestChunk.EventCount
                }
            }
        )
        $totalPartBytes = [long](($manifest.Chunks | ForEach-Object { [long]$_.FileBytes } | Measure-Object -Sum).Sum)
        $requiredMergeBytes = $totalPartBytes + [long][math]::Max([long]64MB, [long][math]::Ceiling($totalPartBytes * 0.05))
        $outputDrive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($outputPath))
        if ($outputDrive.AvailableFreeSpace -lt $requiredMergeBytes) {
            $manifest.State = 'Failed'; $manifest.Summary = [ordered]@{ Error = 'Insufficient disk space to finalize the identity timeline export.' }
            & $writeManifest $manifest
            throw "Finalizing the identity timeline requires at least $([math]::Round($requiredMergeBytes / 1GB, 2)) GiB free. Completed parts were preserved for resume."
        }

        if (Test-Path -LiteralPath $outputPartialPath) { Remove-Item -LiteralPath $outputPartialPath -Force }
        $mergeStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $mergeResult = Merge-XdrTimelineNdjsonPart -Part $orderedParts -DestinationPath $outputPartialPath
        $mergeStopwatch.Stop()

        $totalPages = [long](($manifest.Chunks | ForEach-Object { [long]$_.PageCount } | Measure-Object -Sum).Sum)
        $totalRetries = [long](($manifest.Chunks | ForEach-Object { [long]$_.RetryCount } | Measure-Object -Sum).Sum)
        $totalRewinds = [long](($manifest.Chunks | ForEach-Object { [long]$_.RewindCount } | Measure-Object -Sum).Sum)
        $totalRestarts = [long](($manifest.Chunks | ForEach-Object { [long]$_.AttemptCount } | Measure-Object -Sum).Sum)
        $missingTimestampCount = [long](($manifest.Chunks | ForEach-Object { [long]$_.MissingTimestampCount } | Measure-Object -Sum).Sum)
        $boundaryTimestampCount = [long](($manifest.Chunks | ForEach-Object { [long]$_.BoundaryTimestampCount } | Measure-Object -Sum).Sum)
        $duplicateRepresentationCount = [long](($manifest.Chunks | ForEach-Object { [long]$_.DuplicateRepresentationCount } | Measure-Object -Sum).Sum)
        $operationStopwatch.Stop()
        $manifest.State = 'Publishing'
        $manifest.Summary = [ordered]@{
            OutputPath = $outputPath; EventCount = [long]$mergeResult.EventCount; PageCount = $totalPages
            RetryCount = $totalRetries; ChunkRestartCount = $totalRestarts; PaginationRewindCount = $totalRewinds
            FileBytes = [long]$mergeResult.FileBytes; FileSha256 = [string]$mergeResult.FileSha256
            MissingTimestampCount = $missingTimestampCount; BoundaryTimestampCount = $boundaryTimestampCount
            DuplicateRepresentationCount = $duplicateRepresentationCount
            ResumedChunkCount = $resumedChunkCount; PartsRetained = $true
            MergeSeconds = [math]::Round($mergeStopwatch.Elapsed.TotalSeconds, 3)
            ElapsedSeconds = [math]::Round($operationStopwatch.Elapsed.TotalSeconds, 3)
            CompletedUtc = [datetime]::UtcNow.ToString('o')
        }
        & $writeManifest $manifest
        [System.IO.File]::Move($outputPartialPath, $outputPath, $true)

        $partsRetained = $false
        try { Remove-Item -LiteralPath $partsPath -Recurse -Force -ErrorAction Stop }
        catch {
            $partsRetained = $true
            Write-Warning "The export completed, but temporary parts could not be removed from '$partsPath': $($_.Exception.Message)"
        }
        $manifest.State = 'Complete'; $manifest.Summary.PartsRetained = $partsRetained
        & $writeManifest $manifest

        Write-Information "Identity timeline export complete: $($mergeResult.EventCount) events, $totalChunkCount windows, $([math]::Round($mergeResult.FileBytes / 1MB, 2)) MiB." -InformationAction Continue
        [PSCustomObject]@{
            OutputPath = $outputPath; ManifestPath = $manifestPath; TotalEvents = [long]$mergeResult.EventCount
            TotalPages = $totalPages; TotalRetries = $totalRetries; TotalChunkRestarts = $totalRestarts
            TotalPaginationRewinds = $totalRewinds; TotalChunks = $totalChunkCount; ResumedChunks = $resumedChunkCount
            FileBytes = [long]$mergeResult.FileBytes; FileSha256 = [string]$mergeResult.FileSha256
            MissingTimestampCount = $missingTimestampCount; BoundaryTimestampCount = $boundaryTimestampCount
            DuplicateRepresentationCount = $duplicateRepresentationCount
            MergeSeconds = [math]::Round($mergeStopwatch.Elapsed.TotalSeconds, 3)
            ElapsedSeconds = [math]::Round($operationStopwatch.Elapsed.TotalSeconds, 3)
            TemporaryPartsRetained = $partsRetained
        }
    }
}
