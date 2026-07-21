function Export-XdrEndpointDeviceTimeline {
    <#
    .SYNOPSIS
        Exports a Microsoft Defender XDR device timeline to NDJSON.

    .DESCRIPTION
        Exports a bounded device timeline through the Defender XDR portal timeline API.
        The requested UTC range is divided into four-hour intervals and downloaded by a
        background worker. Each completed interval is written as an atomic UTF-8 NDJSON
        part and recorded in a resumable manifest. Records without a parseable timestamp
        fail the export because they cannot be safely assigned to a single interval.

        The final file is assembled without parsing or reserializing completed parts. A
        failed run does not publish the final path and preserves validated parts for the
        next identical invocation. Successful runs remove temporary part files and retain
        only the NDJSON export and its compact manifest.

        This cmdlet is intended for large incident-response exports. Use
        Get-XdrEndpointDeviceTimeline for smaller, interactive in-memory retrieval.

    .PARAMETER DeviceId
        The 40-character Defender for Endpoint device identifier.

    .PARAMETER FromDate
        Inclusive beginning of the export range. The value is converted to UTC.

    .PARAMETER ToDate
        Exclusive end of the export range. The value is converted to UTC. A maximum range
        of 180 days is supported by the portal timeline experience.

    .PARAMETER Path
        Destination NDJSON file. The path must end in .ndjson.

    .PARAMETER IncludeSentinelEvents
        Includes Microsoft Sentinel events in the exported timeline.

    .PARAMETER Force
        Replaces an existing export and discards incompatible resumable state at Path.

    .EXAMPLE
        Export-XdrEndpointDeviceTimeline -DeviceId $deviceId -FromDate $from -ToDate $to -Path '.\timeline.ndjson'
        Exports the requested device timeline and returns a summary object.

    .EXAMPLE
        Export-XdrEndpointDeviceTimeline -DeviceId $deviceId -FromDate (Get-Date).AddDays(-90) -ToDate (Get-Date) -Path '.\timeline-90d.ndjson' -IncludeSentinelEvents
        Exports a 90-day device timeline including Sentinel events. If interrupted, running
        the same command again resumes from validated completed intervals.

    .OUTPUTS
        PSCustomObject
        Returns the output path, manifest path, event and page counts, file size and hash,
        elapsed time, and whether prior chunks were resumed.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40, 40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [datetime]$FromDate,

        [Parameter(Mandatory)]
        [datetime]$ToDate,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [switch]$IncludeSentinelEvents,

        [Parameter()]
        [switch]$Force
    )

    begin {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            throw 'Export-XdrEndpointDeviceTimeline requires PowerShell 7 or later.'
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

        if ($Force) {
            foreach ($staleFile in @($outputPath, $manifestPath, $manifestPartialPath, $outputPartialPath)) {
                if (Test-Path -LiteralPath $staleFile) {
                    Remove-Item -LiteralPath $staleFile -Force -ErrorAction Stop
                }
            }
            if (Test-Path -LiteralPath $partsPath) {
                Remove-Item -LiteralPath $partsPath -Recurse -Force -ErrorAction Stop
            }
        }
        elseif (Test-Path -LiteralPath $outputPath) {
            throw "Path '$outputPath' already exists. Use -Force to replace it."
        }

        if (Test-Path -LiteralPath $manifestPartialPath) {
            Remove-Item -LiteralPath $manifestPartialPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $outputPartialPath) {
            Remove-Item -LiteralPath $outputPartialPath -Force -ErrorAction SilentlyContinue
        }

        $writeManifest = {
            param($Manifest, $ManifestPath, $PartialPath)

            $Manifest.UpdatedUtc = [datetime]::UtcNow.ToString('o')
            $manifestJson = $Manifest | ConvertTo-Json -Depth 16
            [System.IO.File]::WriteAllText($PartialPath, $manifestJson, [System.Text.UTF8Encoding]::new($false))
            [System.IO.File]::Move($PartialPath, $ManifestPath, $true)
        }

        $chunkHours = 4
        # Larger pages reduce request pressure enough for bounded parallel pagination to
        # remain reliable while materially improving incident-response export speed.
        $pageSize = 1000
        $throttleLimit = 4
        $requestTimeoutSeconds = 120
        $maxRetries = 5
        $maxChunkRestarts = 2
        $maxPagesPerChunk = 10000
        $baseUrl = 'https://security.microsoft.com'
        $manifest = $null
        $resumedChunkCount = 0

        if (Test-Path -LiteralPath $manifestPath) {
            try {
                $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -Depth 16 -ErrorAction Stop
            }
            catch {
                throw "Manifest '$manifestPath' could not be read. Use -Force to start a new export. $($_.Exception.Message)"
            }

            $compatible =
                [int]$manifest.SchemaVersion -eq 1 -and
                [string]$manifest.DeviceId -eq $DeviceId -and
                ([datetime]$manifest.FromDateUtc).ToUniversalTime().Ticks -eq $rangeStart.Ticks -and
                ([datetime]$manifest.ToDateUtc).ToUniversalTime().Ticks -eq $rangeEnd.Ticks -and
                [bool]$manifest.IncludeSentinelEvents -eq $IncludeSentinelEvents.IsPresent -and
                [int]$manifest.ChunkHours -eq $chunkHours -and
                [int]$manifest.PageSize -eq $pageSize

            if (-not $compatible) {
                throw "Manifest '$manifestPath' does not match this request. Use -Force to discard it or choose another Path."
            }
        }
        else {
            $plannedChunks = @(New-XdrEndpointTimelineExportChunk -FromDate $rangeStart -ToDate $rangeEnd -ChunkHours $chunkHours)
            $manifestChunks = @(
                foreach ($plannedChunk in $plannedChunks) {
                    [ordered]@{
                        Index                  = $plannedChunk.Index
                        FromDateUtc            = $plannedChunk.FromDate.ToString('o')
                        ToDateUtc              = $plannedChunk.ToDate.ToString('o')
                        DurationTicks          = $plannedChunk.DurationTicks
                        FileName               = $plannedChunk.FileName
                        Status                 = 'Pending'
                        EventCount             = 0L
                        PageCount              = 0
                        RetryCount             = 0
                        AttemptCount           = 0
                        FileBytes              = 0L
                        FileSha256             = $null
                        MissingTimestampCount  = 0L
                        BoundaryTimestampCount = 0L
                        ElapsedSeconds         = 0.0
                        Error                  = $null
                    }
                }
            )
            $manifest = [ordered]@{
                SchemaVersion         = 1
                State                 = 'InProgress'
                DeviceId              = $DeviceId
                FromDateUtc           = $rangeStart.ToString('o')
                ToDateUtc             = $rangeEnd.ToString('o')
                IncludeSentinelEvents = $IncludeSentinelEvents.IsPresent
                ChunkHours            = $chunkHours
                PageSize              = $pageSize
                Ordering              = 'NewestTimeWindowFirst;ApiEventOrderPreserved'
                CreatedUtc            = [datetime]::UtcNow.ToString('o')
                UpdatedUtc            = [datetime]::UtcNow.ToString('o')
                Chunks                = $manifestChunks
                Summary               = $null
            }
        }

        New-Item -Path $partsPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

        foreach ($manifestChunk in @($manifest.Chunks)) {
            if ([string]$manifestChunk.Status -eq 'Completed') {
                $partPath = Join-Path $partsPath ([string]$manifestChunk.FileName)
                $partIsValid = Test-Path -LiteralPath $partPath -PathType Leaf
                if ($partIsValid) {
                    $partItem = Get-Item -LiteralPath $partPath
                    $partIsValid = $partItem.Length -eq [long]$manifestChunk.FileBytes
                }
                if ($partIsValid) {
                    $actualHash = (Get-FileHash -LiteralPath $partPath -Algorithm SHA256).Hash.ToLowerInvariant()
                    $partIsValid = $actualHash -eq [string]$manifestChunk.FileSha256
                }

                if ($partIsValid) {
                    $resumedChunkCount++
                }
                else {
                    if (Test-Path -LiteralPath $partPath) {
                        Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue
                    }
                    $manifestChunk.Status = 'Pending'
                    $manifestChunk.EventCount = 0L
                    $manifestChunk.PageCount = 0
                    $manifestChunk.RetryCount = 0
                    $manifestChunk.AttemptCount = 0
                    $manifestChunk.FileBytes = 0L
                    $manifestChunk.FileSha256 = $null
                    $manifestChunk.Error = 'Previously completed part failed resume validation and was scheduled again.'
                }
            }
            elseif ([string]$manifestChunk.Status -eq 'Failed') {
                $manifestChunk.Status = 'Pending'
                $manifestChunk.EventCount = 0L
                $manifestChunk.PageCount = 0
                $manifestChunk.RetryCount = 0
                $manifestChunk.AttemptCount = 0
                $manifestChunk.FileBytes = 0L
                $manifestChunk.FileSha256 = $null
                $manifestChunk.MissingTimestampCount = 0L
                $manifestChunk.BoundaryTimestampCount = 0L
                $manifestChunk.ElapsedSeconds = 0.0
                $manifestChunk.Error = $null
            }
        }

        $manifest.State = 'InProgress'
        & $writeManifest $manifest $manifestPath $manifestPartialPath

        $cookieData = @(
            foreach ($cookie in $script:session.Cookies.GetCookies([uri]$baseUrl)) {
                [PSCustomObject]@{
                    Name   = $cookie.Name
                    Value  = $cookie.Value
                    Domain = $cookie.Domain
                    Path   = $cookie.Path
                }
            }
        )
        $headersData = @{}
        foreach ($headerName in $script:headers.Keys) {
            $headersData[$headerName] = $script:headers[$headerName]
        }

        $sharedParameters = @{
            BaseUrl               = $baseUrl
            DeviceId              = $DeviceId
            IncludeSentinelEvents = $IncludeSentinelEvents.IsPresent
            PageSize              = $pageSize
            MaxRetries            = $maxRetries
            RequestTimeoutSeconds = $requestTimeoutSeconds
            MaxPagesPerChunk      = $maxPagesPerChunk
            PartsPath             = $partsPath
            CookieData            = $cookieData
            HeadersData           = $headersData
        }

        $pendingChunks = @(
            foreach ($manifestChunk in @($manifest.Chunks | Where-Object Status -eq 'Pending' | Sort-Object { [int]$_['Index'] })) {
                [PSCustomObject]@{
                    Index         = [int]$manifestChunk.Index
                    FromDate      = [datetime]$manifestChunk.FromDateUtc
                    ToDate        = [datetime]$manifestChunk.ToDateUtc
                    DurationTicks = [long]$manifestChunk.DurationTicks
                    FileName      = [string]$manifestChunk.FileName
                    Attempt       = [int]$manifestChunk.AttemptCount
                }
            }
        )

        $totalChunkCount = @($manifest.Chunks).Count
        $totalDurationTicks = [long](($manifest.Chunks | ForEach-Object { [long]$_.DurationTicks } | Measure-Object -Sum).Sum)
        $initialCompletedTicks = [long](($manifest.Chunks | Where-Object Status -eq 'Completed' | ForEach-Object { [long]$_.DurationTicks } | Measure-Object -Sum).Sum)
        $initialCompletedCount = @($manifest.Chunks | Where-Object Status -eq 'Completed').Count
        $initialCompletedEvents = [long](($manifest.Chunks | Where-Object Status -eq 'Completed' | ForEach-Object { [long]$_.EventCount } | Measure-Object -Sum).Sum)

        Write-Information "Endpoint timeline export: $totalChunkCount four-hour window(s), $resumedChunkCount resumed, throttle=$throttleLimit, output='$outputPath'." -InformationAction Continue

        $workerScript = New-XdrEndpointTimelineExportWorker
        $workerScriptText = $workerScript.ToString()
        $statusMap = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()
        $chunkQueue = [System.Collections.Generic.Queue[object]]::new()
        foreach ($pendingChunk in $pendingChunks) {
            $chunkQueue.Enqueue($pendingChunk)
        }

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $throttleLimit)
        $activeJobs = [System.Collections.Generic.List[object]]::new()
        $completedDuringRunTicks = 0L
        $completedDuringRunCount = 0
        $completedDuringRunEvents = 0L
        $failureResults = [System.Collections.Generic.List[object]]::new()
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
            return [PSCustomObject]@{
                PowerShell = $powerShell
                Handle     = $powerShell.BeginInvoke()
                Chunk      = $Chunk
            }
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
                        if (-not $result) {
                            throw "Chunk $($job.Chunk.Index) returned no result."
                        }
                    }
                    catch {
                        $result = [PSCustomObject]@{
                            Success                = $false
                            ChunkIndex             = [int]$job.Chunk.Index
                            EventCount             = 0L
                            PageCount              = 0
                            FileBytes              = 0L
                            FileSha256             = $null
                            MissingTimestampCount  = 0L
                            BoundaryTimestampCount = 0L
                            ElapsedSeconds         = 0.0
                            RetryCount             = 0
                            Error                  = $_.ToString()
                            FailureClass           = 'WorkerFailure'
                        }
                    }
                    finally {
                        $job.PowerShell.Dispose()
                        [void]$activeJobs.Remove($job)
                    }

                    $manifestChunk = @($manifest.Chunks | Where-Object { [int]$_.Index -eq [int]$result.ChunkIndex })[0]
                    $manifestChunk.RetryCount = [int]$manifestChunk.RetryCount + [int]$result.RetryCount
                    $manifestChunk.AttemptCount = [int]$job.Chunk.Attempt
                    $manifestChunk.ElapsedSeconds = [double]$manifestChunk.ElapsedSeconds + [double]$result.ElapsedSeconds

                    if ($result.Success) {
                        $manifestChunk.Status = 'Completed'
                        $manifestChunk.EventCount = [long]$result.EventCount
                        $manifestChunk.PageCount = [int]$result.PageCount
                        $manifestChunk.FileBytes = [long]$result.FileBytes
                        $manifestChunk.FileSha256 = $result.FileSha256
                        $manifestChunk.MissingTimestampCount = [long]$result.MissingTimestampCount
                        $manifestChunk.BoundaryTimestampCount = [long]$result.BoundaryTimestampCount
                        $manifestChunk.Error = $null
                        $completedDuringRunCount++
                        $completedDuringRunTicks += [long]$manifestChunk.DurationTicks
                        $completedDuringRunEvents += [long]$result.EventCount
                    }
                    elseif ([string]$result.FailureClass -in @('PartialResponse', 'TransientHttp', 'Transport') -and [int]$job.Chunk.Attempt -lt $maxChunkRestarts) {
                        $nextAttempt = [int]$job.Chunk.Attempt + 1
                        $manifestChunk.Status = 'Pending'
                        $manifestChunk.AttemptCount = $nextAttempt
                        $manifestChunk.EventCount = 0L
                        $manifestChunk.PageCount = 0
                        $manifestChunk.FileBytes = 0L
                        $manifestChunk.FileSha256 = $null
                        $manifestChunk.MissingTimestampCount = 0L
                        $manifestChunk.BoundaryTimestampCount = 0L
                        $manifestChunk.Error = $result.Error
                        $chunkQueue.Enqueue([PSCustomObject]@{
                            Index         = [int]$manifestChunk.Index
                            FromDate      = [datetime]$manifestChunk.FromDateUtc
                            ToDate        = [datetime]$manifestChunk.ToDateUtc
                            DurationTicks = [long]$manifestChunk.DurationTicks
                            FileName      = [string]$manifestChunk.FileName
                            Attempt       = $nextAttempt
                        })
                        Write-Information "Restarting endpoint timeline window $($manifestChunk.Index) with a fresh request context (attempt $($nextAttempt + 1)/$($maxChunkRestarts + 1)) after $($result.FailureClass)." -InformationAction Continue
                    }
                    else {
                        $manifestChunk.Status = 'Failed'
                        $manifestChunk.EventCount = [long]$result.EventCount
                        $manifestChunk.PageCount = [int]$result.PageCount
                        $manifestChunk.FileBytes = [long]$result.FileBytes
                        $manifestChunk.FileSha256 = $result.FileSha256
                        $manifestChunk.MissingTimestampCount = [long]$result.MissingTimestampCount
                        $manifestChunk.BoundaryTimestampCount = [long]$result.BoundaryTimestampCount
                        $manifestChunk.Error = $result.Error
                        $failureResults.Add($result)
                        $stopScheduling = $true
                    }

                    & $writeManifest $manifest $manifestPath $manifestPartialPath

                    if (-not $stopScheduling -and $chunkQueue.Count -gt 0) {
                        $activeJobs.Add((& $startChunkJob $chunkQueue.Dequeue()))
                    }
                }

                $now = [datetime]::UtcNow
                $progressIsDue = ($now - $lastProgressUpdate).TotalSeconds -ge 2
                $heartbeatIsDue = ($now - $lastHeartbeat).TotalSeconds -ge 30
                if ($progressIsDue -or $heartbeatIsDue) {
                    $completedTicks = $initialCompletedTicks + $completedDuringRunTicks
                    $completedCount = $initialCompletedCount + $completedDuringRunCount
                    $completedEvents = $initialCompletedEvents + $completedDuringRunEvents
                    $activeEvents = [long](($statusMap.Values | Measure-Object -Property Events -Sum).Sum)
                    $completedBytes = [long](($manifest.Chunks | Where-Object Status -eq 'Completed' | ForEach-Object { [long]$_.FileBytes } | Measure-Object -Sum).Sum)
                    $activeBytes = [long](($statusMap.Values | Measure-Object -Property Bytes -Sum).Sum)
                    $percentComplete = if ($totalDurationTicks -gt 0) { [math]::Min(100, [math]::Round(($completedTicks / $totalDurationTicks) * 100, 1)) } else { 100 }

                    if ($progressIsDue) {
                        $status = "Completed $completedCount/$totalChunkCount windows; events $($completedEvents + $activeEvents); written $([math]::Round(($completedBytes + $activeBytes) / 1MB, 1)) MiB; active $($activeJobs.Count); queued $($chunkQueue.Count)"
                        Write-Progress -Activity 'Exporting XDR endpoint device timeline' -Status $status -PercentComplete $percentComplete
                        $lastProgressUpdate = $now
                    }

                    if ($heartbeatIsDue) {
                        $etaText = 'estimating'
                        if ($completedDuringRunTicks -gt 0 -and $operationStopwatch.Elapsed.TotalSeconds -gt 0) {
                            $ticksPerSecond = $completedDuringRunTicks / $operationStopwatch.Elapsed.TotalSeconds
                            $remainingTicks = [math]::Max([long]0, $totalDurationTicks - $completedTicks)
                            $etaText = [timespan]::FromSeconds($remainingTicks / $ticksPerSecond).ToString('c')
                        }
                        Write-Information "Endpoint timeline heartbeat: $percentComplete% time coverage; windows $completedCount/$totalChunkCount; events $($completedEvents + $activeEvents); written $([math]::Round(($completedBytes + $activeBytes) / 1MB, 1)) MiB; active $($activeJobs.Count); queued $($chunkQueue.Count); elapsed $($operationStopwatch.Elapsed.ToString('c')); rough ETA $etaText." -InformationAction Continue
                        $lastHeartbeat = $now
                    }
                }

                if ($completedJobs.Count -eq 0) {
                    Start-Sleep -Milliseconds 200
                }
            }
        }
        catch {
            $capturedError = $_
        }
        finally {
            foreach ($job in @($activeJobs)) {
                try { $job.PowerShell.Stop() } catch { Write-Verbose "Could not stop chunk $($job.Chunk.Index): $_" }
                $job.PowerShell.Dispose()
            }
            $activeJobs.Clear()
            $runspacePool.Close()
            $runspacePool.Dispose()
            Write-Progress -Activity 'Exporting XDR endpoint device timeline' -Completed
        }

        if ($capturedError) {
            $manifest.State = 'Failed'
            $manifest.Summary = [ordered]@{ Error = $capturedError.ToString() }
            & $writeManifest $manifest $manifestPath $manifestPartialPath
            throw $capturedError
        }

        if ($failureResults.Count -gt 0) {
            $manifest.State = 'Failed'
            $manifest.Summary = [ordered]@{
                FailedChunkCount = $failureResults.Count
                Errors           = @($failureResults | ForEach-Object { "chunk $($_.ChunkIndex): $($_.Error)" })
            }
            & $writeManifest $manifest $manifestPath $manifestPartialPath
            $failureText = $manifest.Summary.Errors -join '; '
            throw "Endpoint timeline export failed. Completed parts were preserved for resume. $failureText"
        }

        if ($chunkQueue.Count -gt 0) {
            throw 'Endpoint timeline export stopped before all planned chunks were scheduled.'
        }

        $incompleteChunks = @($manifest.Chunks | Where-Object Status -ne 'Completed')
        if ($incompleteChunks.Count -gt 0) {
            throw "Endpoint timeline export has $($incompleteChunks.Count) incomplete chunk(s); the final file was not published."
        }

        $orderedParts = @(
            foreach ($manifestChunk in @($manifest.Chunks | Sort-Object { [int]$_['Index'] })) {
                [PSCustomObject]@{
                    FilePath    = Join-Path $partsPath ([string]$manifestChunk.FileName)
                    FileSha256 = [string]$manifestChunk.FileSha256
                    EventCount = [long]$manifestChunk.EventCount
                }
            }
        )

        $totalPartBytes = [long](($manifest.Chunks | ForEach-Object { [long]$_.FileBytes } | Measure-Object -Sum).Sum)
        $mergeSafetyMarginBytes = [long][math]::Max([long]64MB, [long][math]::Ceiling($totalPartBytes * 0.05))
        $requiredMergeBytes = $totalPartBytes + $mergeSafetyMarginBytes
        $outputDrive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($outputPath))
        if ($outputDrive.AvailableFreeSpace -lt $requiredMergeBytes) {
            $storageError = "Finalizing the endpoint timeline requires at least $([math]::Round($requiredMergeBytes / 1GB, 2)) GiB free on '$($outputDrive.Name)', but only $([math]::Round($outputDrive.AvailableFreeSpace / 1GB, 2)) GiB is available. Completed parts were preserved for resume."
            $manifest.State = 'Failed'
            $manifest.Summary = [ordered]@{ Error = $storageError }
            & $writeManifest $manifest $manifestPath $manifestPartialPath
            throw $storageError
        }

        $manifest.State = 'Finalizing'
        & $writeManifest $manifest $manifestPath $manifestPartialPath
        $mergeStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $mergeResult = Merge-XdrEndpointTimelineNdjsonPart -Part $orderedParts -DestinationPath $outputPartialPath
            [System.IO.File]::Move($outputPartialPath, $outputPath, $false)
        }
        catch {
            if (Test-Path -LiteralPath $outputPartialPath) {
                Remove-Item -LiteralPath $outputPartialPath -Force -ErrorAction SilentlyContinue
            }
            $manifest.State = 'Failed'
            $manifest.Summary = [ordered]@{ Error = "Final validation failed: $($_.Exception.Message)" }
            & $writeManifest $manifest $manifestPath $manifestPartialPath
            throw
        }
        finally {
            $mergeStopwatch.Stop()
        }

        $partsRetained = $false
        try {
            Remove-Item -LiteralPath $partsPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            $partsRetained = $true
            Write-Warning "The export completed, but temporary part files could not be removed from '$partsPath': $($_.Exception.Message)"
        }

        $operationStopwatch.Stop()
        $totalPages = [long](($manifest.Chunks | ForEach-Object { [long]$_.PageCount } | Measure-Object -Sum).Sum)
        $totalRetries = [long](($manifest.Chunks | ForEach-Object { [long]$_.RetryCount } | Measure-Object -Sum).Sum)
        $totalChunkRestarts = [long](($manifest.Chunks | ForEach-Object { [long]$_.AttemptCount } | Measure-Object -Sum).Sum)
        $missingTimestampCount = [long](($manifest.Chunks | ForEach-Object { [long]$_.MissingTimestampCount } | Measure-Object -Sum).Sum)
        $boundaryTimestampCount = [long](($manifest.Chunks | ForEach-Object { [long]$_.BoundaryTimestampCount } | Measure-Object -Sum).Sum)
        $manifest.State = 'Complete'
        $manifest.Summary = [ordered]@{
            OutputPath              = $outputPath
            EventCount              = [long]$mergeResult.EventCount
            PageCount               = $totalPages
            RetryCount              = $totalRetries
            ChunkRestartCount       = $totalChunkRestarts
            FileBytes               = [long]$mergeResult.FileBytes
            FileSha256              = [string]$mergeResult.FileSha256
            MissingTimestampCount   = $missingTimestampCount
            BoundaryTimestampCount  = $boundaryTimestampCount
            ResumedChunkCount       = $resumedChunkCount
            PartsRetained           = $partsRetained
            MergeSeconds            = [math]::Round($mergeStopwatch.Elapsed.TotalSeconds, 3)
            ElapsedSeconds          = [math]::Round($operationStopwatch.Elapsed.TotalSeconds, 3)
            CompletedUtc            = [datetime]::UtcNow.ToString('o')
        }
        & $writeManifest $manifest $manifestPath $manifestPartialPath

        Write-Information "Endpoint timeline export complete: $($mergeResult.EventCount) events, $totalChunkCount windows, $([math]::Round($mergeResult.FileBytes / 1MB, 2)) MiB, elapsed $($operationStopwatch.Elapsed.ToString('c'))." -InformationAction Continue

        return [PSCustomObject]@{
            OutputPath              = $outputPath
            ManifestPath            = $manifestPath
            TotalEvents             = [long]$mergeResult.EventCount
            TotalPages              = $totalPages
            TotalRetries            = $totalRetries
            TotalChunkRestarts      = $totalChunkRestarts
            TotalChunks             = $totalChunkCount
            ResumedChunks           = $resumedChunkCount
            FileBytes               = [long]$mergeResult.FileBytes
            FileSha256              = [string]$mergeResult.FileSha256
            MissingTimestampCount   = $missingTimestampCount
            BoundaryTimestampCount  = $boundaryTimestampCount
            MergeSeconds            = [math]::Round($mergeStopwatch.Elapsed.TotalSeconds, 3)
            ElapsedSeconds          = [math]::Round($operationStopwatch.Elapsed.TotalSeconds, 3)
            TemporaryPartsRetained  = $partsRetained
        }
    }
}
