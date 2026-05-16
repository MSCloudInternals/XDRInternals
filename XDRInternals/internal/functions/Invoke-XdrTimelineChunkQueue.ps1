function Invoke-XdrTimelineChunkQueue {
    <#
    .SYNOPSIS
        Runs timeline chunk workers with bounded PowerShell 7 concurrency.

    .DESCRIPTION
        Executes a worker scriptblock against each supplied chunk by using a
        shared runspace pool. The helper limits concurrency, tracks completion,
        records per-chunk failures, and stops queued or running work when the
        overall timeout is reached.

    .PARAMETER Chunks
        Ordered collection of timeline chunk descriptors to process.

    .PARAMETER WorkerScript
        Scriptblock invoked once per chunk. The script must accept Chunk and
        SharedParameters arguments and return one or more result objects.

    .PARAMETER SharedParameters
        Hashtable of read-only values passed to every worker invocation.

    .PARAMETER ThrottleLimit
        Maximum number of chunk workers to run at the same time.

    .PARAMETER TimeoutSeconds
        Maximum total runtime for the queue before active and queued chunks are
        marked as failed.

    .PARAMETER Activity
        Progress activity label displayed while chunks are running.

    .EXAMPLE
        $chunks = New-XdrTimelineChunkPlan -FromDate (Get-Date).AddHours(-2) -ToDate (Get-Date) -ChunkHours 1
        Invoke-XdrTimelineChunkQueue -Chunks $chunks -WorkerScript $worker -Activity 'Retrieving timeline'

        Runs the provided worker script against each generated chunk and returns
        the ordered chunk results.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'SharedParameters', Justification = 'Consumed inside the runspace job creation scriptblock')]
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Chunks,

        [Parameter(Mandatory)]
        [scriptblock]$WorkerScript,

        [Parameter()]
        [hashtable]$SharedParameters = @{},

        [Parameter()]
        [ValidateRange(1, 128)]
        [int]$ThrottleLimit = 8,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds = 3600,

        [Parameter()]
        [string]$Activity = 'Retrieving Timeline'
    )

    if ($PSVersionTable.PSVersion -lt [version]'7.4') {
        throw 'Timeline chunk queues require PowerShell 7.4 or later.'
    }

    $allChunks = @($Chunks)
    if ($allChunks.Count -eq 0) {
        return @()
    }

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [math]::Min($ThrottleLimit, $allChunks.Count))
    $runspacePool.Open()

    $chunkQueue = [System.Collections.Generic.Queue[object]]::new($allChunks)
    $activeJobs = [System.Collections.Generic.List[object]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $workerScriptText = $WorkerScript.ToString()
    $operationTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false

    $createJob = {
        param($Chunk)

        $powershell = [powershell]::Create()
        $powershell.RunspacePool = $runspacePool
        [void]$powershell.AddScript($workerScriptText)
        [void]$powershell.AddParameter('Chunk', $Chunk)
        [void]$powershell.AddParameter('SharedParameters', $SharedParameters)

        [PSCustomObject]@{
            PowerShell = $powershell
            Handle     = $powershell.BeginInvoke()
            Chunk      = $Chunk
            StartedUtc = [datetime]::UtcNow
        }
    }

    try {
        while ($chunkQueue.Count -gt 0 -and $activeJobs.Count -lt $ThrottleLimit) {
            [void]$activeJobs.Add((& $createJob $chunkQueue.Dequeue()))
        }

        while ($activeJobs.Count -gt 0) {
            if ($operationTimer.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                $timedOut = $true
                foreach ($job in @($activeJobs)) {
                    try {
                        $job.PowerShell.Stop()
                    }
                    catch {
                        Write-Verbose "Failed to stop timeline chunk runspace for chunk $($job.Chunk.Index): $($_.Exception.Message)"
                    }
                    [void]$results.Add([PSCustomObject]@{
                            ChunkIndex     = $job.Chunk.Index
                            FromDate       = $job.Chunk.FromDate
                            ToDate         = $job.Chunk.ToDate
                            Success        = $false
                            FailureClass   = 'Timeout'
                            Error          = "Chunk cancelled because $Activity timed out after $TimeoutSeconds seconds."
                            ElapsedSeconds = [math]::Round(([datetime]::UtcNow - $job.StartedUtc).TotalSeconds, 2)
                        })
                    $job.PowerShell.Dispose()
                    [void]$activeJobs.Remove($job)
                }

                while ($chunkQueue.Count -gt 0) {
                    $queuedChunk = $chunkQueue.Dequeue()
                    [void]$results.Add([PSCustomObject]@{
                            ChunkIndex     = $queuedChunk.Index
                            FromDate       = $queuedChunk.FromDate
                            ToDate         = $queuedChunk.ToDate
                            Success        = $false
                            FailureClass   = 'Timeout'
                            Error          = "Chunk was not started because $Activity timed out after $TimeoutSeconds seconds."
                            ElapsedSeconds = 0
                        })
                }
                break
            }

            $completedJobs = @($activeJobs | Where-Object { $_.Handle.IsCompleted })
            foreach ($job in $completedJobs) {
                try {
                    foreach ($result in @($job.PowerShell.EndInvoke($job.Handle))) {
                        [void]$results.Add($result)
                    }
                }
                catch {
                    [void]$results.Add([PSCustomObject]@{
                            ChunkIndex     = $job.Chunk.Index
                            FromDate       = $job.Chunk.FromDate
                            ToDate         = $job.Chunk.ToDate
                            Success        = $false
                            Error          = $_.ToString()
                            ElapsedSeconds = [math]::Round(([datetime]::UtcNow - $job.StartedUtc).TotalSeconds, 2)
                        })
                }
                finally {
                    $job.PowerShell.Dispose()
                    [void]$activeJobs.Remove($job)
                }

                if (-not $timedOut -and $chunkQueue.Count -gt 0) {
                    [void]$activeJobs.Add((& $createJob $chunkQueue.Dequeue()))
                }
            }

            $completedCount = $results.Count
            $percent = [math]::Min(99, [math]::Round(($completedCount / [math]::Max(1, $allChunks.Count)) * 100))
            Write-Progress -Activity $Activity -Status "Completed $completedCount of $($allChunks.Count) chunks (active: $($activeJobs.Count), queued: $($chunkQueue.Count))" -PercentComplete $percent

            if ($completedJobs.Count -eq 0) {
                Start-Sleep -Milliseconds 150
            }
        }
    }
    finally {
        Write-Progress -Activity $Activity -Completed
        $runspacePool.Close()
        $runspacePool.Dispose()
    }

    return @($results | Sort-Object ChunkIndex)
}
