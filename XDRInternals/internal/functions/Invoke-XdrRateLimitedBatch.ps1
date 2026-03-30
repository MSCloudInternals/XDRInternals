function Invoke-XdrRateLimitedBatch {
    <#
    .SYNOPSIS
        Executes a rate-limited batch of parallel work items.

    .DESCRIPTION
        Starts work items in batches, launching up to BatchSize items per minute while
        preserving the original item order in the returned results. Each item is executed
        in its own runspace using the supplied ItemScript.

    .PARAMETER Items
        The collection of work items to process.

    .PARAMETER OperationName
        A human-readable name for the operation used in warnings and verbose output.

    .PARAMETER ItemScript
        The scriptblock to run for each item. It receives -Item and -SharedParameters.

    .PARAMETER SharedParameters
        Shared values passed to every item invocation.

    .PARAMETER BatchSize
        The number of items to launch per batch. Defaults to 10.

    .PARAMETER MaxItems
        The maximum number of items allowed in a single invocation. Defaults to 50.

    .PARAMETER BatchDelaySeconds
        The delay between launching successive batches. Defaults to 60 seconds.

    .PARAMETER BatchStartedScript
        Optional scriptblock invoked on the main thread before each batch starts.
        Receives -BatchNumber, -TotalBatches, and -Items.

    .PARAMETER ItemCompletedScript
        Optional scriptblock invoked on the main thread each time an item completes.
        Receives -BatchNumber, -TotalBatches, and -Result.

    .EXAMPLE
        Invoke-XdrRateLimitedBatch -Items $items -OperationName 'Example' -ItemScript $worker
        Runs the supplied worker script against the items using the default 10-per-minute cadence.

    .OUTPUTS
        PSCustomObject[]
        Returns ordered result objects with Success, ItemIndex, Item, Result, and ErrorText properties.
    #>
    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Items,

        [Parameter(Mandatory = $true)]
        [string]$OperationName,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ItemScript,

        [Parameter()]
        [hashtable]$SharedParameters = @{},

        [Parameter()]
        [int]$BatchSize = 10,

        [Parameter()]
        [int]$MaxItems = 50,

        [Parameter()]
        [int]$BatchDelaySeconds = 60,

        [Parameter()]
        [scriptblock]$BatchStartedScript,

        [Parameter()]
        [scriptblock]$ItemCompletedScript
    )

    $allItems = @($Items)
    if ($allItems.Count -eq 0) {
        return [PSCustomObject[]]@()
    }

    if ($allItems.Count -gt $MaxItems) {
        throw "$OperationName supports a maximum of $MaxItems item(s) per invocation. Received $($allItems.Count)."
    }

    $totalBatches = [int][Math]::Ceiling($allItems.Count / $BatchSize)
    if ($totalBatches -gt 1) {
        $itemWord = if ($allItems.Count -eq 1) { 'item' } else { 'items' }
        $batchWord = if ($totalBatches -eq 1) { 'batch' } else { 'batches' }
        Write-Warning "$OperationName will process $($allItems.Count) $itemWord in $totalBatches minute(s) across $totalBatches $batchWord due to the API limit of $BatchSize per minute."
    }

    $workerScript = @'
param($item, $itemIndex, $itemScriptText, $sharedParameters)

$itemScript = [scriptblock]::Create($itemScriptText)

try {
    $result = & $itemScript -Item $item -SharedParameters $sharedParameters
    [PSCustomObject]@{
        Success   = $true
        ItemIndex = $itemIndex
        Item      = $item
        Result    = $result
        ErrorText = $null
    }
} catch {
    [PSCustomObject]@{
        Success   = $false
        ItemIndex = $itemIndex
        Item      = $item
        Result    = $null
        ErrorText = $_.ToString()
    }
}
'@

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $allItems.Count))
    $runspacePool.Open()

    $jobs = [System.Collections.Generic.List[object]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $itemScriptText = $ItemScript.ToString()

    try {
        for ($offset = 0; $offset -lt $allItems.Count; $offset += $BatchSize) {
            $batchNumber = [int]($offset / $BatchSize) + 1
            $batch = @($allItems | Select-Object -Skip $offset -First $BatchSize)

            Write-Verbose "Starting $OperationName batch $batchNumber of $totalBatches ($($batch.Count) item(s))"

            for ($i = 0; $i -lt $batch.Count; $i++) {
                $itemIndex = $offset + $i
                $powershell = [powershell]::Create()
                $powershell.RunspacePool = $runspacePool

                [void]$powershell.AddScript($workerScript)
                [void]$powershell.AddParameter('item', $batch[$i])
                [void]$powershell.AddParameter('itemIndex', $itemIndex)
                [void]$powershell.AddParameter('itemScriptText', $itemScriptText)
                [void]$powershell.AddParameter('sharedParameters', $SharedParameters)

                $jobs.Add([PSCustomObject]@{
                        PowerShell  = $powershell
                        Handle      = $powershell.BeginInvoke()
                        BatchNumber = $batchNumber
                    })
            }

            if ($BatchStartedScript) {
                try {
                    & $BatchStartedScript -BatchNumber $batchNumber -TotalBatches $totalBatches -Items $batch
                } catch {
                    Write-Verbose "BatchStartedScript failed for $OperationName batch ${batchNumber}: $_"
                }
            }

            if ($batchNumber -lt $totalBatches) {
                Write-Verbose "Waiting $BatchDelaySeconds second(s) before starting the next $OperationName batch"
                Start-Sleep -Seconds $BatchDelaySeconds
            }
        }

        while ($jobs.Count -gt 0) {
            $completedJobs = @($jobs | Where-Object { $_.Handle.IsCompleted })
            if ($completedJobs.Count -eq 0) {
                Start-Sleep -Milliseconds 250
                continue
            }

            foreach ($job in $completedJobs) {
                try {
                    $jobResult = $job.PowerShell.EndInvoke($job.Handle)
                    foreach ($result in @($jobResult)) {
                        [void]$results.Add($result)
                        if ($ItemCompletedScript) {
                            try {
                                & $ItemCompletedScript -BatchNumber $job.BatchNumber -TotalBatches $totalBatches -Result $result
                            } catch {
                                Write-Verbose "ItemCompletedScript failed for $OperationName batch $($job.BatchNumber): $_"
                            }
                        }
                    }
                } finally {
                    $job.PowerShell.Dispose()
                    [void]$jobs.Remove($job)
                }
            }
        }
    } finally {
        $runspacePool.Close()
        $runspacePool.Dispose()
    }

    return [PSCustomObject[]]@($results | Sort-Object -Property ItemIndex)
}