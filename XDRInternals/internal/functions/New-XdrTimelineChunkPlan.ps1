function New-XdrTimelineChunkPlan {
    <#
    .SYNOPSIS
        Creates timeline date chunks for parallel retrieval.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory timeline chunk plan and does not mutate state')]
    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$FromDate,

        [Parameter(Mandatory)]
        [datetime]$ToDate,

        [ValidateRange(1, 10080)]
        [int]$ChunkHours = 0,

        [Parameter()]
        [ValidateRange(1, 604800)]
        [int]$ChunkMinutes = 0,

        [Parameter()]
        [ValidateRange(0, 10000)]
        [int]$TargetChunkCount,

        [Parameter()]
        [string]$Strategy = 'Fixed'
    )

    $fromUtc = $FromDate.ToUniversalTime()
    $toUtc = $ToDate.ToUniversalTime()

    if ($fromUtc -ge $toUtc) {
        throw 'FromDate must be before ToDate.'
    }

    if ($ChunkHours -le 0 -and $ChunkMinutes -le 0) {
        throw 'Either ChunkHours or ChunkMinutes must be specified.'
    }

    if ($ChunkHours -gt 0 -and $ChunkMinutes -gt 0) {
        throw 'Specify either ChunkHours or ChunkMinutes, not both.'
    }

    $effectiveChunkMinutes = if ($ChunkMinutes -gt 0) { $ChunkMinutes } else { $ChunkHours * 60 }
    $effectiveStrategy = $Strategy
    if ($TargetChunkCount -gt 0) {
        $totalMinutes = ($toUtc - $fromUtc).TotalMinutes
        $effectiveChunkMinutes = [math]::Max(1, [math]::Ceiling($totalMinutes / $TargetChunkCount))
        $effectiveStrategy = "TargetChunkCount:$TargetChunkCount"
    }

    $chunks = [System.Collections.Generic.List[object]]::new()
    $cursor = $fromUtc
    while ($cursor -lt $toUtc) {
        $chunkEnd = $cursor.AddMinutes($effectiveChunkMinutes)
        if ($chunkEnd -gt $toUtc) {
            $chunkEnd = $toUtc
        }

        if (($chunkEnd - $cursor).TotalSeconds -lt 1) {
            break
        }

        [void]$chunks.Add([PSCustomObject]@{
                Index      = $chunks.Count
                FromDate   = $cursor
                ToDate     = $chunkEnd
                ChunkHours   = [math]::Round($effectiveChunkMinutes / 60, 4)
                ChunkMinutes = $effectiveChunkMinutes
                Strategy   = $effectiveStrategy
            })

        $cursor = $chunkEnd
    }

    return $chunks.ToArray()
}
