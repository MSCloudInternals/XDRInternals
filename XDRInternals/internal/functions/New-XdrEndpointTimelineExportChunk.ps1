function New-XdrEndpointTimelineExportChunk {
    <#
    .SYNOPSIS
        Creates newest-first time chunks for an endpoint timeline export.

    .DESCRIPTION
        Creates adjacent, non-overlapping UTC intervals. Chunks are ordered newest first
        so concatenating their API-ordered NDJSON files preserves descending time windows.

    .PARAMETER FromDate
        Inclusive start of the export range.

    .PARAMETER ToDate
        Exclusive end of the export range.

    .PARAMETER ChunkHours
        Size of each chunk in hours.

    .EXAMPLE
        New-XdrEndpointTimelineExportChunk -FromDate $from -ToDate $to -ChunkHours 4
        Creates four-hour export chunks.
    #>
    [OutputType([PSCustomObject[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private planner that only returns in-memory chunk descriptors.')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [datetime]$FromDate,

        [Parameter(Mandatory)]
        [datetime]$ToDate,

        [Parameter()]
        [ValidateRange(1, 24)]
        [int]$ChunkHours = 4
    )

    $rangeStart = $FromDate.ToUniversalTime()
    $rangeEnd = $ToDate.ToUniversalTime()
    if ($rangeStart -ge $rangeEnd) {
        throw 'FromDate must be before ToDate.'
    }

    $chunks = [System.Collections.Generic.List[object]]::new()
    $chunkEnd = $rangeEnd
    $index = 0

    while ($chunkEnd -gt $rangeStart) {
        $chunkStart = $chunkEnd.AddHours(-$ChunkHours)
        if ($chunkStart -lt $rangeStart) {
            $chunkStart = $rangeStart
        }

        $chunks.Add([PSCustomObject]@{
                Index         = $index
                FromDate      = $chunkStart
                ToDate        = $chunkEnd
                DurationTicks = ($chunkEnd - $chunkStart).Ticks
                FileName      = ('chunk_{0:D4}_{1:yyyyMMddTHHmmssfffZ}_{2:yyyyMMddTHHmmssfffZ}.ndjson' -f $index, $chunkStart, $chunkEnd)
            })

        $index++
        $chunkEnd = $chunkStart
    }

    return [PSCustomObject[]]$chunks.ToArray()
}
