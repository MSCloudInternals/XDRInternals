function Merge-XdrTimelineNdjsonPart {
    <#
    .SYNOPSIS
        Concatenates validated timeline NDJSON part files.

    .DESCRIPTION
        Copies part files into one destination without parsing JSON. Each part hash is
        verified while it is copied, and the final SHA-256 hash is calculated in the same pass.

    .PARAMETER Part
        Ordered part metadata containing FilePath, FileSha256, and EventCount.

    .PARAMETER DestinationPath
        Path to create. The destination must not already exist.

    .EXAMPLE
        Merge-XdrTimelineNdjsonPart -Part $parts -DestinationPath $partialPath
        Creates and hashes the combined NDJSON file.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]$Part,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    if (Test-Path -LiteralPath $DestinationPath) {
        throw "DestinationPath '$DestinationPath' already exists."
    }

    $destination = $null
    $outputHasher = $null
    $hashingDestination = $null
    $totalEvents = 0L

    try {
        $destination = [System.IO.FileStream]::new(
            $DestinationPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            1MB,
            [System.IO.FileOptions]::SequentialScan
        )
        $outputHasher = [System.Security.Cryptography.SHA256]::Create()
        $hashingDestination = [System.Security.Cryptography.CryptoStream]::new(
            $destination,
            $outputHasher,
            [System.Security.Cryptography.CryptoStreamMode]::Write,
            $true
        )

        foreach ($partItem in $Part) {
            $source = $null
            $partHasher = $null
            $hashingSource = $null
            try {
                $source = [System.IO.FileStream]::new(
                    [string]$partItem.FilePath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read,
                    1MB,
                    [System.IO.FileOptions]::SequentialScan
                )
                $partHasher = [System.Security.Cryptography.SHA256]::Create()
                $hashingSource = [System.Security.Cryptography.CryptoStream]::new(
                    $source,
                    $partHasher,
                    [System.Security.Cryptography.CryptoStreamMode]::Read,
                    $true
                )
                $hashingSource.CopyTo($hashingDestination, 1MB)
            }
            finally {
                if ($hashingSource) { $hashingSource.Dispose() }
                if ($source) { $source.Dispose() }
            }

            $actualPartHash = [Convert]::ToHexString($partHasher.Hash).ToLowerInvariant()
            $partHasher.Dispose()
            if ($actualPartHash -ne [string]$partItem.FileSha256) {
                throw "Timeline part '$($partItem.FilePath)' failed SHA-256 validation."
            }

            $totalEvents += [long]$partItem.EventCount
        }

        $hashingDestination.FlushFinalBlock()
        $hashingDestination.Dispose()
        $hashingDestination = $null
        $destination.Flush($true)
        $destination.Dispose()
        $destination = $null

        return [PSCustomObject]@{
            FilePath    = $DestinationPath
            FileSha256 = [Convert]::ToHexString($outputHasher.Hash).ToLowerInvariant()
            FileBytes   = (Get-Item -LiteralPath $DestinationPath).Length
            EventCount = $totalEvents
        }
    }
    finally {
        if ($hashingDestination) { $hashingDestination.Dispose() }
        if ($outputHasher) { $outputHasher.Dispose() }
        if ($destination) { $destination.Dispose() }
    }
}

function Merge-XdrEndpointTimelineNdjsonPart {
    <#
    .SYNOPSIS
        Preserves the endpoint-specific private helper name.

    .DESCRIPTION
        Calls the workload-neutral timeline merger so the endpoint exporter keeps
        its original private helper contract.

    .PARAMETER Part
        Ordered endpoint timeline part metadata to validate and concatenate.

    .PARAMETER DestinationPath
        Path to the new combined NDJSON file.

    .EXAMPLE
        Merge-XdrEndpointTimelineNdjsonPart -Part $parts -DestinationPath $partialPath
        Validates and merges endpoint timeline parts.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]$Part,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    Merge-XdrTimelineNdjsonPart -Part $Part -DestinationPath $DestinationPath
}
