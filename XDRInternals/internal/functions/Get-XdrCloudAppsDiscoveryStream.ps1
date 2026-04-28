function Get-XdrCloudAppsDiscoveryStream {
    <#
    .SYNOPSIS
        Internal function to get discovery streams by ID, name pattern, or return all streams.

    .DESCRIPTION
        Gets discovery streams for use by grouped Cloud Apps discovery commands.
        Supports explicit StreamId, wildcard StreamName matching, or returning all streams when neither
        is specified.

    .PARAMETER StreamId
        Explicit stream ID to use. If specified, validates the stream exists.

    .PARAMETER StreamName
        Stream name pattern supporting wildcards. If specified, returns matching streams.

    .PARAMETER Force
        Forces refresh of the streams cache.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveryStream
        Returns all available discovery streams.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveryStream -StreamId "12345678901234567890"
        Returns the stream with the specified ID.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveryStream -StreamName "Defender*"
        Returns all streams whose display name matches the wildcard pattern.

    .OUTPUTS
        Returns an array of stream objects, each containing _id and displayName properties.
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter()]
        [string]$StreamId,

        [Parameter()]
        [string]$StreamName,

        [Parameter()]
        [switch]$Force
    )

    $allStreams = Invoke-XdrCloudAppsRequest `
        -Path '/mcas/cas/api/discovery/streams/' `
        -TypeName 'XdrCloudAppsConfigurationDiscoveryStream' `
        -DataProperty 'streams' `
        -CacheKey 'XdrCloudAppsConfigurationDiscoveryStream' `
        -TTLMinutes 15 `
        -Force:$Force

    if (-not $allStreams) {
        Write-Error "No discovery streams found. Ensure Cloud Discovery is configured in your tenant."
        return @()
    }

    # If explicit StreamId provided, validate and return it
    if ($PSBoundParameters.ContainsKey('StreamId') -and $StreamId) {
        $stream = $allStreams | Where-Object { $_._id -eq $StreamId }
        if (-not $stream) {
            $availableStreams = ($allStreams | ForEach-Object { "$($_.displayName) ($_._id)" }) -join ', '
            Write-Error "Stream ID '$StreamId' not found. Available streams: $availableStreams"
            return @()
        }
        return @($stream)
    }

    # If StreamName provided, filter by name pattern (supports wildcards)
    if ($PSBoundParameters.ContainsKey('StreamName') -and $StreamName) {
        $matchingStreams = $allStreams | Where-Object { $_.displayName -like $StreamName }
        if (-not $matchingStreams) {
            $availableNames = ($allStreams | ForEach-Object { $_.displayName }) -join ', '
            Write-Error "No streams found matching '$StreamName'. Available streams: $availableNames"
            return @()
        }
        return @($matchingStreams)
    }

    # Return all streams
    return @($allStreams)
}
