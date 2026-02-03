function Get-XdrCloudAppsConfigurationDiscoveryStream {
    <#
    .SYNOPSIS
        Retrieves discovery streams from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured discovery streams from Microsoft Defender for Cloud Apps.
        Discovery streams represent the data flow pipelines for cloud app discovery,
        containing traffic log data from various sources.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryStream
        Retrieves all discovery streams using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryStream -Force
        Forces a fresh retrieval of all discovery streams, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryStream | Select-Object name, streamType
        Retrieves all discovery streams and displays name and stream type.

    .OUTPUTS
        XdrCloudAppsConfigurationDiscoveryStream[]
        Returns an array of discovery stream objects containing stream configuration details.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConfigurationDiscoveryStream"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps discovery streams"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps discovery streams cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/discovery/streams/"

        Write-Verbose "Retrieving Cloud Apps discovery streams"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.streams) { $response.streams } elseif ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryStream')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps discovery streams: $_"
        }
    }

    end {
    }
}
