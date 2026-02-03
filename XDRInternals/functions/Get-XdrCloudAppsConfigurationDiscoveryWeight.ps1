function Get-XdrCloudAppsConfigurationDiscoveryWeight {
    <#
    .SYNOPSIS
        Retrieves discovery weights from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured discovery weights from Microsoft Defender for Cloud Apps.
        Discovery weights define the relative importance of different risk factors
        used in cloud app risk scoring calculations.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryWeight
        Retrieves all discovery weights using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryWeight -Force
        Forces a fresh retrieval of all discovery weights, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryWeight | Format-Table
        Retrieves all discovery weights and displays them in a table format.

    .OUTPUTS
        XdrCloudAppsConfigurationDiscoveryWeight[]
        Returns discovery weight objects containing weight configuration details.
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
        $CacheKey = "XdrCloudAppsConfigurationDiscoveryWeight"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps discovery weights"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps discovery weights cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/weights/"

        Write-Verbose "Retrieving Cloud Apps discovery weights"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                # Handle both single object and array responses
                if ($result -is [array]) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryWeight')
                    }
                } else {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryWeight')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps discovery weights: $_"
        }
    }

    end {
    }
}
