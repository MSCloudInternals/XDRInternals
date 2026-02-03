function Get-XdrCloudAppsConfigurationDiscoveryDataSource {
    <#
    .SYNOPSIS
        Retrieves discovery data sources from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured discovery data sources from Microsoft Defender for Cloud Apps.
        Data sources define where cloud discovery traffic logs are collected from,
        such as firewalls, proxies, or other network appliances.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryDataSource
        Retrieves all discovery data sources using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryDataSource -Force
        Forces a fresh retrieval of all discovery data sources, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryDataSource | Where-Object { $_.enabled -eq $true }
        Retrieves all data sources and filters for enabled ones.

    .OUTPUTS
        XdrCloudAppsConfigurationDiscoveryDataSource[]
        Returns an array of discovery data source objects containing configuration details.
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
        $CacheKey = "XdrCloudAppsConfigurationDiscoveryDataSource"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps discovery data sources"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps discovery data sources cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/data_sources/?performAsyncTotal=false"

        Write-Verbose "Retrieving Cloud Apps discovery data sources"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryDataSource')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps discovery data sources: $_"
        }
    }

    end {
    }
}
