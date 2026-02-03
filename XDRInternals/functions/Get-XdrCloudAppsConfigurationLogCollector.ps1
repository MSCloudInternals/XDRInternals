function Get-XdrCloudAppsConfigurationLogCollector {
    <#
    .SYNOPSIS
        Retrieves log collectors from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured log collectors from Microsoft Defender for Cloud Apps.
        Log collectors are used to automatically upload discovery logs from your network
        to Microsoft Defender for Cloud Apps for continuous cloud discovery analysis.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLogCollector
        Retrieves all log collectors using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLogCollector -Force
        Forces a fresh retrieval of all log collectors, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLogCollector | Where-Object { $_.status -eq 'Running' }
        Retrieves all log collectors and filters for those with Running status.

    .OUTPUTS
        XdrCloudAppsConfigurationLogCollector[]
        Returns an array of log collector objects containing configuration details.
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
        $CacheKey = "XdrCloudAppsConfigurationLogCollector"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps log collectors"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps log collectors cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/log_collectors/"

        Write-Verbose "Retrieving Cloud Apps log collectors"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationLogCollector')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps log collectors: $_"
        }
    }

    end {
    }
}
