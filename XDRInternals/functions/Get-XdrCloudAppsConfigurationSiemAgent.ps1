function Get-XdrCloudAppsConfigurationSiemAgent {
    <#
    .SYNOPSIS
        Retrieves SIEM agents from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured SIEM agents from Microsoft Defender for Cloud Apps,
        including agent details and configuration. Optionally retrieves only the count
        of SIEM agents.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER CountOnly
        Returns only the count of SIEM agents instead of the full agent details.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSiemAgent
        Retrieves all Cloud Apps SIEM agents using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSiemAgent -CountOnly
        Retrieves only the count of Cloud Apps SIEM agents.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSiemAgent -Force
        Forces a fresh retrieval of all Cloud Apps SIEM agents, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationSiemAgent[]
        Returns an array of SIEM agent objects when CountOnly is not specified.

        System.Int32
        Returns the count of SIEM agents when CountOnly is specified.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$CountOnly,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($CountOnly) {
            $CacheKey = "XdrCloudAppsConfigurationSiemAgentCount"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps SIEM agent count"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps SIEM agent count cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/api/v1/agents/siem/count/"

            Write-Verbose "Retrieving Cloud Apps SIEM agent count"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps SIEM agent count: $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsConfigurationSiemAgent"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps SIEM agents"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps SIEM agents cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/api/v1/agents/siem/"

            Write-Verbose "Retrieving Cloud Apps SIEM agents"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationSiemAgent')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps SIEM agents: $_"
            }
        }
    }

    end {
    }
}
