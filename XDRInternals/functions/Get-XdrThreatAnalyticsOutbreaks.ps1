function Get-XdrThreatAnalyticsOutbreaks {
    <#
    .SYNOPSIS
        Retrieves threat analytics outbreaks from Microsoft Defender XDR.

    .DESCRIPTION
        Gets threat analytics outbreaks data from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.

        By default, retrieves the full outbreaks list. Use -ChangeCount or -TopThreats
        switches to retrieve specific outbreak metrics from dedicated endpoints.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .PARAMETER ChangeCount
        Returns the outbreak change count information using the dedicated /changeCount endpoint.
        This provides metrics about changes in outbreak data over time.

    .PARAMETER TopThreats
        Returns the top threats from outbreaks using the dedicated /topThreats endpoint.
        This provides a prioritized list of the most significant threats.

    .EXAMPLE
        Get-XdrThreatAnalyticsOutbreaks
        Retrieves threat analytics outbreaks using cached data if available.

    .EXAMPLE
        Get-XdrThreatAnalyticsOutbreaks -Force
        Forces a fresh retrieval of threat analytics outbreaks, bypassing the cache.

    .EXAMPLE
        Get-XdrThreatAnalyticsOutbreaks -ChangeCount
        Retrieves the outbreak change count metrics from the dedicated endpoint.

    .EXAMPLE
        Get-XdrThreatAnalyticsOutbreaks -TopThreats
        Retrieves the top threats from outbreaks, prioritized by significance.

    .EXAMPLE
        Get-XdrThreatAnalyticsOutbreaks -TopThreats -Force
        Forces a fresh retrieval of top threats, bypassing the cache.

    .OUTPUTS
        Object
        Returns the threat analytics outbreaks data, change count, or top threats depending on parameters.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter()]
        [switch]$Force,

        [Parameter(ParameterSetName = 'ChangeCount')]
        [switch]$ChangeCount,

        [Parameter(ParameterSetName = 'TopThreats')]
        [switch]$TopThreats
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Handle ChangeCount parameter - use dedicated changeCount endpoint
        if ($ChangeCount) {
            $cacheKey = "XdrThreatAnalyticsOutbreaksChangeCount"
            $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue

            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached outbreak change count"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $cacheKey
            } else {
                Write-Verbose "Outbreak change count cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mtp/threatAnalytics/outbreaks/changeCount"
            Write-Verbose "Retrieving outbreak change count"
            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
                return $result
            } catch {
                Write-Error "Failed to retrieve outbreak change count: $_"
                return
            }
        }

        # Handle TopThreats parameter - use dedicated topThreats endpoint
        if ($TopThreats) {
            $cacheKey = "XdrThreatAnalyticsOutbreaksTopThreats"
            $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue

            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached threat analytics top threats"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $cacheKey
            } else {
                Write-Verbose "Threat analytics top threats cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mtp/threatAnalytics/outbreaks/topThreats"
            Write-Verbose "Retrieving threat analytics top threats"
            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
                return $result
            } catch {
                Write-Error "Failed to retrieve threat analytics top threats: $_"
                return
            }
        }

        # Default behavior - retrieve full outbreaks list
        $currentCacheValue = Get-XdrCache -CacheKey "XdrThreatAnalyticsOutbreaks" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached threat analytics outbreaks"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrThreatAnalyticsOutbreaks"
        } else {
            Write-Verbose "Threat analytics outbreaks cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/threatAnalytics/outbreaks"
        Write-Verbose "Retrieving threat analytics outbreaks"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrThreatAnalyticsOutbreaks" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve threat analytics outbreaks: $_"
        }
    }

    end {

    }
}
