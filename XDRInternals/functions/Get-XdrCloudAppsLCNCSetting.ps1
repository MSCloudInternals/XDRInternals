function Get-XdrCloudAppsLCNCSetting {
    <#
    .SYNOPSIS
        Retrieves low-code/no-code settings from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the low-code/no-code (LCNC) settings configured in Microsoft Defender
        for Cloud Apps. These settings control how the platform handles low-code
        and no-code applications discovered in the environment.
        This function includes caching support with a 5-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsLCNCSetting
        Retrieves the current LCNC settings using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsLCNCSetting -Force
        Forces a fresh retrieval of LCNC settings, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsLCNCSetting -Verbose
        Retrieves LCNC settings with verbose output showing cache status.

    .OUTPUTS
        XdrCloudAppsLCNCSetting
        Returns an object containing low-code/no-code configuration settings.
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
        $CacheKey = "XdrCloudAppsLCNCSetting"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps LCNC settings"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps LCNC settings cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/lcnc_settings/"

        Write-Verbose "Retrieving Cloud Apps LCNC settings"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsLCNCSetting')
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps LCNC settings: $_"
        }
    }

    end {
    }
}
