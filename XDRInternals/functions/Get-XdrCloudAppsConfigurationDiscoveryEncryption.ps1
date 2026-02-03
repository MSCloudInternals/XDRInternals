function Get-XdrCloudAppsConfigurationDiscoveryEncryption {
    <#
    .SYNOPSIS
        Retrieves discovery encryption settings from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured discovery encryption settings from Microsoft Defender for Cloud Apps.
        Encryption settings control how sensitive data in discovery reports is encrypted
        and protected during transmission and storage.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryEncryption
        Retrieves the discovery encryption settings using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryEncryption -Force
        Forces a fresh retrieval of the discovery encryption settings, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationDiscoveryEncryption
        Returns the discovery encryption settings object containing encryption configuration details.
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
        $CacheKey = "XdrCloudAppsConfigurationDiscoveryEncryption"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps discovery encryption settings"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps discovery encryption settings cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/get_encryption_settings/"

        Write-Verbose "Retrieving Cloud Apps discovery encryption settings"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                # Handle both single object and array responses
                if ($result -is [array]) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryEncryption')
                    }
                } else {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryEncryption')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps discovery encryption settings: $_"
        }
    }

    end {
    }
}
