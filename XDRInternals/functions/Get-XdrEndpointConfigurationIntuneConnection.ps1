function Get-XdrEndpointConfigurationIntuneConnection {
    <#
    .SYNOPSIS
        Retrieves the Intune connection status for Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets the Intune onboarding connection status from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationIntuneConnection
        Retrieves the Intune connection status using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationIntuneConnection -Force
        Forces a fresh retrieval of the Intune connection status, bypassing the cache.
    
    .OUTPUTS
        Object
        Returns the API response.
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
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointConfigurationIntuneConnection" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointConfigurationIntuneConnection data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointConfigurationIntuneConnection"
        } else {
            Write-Verbose "GetXdrEndpointConfigurationIntuneConnection cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/onboarding/intune/status"
            Write-Verbose "Retrieving XDR Intune Connection configuration"
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "GetXdrEndpointConfigurationIntuneConnection" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve Intune connection configuration: $_"
        }
    }
    
    end {
    }
}
