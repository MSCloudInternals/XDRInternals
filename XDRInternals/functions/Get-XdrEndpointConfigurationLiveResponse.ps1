function Get-XdrEndpointConfigurationLiveResponse {
    <#
    .SYNOPSIS
        Retrieves the Live Response configuration settings for Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets the Live Response configuration settings from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationLiveResponse
        Retrieves the Live Response configuration using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationLiveResponse -Force
        Forces a fresh retrieval of the Live Response configuration, bypassing the cache.
    
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
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointConfigurationLiveResponse" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointConfigurationLiveResponse data"
            return $currentCacheValue.Value
        }
        elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointConfigurationLiveResponse"
        }
        else {
            Write-Verbose "GetXdrEndpointConfigurationLiveResponse cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/get_properties?useV2Api=true&useV3Api=true"
        Write-Verbose "Retrieving XDR Live Response configuration"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "GetXdrEndpointConfigurationLiveResponse" -Value $result -TTLMinutes 30
        return $result
    }
    
    end {
    }
}
