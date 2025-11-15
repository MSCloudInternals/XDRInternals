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
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Live Response configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/get_properties?useV2Api=true&useV3Api=true" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
