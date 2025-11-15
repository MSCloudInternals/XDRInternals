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
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Intune Connection configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/onboarding/intune/status" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
