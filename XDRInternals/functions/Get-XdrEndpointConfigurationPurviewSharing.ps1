function Get-XdrEndpointConfigurationPurviewSharing {
    <#
    .SYNOPSIS
        Retrieves the Purview alert sharing configuration for Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets the Purview alert sharing status and configuration from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPurviewSharing
        Retrieves the Purview sharing configuration using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPurviewSharing -Force
        Forces a fresh retrieval of the Purview sharing configuration, bypassing the cache.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Purview Sharing configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/wdatpInternalApi/compliance/alertSharing/status" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
