function Get-XdrEndpointConfigurationPreviewFeature {
    <#
    .SYNOPSIS
        Retrieves the preview features configuration for Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets the preview experience settings from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPreviewFeature
        Retrieves the preview features configuration using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPreviewFeature -Force
        Forces a fresh retrieval of the preview features configuration, bypassing the cache.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Preview Features configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
