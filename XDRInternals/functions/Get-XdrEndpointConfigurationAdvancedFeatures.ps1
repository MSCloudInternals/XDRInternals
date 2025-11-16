function Get-XdrEndpointConfigurationAdvancedFeatures {
    <#
    .SYNOPSIS
        Retrieves the advanced features configuration settings for Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets the raw advanced features settings from the Microsoft Defender XDR portal.
        This function includes caching support with a 15-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationAdvancedFeatures
        Retrieves the advanced features configuration using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationAdvancedFeatures -Force
        Forces a fresh retrieval of the advanced features configuration, bypassing the cache.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Advanced Features is plural by design')]
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Advanced Features configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetAdvancedFeaturesSetting" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
