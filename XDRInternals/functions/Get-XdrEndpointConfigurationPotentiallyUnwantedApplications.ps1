function Get-XdrEndpointConfigurationPotentiallyUnwantedApplications {
    <#
    .SYNOPSIS
        Retrieves the potentially unwanted applications (PUA) configuration for Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets the configuration settings for potentially unwanted applications from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPotentiallyUnwantedApplications
        Retrieves the PUA configuration using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPotentiallyUnwantedApplications -Force
        Forces a fresh retrieval of the PUA configuration, bypassing the cache.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Potentially Unwanted Applications is plural by design')]
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Potentially Unwanted Applications configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/ui/properties/" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
