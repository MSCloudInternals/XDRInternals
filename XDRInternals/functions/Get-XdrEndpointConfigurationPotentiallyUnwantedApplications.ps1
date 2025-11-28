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
    
    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Potentially Unwanted Applications is plural by design')]
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointConfigurationPotentiallyUnwantedApplications" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointConfigurationPotentiallyUnwantedApplications data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointConfigurationPotentiallyUnwantedApplications"
        } else {
            Write-Verbose "GetXdrEndpointConfigurationPotentiallyUnwantedApplications cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/autoIr/ui/properties/"
            Write-Verbose "Retrieving XDR Potentially Unwanted Applications configuration"
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            Set-XdrCache -CacheKey "GetXdrEndpointConfigurationPotentiallyUnwantedApplications" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve Potentially Unwanted Applications configuration: $_"
        }
    }
    
    end {
    }
}
