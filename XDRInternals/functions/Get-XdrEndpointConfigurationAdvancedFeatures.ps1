function Get-XdrEndpointConfigurationAdvancedFeatures {
    <#
    .SYNOPSIS
        Retrieves the advanced features configuration settings for Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets the raw advanced features settings from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationAdvancedFeatures
        Retrieves the advanced features configuration using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationAdvancedFeatures -Force
        Forces a fresh retrieval of the advanced features configuration, bypassing the cache.
    
    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Advanced Features is plural by design')]
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointConfigurationAdvancedFeatures" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointConfigurationAdvancedFeatures data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointConfigurationAdvancedFeatures"
        } else {
            Write-Verbose "GetXdrEndpointConfigurationAdvancedFeatures cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/settings/GetAdvancedFeaturesSetting"
        Write-Verbose "Retrieving GetXdrEndpointConfigurationAdvancedFeatures data"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "GetXdrEndpointConfigurationAdvancedFeatures" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve endpoint advanced features configuration: $_"
        }
    }
    
    end {
    }
}
