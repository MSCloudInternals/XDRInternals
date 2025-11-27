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
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointConfigurationPreviewFeature" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointConfigurationPreviewFeature data"
            return $currentCacheValue.Value
        }
        elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointConfigurationPreviewFeature"
        }
        else {
            Write-Verbose "GetXdrEndpointConfigurationPreviewFeature cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext"
        Write-Verbose "Retrieving XDR Preview Features configuration"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "GetXdrEndpointConfigurationPreviewFeature" -Value $result -TTLMinutes 30
        return $result
    }
    
    end {
    }
}
