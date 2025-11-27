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
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointConfigurationPurviewSharing" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointConfigurationPurviewSharing data"
            return $currentCacheValue.Value
        }
        elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointConfigurationPurviewSharing"
        }
        else {
            Write-Verbose "GetXdrEndpointConfigurationPurviewSharing cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/wdatpInternalApi/compliance/alertSharing/status"
        Write-Verbose "Retrieving XDR Purview Sharing configuration"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "GetXdrEndpointConfigurationPurviewSharing" -Value $result -TTLMinutes 30
        return $result
    }
    
    end {
    }
}
