function Get-XdrEndpointDeviceVendor {
    <#
    .SYNOPSIS
        Retrieves all device vendors from Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets a list of all device hardware vendors from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointDeviceVendor
        Retrieves all device vendors using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointDeviceVendor -Force
        Forces a fresh retrieval of device vendors, bypassing the cache.
    
    .OUTPUTS
        Array
        Returns an array of device vendor names.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointDeviceVendors" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint device vendors"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointDeviceVendors"
        } else {
            Write-Verbose "XDR Endpoint device vendors cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allVendors"
            Write-Verbose "Retrieving XDR Endpoint device vendors"
            $XdrEndpointDeviceVendors = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointDeviceVendors" -Value $XdrEndpointDeviceVendors -TTLMinutes 30
            return $XdrEndpointDeviceVendors
        } catch {
            Write-Error "Failed to retrieve endpoint device vendors: $_"
        }
    }
    
    end {
        
    }
}