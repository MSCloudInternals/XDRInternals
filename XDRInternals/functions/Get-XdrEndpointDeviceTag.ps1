function Get-XdrEndpointDeviceTag {
    <#
    .SYNOPSIS
        Retrieves all device tags from Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets a list of all device tags from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointDeviceTag
        Retrieves all device tags using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointDeviceTag -Force
        Forces a fresh retrieval of device tags, bypassing the cache.
    
    .OUTPUTS
        Array
        Returns an array of device tag strings.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointDeviceTags" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint Device Tags"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointDeviceTags"
        } else {
            Write-Verbose "XDR Endpoint Device Tags cache is missing or expired"
        }
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allMachinesTags"
        Write-Verbose "Retrieving XDR Endpoint Device Tags"
        $XdrEndpointDeviceTags = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        Set-XdrCache -CacheKey "XdrEndpointDeviceTags" -Value $XdrEndpointDeviceTags -TTLMinutes 30
        return $XdrEndpointDeviceTags
    }
    
    end {
        
    }
}