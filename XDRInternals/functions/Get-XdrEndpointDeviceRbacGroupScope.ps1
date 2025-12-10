function Get-XdrEndpointDeviceRbacGroupScope {
    <#
    .SYNOPSIS
        Retrieves all RBAC groups from Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets a list of all Role-Based Access Control (RBAC) device groups from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointDeviceRbacGroupScope
        Retrieves all RBAC groups using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointDeviceRbacGroupScope -Force
        Forces a fresh retrieval of RBAC groups, bypassing the cache.
    
    .OUTPUTS
        Array
        Returns an array of RBAC group objects.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointDeviceRbacGroupScope" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint device RBAC groups"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointDeviceRbacGroupScope"
        } else {
            Write-Verbose "XDR Endpoint device RBAC groups cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/userExposedRbacGroups/UserExposedRbacGroups"
            Write-Verbose "Retrieving XDR Endpoint device RBAC groups"
            $XdrEndpointDeviceRbacGroupScope = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointDeviceRbacGroupScope" -Value $XdrEndpointDeviceRbacGroupScope -TTLMinutes 30
            return $XdrEndpointDeviceRbacGroupScope
        } catch {
            Write-Error "Failed to retrieve endpoint device RBAC groups: $_"
        }
    }
    
    end {
    }
}