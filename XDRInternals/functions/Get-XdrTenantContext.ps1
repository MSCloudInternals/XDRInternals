function Get-XdrTenantContext {
    <#
    .SYNOPSIS
        Retrieves the tenant context information from Microsoft Defender XDR.
    
    .DESCRIPTION
        Gets the tenant context information from the Microsoft Defender XDR portal,
        including tenant settings and configuration details.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrTenantContext
        Retrieves the tenant context using cached data if available.
    
    .EXAMPLE
        Get-XdrTenantContext -Force
        Forces a fresh retrieval of the tenant context, bypassing the cache.
    
    .OUTPUTS
        Object
        Returns the tenant context configuration object.
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
        try {
            $currentCacheValue = Get-XdrCache -CacheKey "XdrTenantContext" -ErrorAction SilentlyContinue
        } catch {
            $currentCacheValue = $null
        }
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Tenant Context"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrTenantContext"
        } else {
            Write-Verbose "XDR Tenant Context cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Tenant Context"
        try {
            $XdrTenantContext = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext?realTime=true" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrTenantContext" -Value $XdrTenantContext -TTLMinutes 30
            return $XdrTenantContext
        } catch {
            throw "Failed to retrieve XDR Tenant Context: $($_.Exception.Message)"
        }
    }
    
    end {
    }
}
