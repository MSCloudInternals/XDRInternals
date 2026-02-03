function Get-XdrMtoTenantList {
    <#
    .SYNOPSIS
        Retrieves the list of accessible tenants from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the list of tenants that the current user has access to in the Microsoft Defender XDR portal,
        including tenant information such as name, tenant ID, environment, and access status.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrMtoTenantList
        Retrieves the list of accessible tenants using cached data if available.

    .EXAMPLE
        Get-XdrMtoTenantList -Force
        Forces a fresh retrieval of the tenant list, bypassing the cache.

    .EXAMPLE
        Get-XdrMtoTenantList | Where-Object { $_.selected }
        Retrieves the currently selected tenant.

    .EXAMPLE
        Get-XdrMtoTenantList | Where-Object { -not $_.lostAccess }
        Retrieves only tenants where access has not been lost.

    .OUTPUTS
        Object[]
        Returns an array of tenant information objects with properties:
        - selected: Whether this is the currently selected tenant
        - lostAccess: Whether access to this tenant has been lost
        - name: The display name of the tenant
        - tenantId: The Azure AD tenant ID (GUID)
        - tenantAadEnvironment: The AAD environment type (1 = Public Cloud)
        - addedOn: The date when the tenant was added (if available)
        Also returns responseTypes object with B2B and GDAP status
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Tenants is plural by design')]
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }
    process {
        $currentCacheValue = Get-XdrCache -CacheKey "XdrTenants" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Tenants"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrTenants"
        } else {
            Write-Verbose "XDR Tenants cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Tenants"
        try {
            # Add mtoproxyurl header
            $customHeaders = $script:headers.Clone()
            $customHeaders['mtoproxyurl'] = "MTO"
            Write-Verbose "Added mtoproxyurl header: MTO"
            $XdrTenants = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtoapi/tenants/TenantPicker" -ContentType "application/json" -WebSession $script:session -Headers $customHeaders | Select-Object -ExpandProperty tenantInfoList
            Set-XdrCache -CacheKey "XdrTenants" -Value $XdrTenants -TTLMinutes 30
            # Reset web session to avoid issues with custom headers in subsequent calls
            Set-XdrConnectionSettings -ResetWebSession
            return $XdrTenants
        } catch {
            throw "Failed to retrieve XDR Tenants: $($_.Exception.Message)"
        }
    }

    end {
    }
}
