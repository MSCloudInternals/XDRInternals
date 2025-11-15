function Get-XdrUnifiedPortalIsOnboarded {
    <#
    .SYNOPSIS
        Checks if the tenant is onboarded to Microsoft Defender Unified Portal.

    .DESCRIPTION
        Checks whether the current tenant is onboarded to the Unified Portal using MATP authentication.
        This function uses a separate API with different authentication than the standard XDR endpoints.
        The MATP token is cached with a 40-minute TTL to reduce authentication overhead.

    .PARAMETER Force
        Bypasses the token cache and forces a fresh token retrieval from the API.

    .EXAMPLE
        Get-XdrUnifiedPortalIsOnboarded
        Checks if the tenant is onboarded to the Unified Portal using a cached token if available.

    .EXAMPLE
        Get-XdrUnifiedPortalIsOnboarded -Force
        Forces a fresh token retrieval, bypassing the cache, and checks the onboarding status.

    .OUTPUTS
        Boolean
        Returns $true if the tenant is onboarded, $false otherwise.
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
        # Check cache for MATP token
        $currentCacheValue = Get-XdrCache -CacheKey "XdrUnifiedPortalIsOnboardedToken" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached MATP token for Unified Portal API"
            $Token = $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing token cache"
            Clear-XdrCache -CacheKey "XdrUnifiedPortalIsOnboardedToken"
            Write-Verbose "Retrieving fresh MATP token for Unified Portal API"
        } else {
            Write-Verbose "MATP token cache is missing or expired"
            Write-Verbose "Retrieving MATP token for Unified Portal API"
        }

        $Token = Get-XdrToken -ResourceName MATP
        Set-XdrCache -CacheKey "XdrUnifiedPortalIsOnboardedToken" -Value $Token -TTLMinutes 40

        Write-Verbose "Building authorization header for `"https://securitycenter.microsoft.com/mtp`""
        $AuthorizationHeader = @{
            "Authorization" = "Bearer $($Token.Token)"
        }

        $Uri = "https://partnersgw.securitycenter.windows.com/api/mdgw/sentinel/workspaces/isOnboarded"

        Write-Verbose "Checking Unified Portal onboarding status from $Uri"
        $result = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -Headers $AuthorizationHeader

        return $result
    }

    end {
    }
}