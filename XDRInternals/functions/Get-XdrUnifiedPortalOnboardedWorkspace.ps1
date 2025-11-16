function Get-XdrUnifiedPortalOnboardedWorkspace {
    <#
    .SYNOPSIS
        Retrieves onboarded Sentinel workspaces from Microsoft Defender Unified Portal.

    .DESCRIPTION
        Gets a list of onboarded Microsoft Sentinel workspaces from the Unified Portal API using MATP authentication.
        This function uses a separate API with different authentication than the standard XDR endpoints.
        The MATP token is cached with a 40-minute TTL to reduce authentication overhead.

    .PARAMETER Force
        Bypasses the token cache and forces a fresh token retrieval from the API.

    .EXAMPLE
        Get-XdrUnifiedPortalOnboardedWorkspace
        Retrieves the list of onboarded Sentinel workspaces using a cached token if available.

    .EXAMPLE
        Get-XdrUnifiedPortalOnboardedWorkspace -Force
        Forces a fresh token retrieval, bypassing the cache, and gets the onboarded workspaces.

    .OUTPUTS
        Object
        Returns the list of onboarded Sentinel workspaces from the API response.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrUnifiedPortalOnboardedWorkspacesToken" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached MATP token for Unified Portal API"
            $Token = $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing token cache"
            Clear-XdrCache -CacheKey "XdrUnifiedPortalOnboardedWorkspacesToken"
            Write-Verbose "Retrieving fresh MATP token for Unified Portal API"
        } else {
            Write-Verbose "MATP token cache is missing or expired"
            Write-Verbose "Retrieving MATP token for Unified Portal API"
        }

        $Token = Get-XdrToken -ResourceName MATP
        Set-XdrCache -CacheKey "XdrUnifiedPortalOnboardedWorkspacesToken" -Value $Token -TTLMinutes 40

        Write-Verbose "Building authorization header for `"https://securitycenter.microsoft.com/mtp`""
        $AuthorizationHeader = @{
            "Authorization" = "Bearer $($Token.Token)"
        }

        $Uri = "https://partnersgw.securitycenter.windows.com/api/mdgw/sentinel/workspaces"

        Write-Verbose "Retrieving onboarded Sentinel workspaces from $Uri"
        $result = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -Headers $AuthorizationHeader

        return $result
    }

    end {
    }
}
