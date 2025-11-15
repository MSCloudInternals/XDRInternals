function Get-XdrServiceInfo {
    <#
    .SYNOPSIS
        Retrieves service information from Microsoft Defender for Endpoint API.

    .DESCRIPTION
        Gets service information from the MTP service info API endpoint using MATP authentication.
        This function uses a separate API with different authentication than the standard XDR endpoints.
        The MATP token is cached with a 40-minute TTL to reduce authentication overhead.

    .PARAMETER Force
        Bypasses the token cache and forces a fresh token retrieval from the API.

    .EXAMPLE
        Get-XdrServiceInfo
        Retrieves the current service information from Microsoft Defender for Endpoint using a cached token if available.

    .EXAMPLE
        Get-XdrServiceInfo -Force
        Forces a fresh token retrieval, bypassing the cache, and gets the service information.

    .OUTPUTS
        Object
        Returns the service information object from the API response.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrServiceInfoToken" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached MATP token for service info API"
            $Token = $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing token cache"
            Clear-XdrCache -CacheKey "XdrServiceInfoToken"
            Write-Verbose "Retrieving fresh MATP token for service info API"
        } else {
            Write-Verbose "MATP token cache is missing or expired"
            Write-Verbose "Retrieving MATP token for service info API"
        }

        $Token = Get-XdrToken -ResourceName MATP
        Set-XdrCache -CacheKey "XdrServiceInfoToken" -Value $Token -TTLMinutes 40

        Write-Verbose "Building authorization header for `"https://securitycenter.microsoft.com/mtp`""
        $AuthorizationHeader = @{
            "Authorization" = "Bearer $($Token.Token)"
        }

        $Uri = "https://api.security.microsoft.com/mtpserviceinfo"

        Write-Verbose "Retrieving XDR service information from $Uri"
        $result = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -Headers $AuthorizationHeader

        return $result
    }

    end {
    }
}
