function Get-XdrIdentityStatistic {
    <#
    .SYNOPSIS
        Retrieves aggregated identity statistics from Microsoft Defender for Identity.

    .DESCRIPTION
        Gets aggregated identity data and statistics from Microsoft Defender for Identity,
        including counts and metrics across all identities.
        This function includes caching support with a 10-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityStatistic
        Retrieves identity statistics using cached data if available.

    .EXAMPLE
        Get-XdrIdentityStatistic -Force
        Forces a fresh retrieval of identity statistics, bypassing the cache.

    .OUTPUTS
        Object
        Returns aggregated identity statistics.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityStatistic" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR identity statistics"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityStatistic"
        } else {
            Write-Verbose "XDR identity statistics cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/identities/aggregatedData"
        Write-Verbose "Retrieving XDR identity statistics"
        
        # POST with empty body
        $body = @{}
        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "XdrIdentityStatistic" -Value $result -TTLMinutes 10
        return $result
    }

    end {

    }
}
