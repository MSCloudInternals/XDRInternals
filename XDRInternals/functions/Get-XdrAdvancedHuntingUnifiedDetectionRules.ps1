function Get-XdrAdvancedHuntingUnifiedDetectionRules {
    <#
    .SYNOPSIS
        Retrieves the Unified Detection Rules from Advanced Hunting.

    .DESCRIPTION
        Retrieves the Unified Detection Rules from Advanced Hunting.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrAdvancedHuntingUnifiedDetectionRules
        Retrieves the Unified Detection Rules from Advanced Hunting.

    .EXAMPLE
        Get-XdrAdvancedHuntingUnifiedDetectionRules -Force
        Forces a fresh retrieval, bypassing the cache.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Returns all rules, so is plural by design')]
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrAdvancedHuntingUnifiedDetectionRules" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Get-XdrAdvancedHuntingUnifiedDetectionRules data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrAdvancedHuntingUnifiedDetectionRules"
        } else {
            Write-Verbose "Get-XdrAdvancedHuntingUnifiedDetectionRules cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/rules/unified?pageIndex=1&pageSize=10000&sortOrder=Ascending&isUnifiedRulesListEnabled=true"
        Write-Verbose "Retrieving Get-XdrAdvancedHuntingUnifiedDetectionRules data"
        
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "GetXdrAdvancedHuntingUnifiedDetectionRules" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}