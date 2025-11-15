function Get-XdrConfigurationCriticalAssetManagement {
    <#
    .SYNOPSIS
        Retrieves critical asset management configuration from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the critical asset management rules from the Microsoft Defender XDR portal,
        including asset classification rules and conditions.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER RuleType
        Filters rules by type. Valid values are "Predefined" and "CreatedByUser".
        If not specified, all rules are returned.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagement
        Retrieves all critical asset management rules using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagement -RuleType Predefined
        Retrieves only predefined critical asset management rules.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagement -RuleType CreatedByUser
        Retrieves only user-created critical asset management rules.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagement -Force
        Forces a fresh retrieval of the critical asset management configuration, bypassing the cache.

    .OUTPUTS
        Array
        Returns the rules array containing critical asset management configuration.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('Predefined', 'CreatedByUser')]
        [string]$RuleType,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $currentCacheValue = Get-XdrCache -CacheKey "XdrConfigurationCriticalAssetManagement" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR critical asset management configuration"

            # Filter by RuleType if specified
            if ($PSBoundParameters.ContainsKey('RuleType')) {
                Write-Verbose "Filtering rules by RuleType: $RuleType"
                $criticalAssetRules = $currentCacheValue.Value | Where-Object { $_.ruleType -eq $RuleType }
            }
            return $criticalAssetRules
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrConfigurationCriticalAssetManagement"
        } else {
            Write-Verbose "XDR critical asset management configuration cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/assetrules"
        Write-Verbose "Retrieving XDR critical asset management configuration"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        # Return only the rules property
        $criticalAssetRules = $result.rules

        Set-XdrCache -CacheKey "XdrConfigurationCriticalAssetManagement" -Value $criticalAssetRules -TTLMinutes 30

        # Filter by RuleType if specified
        if ($PSBoundParameters.ContainsKey('RuleType')) {
            Write-Verbose "Filtering rules by RuleType: $RuleType"
            $criticalAssetRules = $criticalAssetRules | Where-Object { $_.ruleType -eq $RuleType }
        }
        return $criticalAssetRules
    }

    end {

    }
}
