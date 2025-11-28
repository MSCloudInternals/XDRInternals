function Get-XdrConfigurationAssetRuleManagement {
    <#
    .SYNOPSIS
        Retrieves asset rule management configuration from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the asset rule management configuration from the Microsoft Defender XDR portal,
        including device tagging rules, conditions, and actions.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationAssetRuleManagement
        Retrieves the asset rule management configuration using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationAssetRuleManagement -Force
        Forces a fresh retrieval of the asset rule management configuration, bypassing the cache.

    .OUTPUTS
        Array
        Returns the rules array containing asset rule management configuration.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrAssetRuleManagementConfiguration" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR asset rule management configuration"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrAssetRuleManagementConfiguration"
        } else {
            Write-Verbose "XDR asset rule management configuration cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/rulesengine/rules"
        Write-Verbose "Retrieving XDR asset rule management configuration"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            # Return only the rules property
            $assetRules = $result.rules

            Set-XdrCache -CacheKey "XdrAssetRuleManagementConfiguration" -Value $assetRules -TTLMinutes 30
            return $assetRules
        } catch {
            Write-Error "Failed to retrieve asset rule management configuration: $_"
        }
    }

    end {

    }
}
