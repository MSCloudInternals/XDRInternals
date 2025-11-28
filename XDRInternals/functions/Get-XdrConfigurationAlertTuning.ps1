function Get-XdrConfigurationAlertTuning {
    <#
    .SYNOPSIS
        Retrieves alert tuning configuration from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the alert suppression rules configuration from the Microsoft Defender XDR portal,
        including alert tuning rules and their conditions.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationAlertTuning
        Retrieves the alert tuning configuration using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationAlertTuning -Force
        Forces a fresh retrieval of the alert tuning configuration, bypassing the cache.

    .OUTPUTS
        Object
        Returns the alert suppression rules configuration.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrConfigurationAlertTuning" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR alert tuning configuration"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrConfigurationAlertTuning"
        } else {
            Write-Verbose "XDR alert tuning configuration cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/suppressionRulesService/suppressionRules"
        Write-Verbose "Retrieving XDR alert tuning configuration"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrConfigurationAlertTuning" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve alert tuning configuration: $_"
        }
    }

    end {

    }
}
