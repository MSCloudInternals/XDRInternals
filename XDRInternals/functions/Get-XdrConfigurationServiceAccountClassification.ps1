function Get-XdrConfigurationServiceAccountClassification {
    <#
    .SYNOPSIS
        Retrieves service account classification rules from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the service account classification rules from the Microsoft Defender XDR portal,
        including rules for identifying and classifying service accounts.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationServiceAccountClassification
        Retrieves the service account classification rules using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationServiceAccountClassification -Force
        Forces a fresh retrieval of the service account classification rules, bypassing the cache.

    .OUTPUTS
        Object
        Returns the service account classification rules configuration.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrConfigurationServiceAccountClassification" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR service account classification rules"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrConfigurationServiceAccountClassification"
        } else {
            Write-Verbose "XDR service account classification rules cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/radius/api/radius/serviceaccounts/classificationrule/getall"
        Write-Verbose "Retrieving XDR service account classification rules"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "XdrConfigurationServiceAccountClassification" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}
