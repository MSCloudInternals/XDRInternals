function Get-XdrCloudAppsGeneralSetting {
    <#
    .SYNOPSIS
        Retrieves general settings from Microsoft Defender for Cloud Apps (Cloud Apps).

    .DESCRIPTION
        Gets the general configuration settings from Microsoft Defender for Cloud Apps,
        including organization display name, domains, email masking policies, file monitoring,
        Azure IP allowlisting, RMS decryption settings, and integration configurations.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsGeneralSetting
        Retrieves the Cloud Apps general settings using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsGeneralSetting -Force
        Forces a fresh retrieval of the Cloud Apps general settings, bypassing the cache.

    .OUTPUTS
        Object
        Returns the Cloud Apps general settings configuration object containing:
        - environmentName: Environment name
        - orgDisplayName: Organization display name
        - domains: List of configured domains
        - emailMaskPolicy: Email masking policy setting
        - allowAzIP: Azure IP allowlist status
        - fileMonitoring: File monitoring configuration
        - rmsDecryptAllConsented: RMS decryption consent status
        - mdatpGlobalSeverityLevel: Global severity level for Microsoft Defender ATP integration
        - allowAzureSecurityIntegration: Azure Security Center integration status
        - And additional configuration properties
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrCloudAppsGeneralSettings" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps general settings"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrCloudAppsGeneralSettings"
        } else {
            Write-Verbose "Cloud Apps general settings cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/settings/"
        Write-Verbose "Retrieving Cloud Apps general settings"
        try {
            $result = Invoke-XdrRestMethod -Uri $Uri -Method Get
            Set-XdrCache -CacheKey "XdrCloudAppsGeneralSettings" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps general settings: $_"
        }
    }

    end {
    }
}

