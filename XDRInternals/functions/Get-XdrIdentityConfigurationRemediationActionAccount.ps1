function Get-XdrIdentityConfigurationRemediationActionAccount {
    <#
    .SYNOPSIS
        Retrieves the remediation action account configuration for Microsoft Defender for Identity.

    .DESCRIPTION
        Gets the remediation action account configuration from Microsoft Defender for Identity.
        If remediation is configured to use Local System, returns the configuration status.
        If remediation uses a dedicated account, returns both the configuration status and the account details.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityConfigurationRemediationActionAccount
        Retrieves the remediation action account configuration using cached data if available.

    .EXAMPLE
        Get-XdrIdentityConfigurationRemediationActionAccount -Force
        Forces a fresh retrieval of the remediation action account configuration, bypassing the cache.

    .EXAMPLE
        $config = Get-XdrIdentityConfigurationRemediationActionAccount
        if ($config.IsRemediationWithLocalSystemEnabled) {
            Write-Host "Using Local System account for remediation"
        } else {
            Write-Host "Using dedicated account: $($config.RemediationAccounts[0].AccountName)"
        }
        Retrieves the configuration and checks which account type is being used.

    .OUTPUTS
        Object
        Returns a configuration object containing:
        - IsRemediationWithLocalSystemEnabled: Boolean indicating if Local System is used
        - RemediationAccounts: Array of remediation account details (only if not using Local System)
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityConfigurationRemediationActionAccount" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity remediation action account configuration"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityConfigurationRemediationActionAccount"
        } else {
            Write-Verbose "XDR Identity remediation action account configuration cache is missing or expired"
        }

        # Get the primary configuration
        $configUri = "https://security.microsoft.com/apiproxy/aatp/api/remediationActions/configuration"
        Write-Verbose "Retrieving XDR Identity remediation action configuration"
        $config = Invoke-RestMethod -Uri $configUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        # Initialize the result object
        $result = [PSCustomObject]@{
            IsRemediationWithLocalSystemEnabled = $config.IsRemediationWithLocalSystemEnabled
            RemediationAccounts                 = $null
        }

        # If not using Local System, get the remediation account details
        if (-not $config.IsRemediationWithLocalSystemEnabled) {
            Write-Verbose "Remediation is not using Local System, retrieving account details"
            $credentialsUri = "https://security.microsoft.com/apiproxy/aatp/odata/EntityRemediatorCredentials"
            $credentials = Invoke-RestMethod -Uri $credentialsUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            
            # Extract only the value array
            if ($credentials.value) {
                $result.RemediationAccounts = $credentials.value
                Write-Verbose "Retrieved $($credentials.value.Count) remediation account(s)"
            } else {
                $result.RemediationAccounts = @()
                Write-Verbose "No remediation accounts found"
            }
        } else {
            Write-Verbose "Remediation is using Local System account"
        }

        Set-XdrCache -CacheKey "XdrIdentityConfigurationRemediationActionAccount" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}
