function Get-XdrCloudAppsAppGovernancePolicy {
    <#
    .SYNOPSIS
        Retrieves App Governance policies.

    .DESCRIPTION
        Gets the policies configured in Microsoft Defender for Cloud Apps
        App Governance. Policies define rules for governing application
        behavior, data access, and security requirements.
        This function includes caching support with a 15-minute TTL to reduce API calls.

    .PARAMETER Top
        The maximum number of policies to retrieve. Default is 40.

    .PARAMETER OrderBy
        The field to order results by. Default is "lastModified desc".

    .PARAMETER ExpandPolicyRule
        Whether to expand policy rule details. By default, policy rules are expanded.
        Use -ExpandPolicyRule:$false to exclude policy rule details.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicy
        Retrieves App Governance policies using default parameters and cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicy -Force
        Forces a fresh retrieval of policies, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicy -Top 100
        Retrieves up to 100 App Governance policies.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicy -OrderBy "displayName asc"
        Retrieves policies ordered by display name in ascending order.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicy -ExpandPolicyRule:$false
        Retrieves policies without expanding policy rule details.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicy -ExpandPolicyRule
        Explicitly includes policy rule details in the response.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicy | Where-Object { $_.isEnabled -eq $true }
        Retrieves all policies and filters for enabled ones.

    .OUTPUTS
        XdrCloudAppsAppGovernancePolicy
        Returns an array of App Governance policy objects.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$Top = 40,

        [Parameter()]
        [string]$OrderBy = "lastModified desc",

        [Parameter()]
        [switch]$ExpandPolicyRule,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Default to expanding policy rules unless explicitly set to false
        $shouldExpandPolicyRule = -not $PSBoundParameters.ContainsKey('ExpandPolicyRule') -or $ExpandPolicyRule

        $CacheKey = "XdrCloudAppsAppGovernancePolicy_Top${Top}_OrderBy$($OrderBy -replace ' ', '_')_Expand$shouldExpandPolicyRule"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached App Governance policies"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "App Governance policies cache is missing or expired"
        }

        $encodedOrderBy = [System.Web.HttpUtility]::UrlEncode($OrderBy)
        $Uri = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/Policy?`$count=true&`$orderby=$encodedOrderBy&`$top=$Top&api-version=1.0"

        if ($shouldExpandPolicyRule) {
            $Uri += "&`$expand=policyRule"
        }

        Write-Verbose "Retrieving App Governance policies"
        Write-Verbose "URI: $Uri"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.value) { $response.value } elseif ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    if ($null -ne $item -and $item.PSObject) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernancePolicy')
                    }
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve App Governance policies: $_"
        }
    }

    end {
    }
}
