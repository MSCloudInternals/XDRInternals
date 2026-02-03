function Get-XdrCloudAppsAppGovernancePredefinedPolicy {
    <#
    .SYNOPSIS
        Retrieves predefined App Governance policies.

    .DESCRIPTION
        Gets the predefined policies from Microsoft Defender for Cloud Apps
        App Governance. Predefined policies are Microsoft-provided policies
        that offer baseline protection and governance for applications.
        This function includes caching support with a 15-minute TTL to reduce API calls.

    .PARAMETER Status
        The status of policies to retrieve. Default is "Active".
        Common values: Active, Inactive, Draft

    .PARAMETER Source
        The source of policies to retrieve. Default is "Predefined".
        Common values: Predefined, Custom

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePredefinedPolicy
        Retrieves active predefined App Governance policies using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePredefinedPolicy -Force
        Forces a fresh retrieval of predefined policies, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePredefinedPolicy -Status "Inactive"
        Retrieves inactive predefined App Governance policies.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePredefinedPolicy | Select-Object displayName, description, isEnabled
        Retrieves predefined policies and displays selected properties.

    .OUTPUTS
        XdrCloudAppsAppGovernancePredefinedPolicy
        Returns an array of predefined App Governance policy objects.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Status = "Active",

        [Parameter()]
        [string]$Source = "Predefined",

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsAppGovernancePredefinedPolicy_Status${Status}_Source${Source}"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached App Governance predefined policies"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "App Governance predefined policies cache is missing or expired"
        }

        $encodedFilter = [System.Web.HttpUtility]::UrlEncode("(status eq '$Status')")
        $Uri = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/policies?api-version=1.0&`$filter=$encodedFilter&source=$Source&`$count=true"

        Write-Verbose "Retrieving App Governance predefined policies"
        Write-Verbose "URI: $Uri"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.value) { $response.value } elseif ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    if ($null -ne $item -and $item.PSObject) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernancePredefinedPolicy')
                    }
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve App Governance predefined policies: $_"
        }
    }

    end {
    }
}
