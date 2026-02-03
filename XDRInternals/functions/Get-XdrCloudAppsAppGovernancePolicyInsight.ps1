function Get-XdrCloudAppsAppGovernancePolicyInsight {
    <#
    .SYNOPSIS
        Retrieves App Governance policy insights.

    .DESCRIPTION
        Gets the policy insights from Microsoft Defender for Cloud Apps
        App Governance. Policy insights provide visibility into policy
        effectiveness, triggered alerts, and recommendations for policy
        improvements.
        This function includes caching support with a 15-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicyInsight
        Retrieves App Governance policy insights using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicyInsight -Force
        Forces a fresh retrieval of policy insights, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernancePolicyInsight | ConvertTo-Json -Depth 5
        Retrieves policy insights and converts to JSON for detailed inspection.

    .OUTPUTS
        XdrCloudAppsAppGovernancePolicyInsight
        Returns an object containing App Governance policy insights.
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
        $CacheKey = "XdrCloudAppsAppGovernancePolicyInsight"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached App Governance policy insights"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "App Governance policy insights cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/policyinsights?api-version=1.0"

        Write-Verbose "Retrieving App Governance policy insights"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                if ($result -is [System.Array]) {
                    foreach ($item in $result) {
                        if ($null -ne $item -and $item.PSObject) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernancePolicyInsight')
                        }
                    }
                } else {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernancePolicyInsight')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve App Governance policy insights: $_"
        }
    }

    end {
    }
}
