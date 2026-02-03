function Get-XdrCloudAppsAppGovernanceLabel {
    <#
    .SYNOPSIS
        Retrieves labels for App Governance.

    .DESCRIPTION
        Gets the labels configured in Microsoft Defender for Cloud Apps
        App Governance. Labels are used to categorize and organize
        governed applications.
        This function includes caching support with a 15-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceLabel
        Retrieves all App Governance labels using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceLabel -Force
        Forces a fresh retrieval of all labels, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceLabel | Where-Object { $_.name -like "*sensitive*" }
        Retrieves all labels and filters for those containing "sensitive" in the name.

    .OUTPUTS
        XdrCloudAppsAppGovernanceLabel
        Returns an array of label objects for App Governance.
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
        $CacheKey = "XdrCloudAppsAppGovernanceLabel"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached App Governance labels"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "App Governance labels cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/getLabels"

        Write-Verbose "Retrieving App Governance labels"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    if ($null -ne $item -and $item.PSObject) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernanceLabel')
                    }
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve App Governance labels: $_"
        }
    }

    end {
    }
}
