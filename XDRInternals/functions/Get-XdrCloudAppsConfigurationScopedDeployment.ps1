function Get-XdrCloudAppsConfigurationScopedDeployment {
    <#
    .SYNOPSIS
        Retrieves scoped deployment rules from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the scoped deployment rules from Microsoft Defender for Cloud Apps,
        including Include, Exclude, and Activity Privacy rules. These rules control
        which users and groups are included or excluded from Cloud Apps monitoring.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER RuleType
        Specifies the type of scoped deployment rules to retrieve.
        Valid values are 'Include', 'Exclude', 'ActivityPrivacy', or 'All'.
        Default is 'All' which retrieves all three rule types.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedDeployment
        Retrieves all scoped deployment rules using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedDeployment -RuleType Include
        Retrieves only the Include scoped deployment rules.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedDeployment -RuleType Exclude -Force
        Forces a fresh retrieval of the Exclude scoped deployment rules, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedDeployment -RuleType ActivityPrivacy
        Retrieves the Activity Privacy scoped deployment rules.

    .OUTPUTS
        XdrCloudAppsConfigurationScopedDeployment[]
        Returns an array of scoped deployment rule objects containing rule configuration details.
        Each object includes a RuleType property indicating the type of rule.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Returns a List that can be treated as object[]')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [Parameter()]
        [ValidateSet('Include', 'Exclude', 'ActivityPrivacy', 'All')]
        [string]$RuleType = 'All',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConfigurationScopedDeployment-$RuleType"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps scoped deployment rules ($RuleType)"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps scoped deployment rules cache is missing or expired"
        }

        $BaseUri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_deployment"
        $Body = @{
            skip              = 0
            limit             = 100
            filters           = @{}
            performAsyncTotal = $false
            sortDirection     = "desc"
            sortField         = "name"
        } | ConvertTo-Json -Compress

        $ruleTypes = @()
        if ($RuleType -eq 'All') {
            $ruleTypes = @('Include', 'Exclude', 'ActivityPrivacy')
        } else {
            $ruleTypes = @($RuleType)
        }

        $allResults = [System.Collections.Generic.List[object]]::new()

        foreach ($type in $ruleTypes) {
            $endpoint = switch ($type) {
                'Include' { 'include' }
                'Exclude' { 'exclude' }
                'ActivityPrivacy' { 'activity_privacy' }
            }

            $Uri = "$BaseUri/$endpoint/"
            Write-Verbose "Retrieving Cloud Apps scoped deployment rules ($type)"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $response.data) {
                    foreach ($item in $response.data) {
                        $item | Add-Member -NotePropertyName 'RuleType' -NotePropertyValue $type -Force
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationScopedDeployment')
                        $allResults.Add($item)
                    }
                }
            } catch {
                Write-Error "Failed to retrieve Cloud Apps scoped deployment rules ($type): $_"
            }
        }

        if ($allResults.Count -gt 0) {
            Set-XdrCache -CacheKey $CacheKey -Value $allResults -TTLMinutes 30
        }

        return $allResults
    }

    end {
    }
}
