function Get-XdrConfigurationCriticalAssetManagementClassification {
    <#
    .SYNOPSIS
        Retrieves critical asset management classification rules from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the critical asset management rules from the Microsoft Defender XDR portal,
        including asset classification rules and conditions.
        This function includes caching support with a 30-minute TTL to reduce API calls.

        Critical asset management allows you to define classification rules that identify
        high-value assets in your organization, such as privileged accounts, critical servers,
        or sensitive data repositories.

    .PARAMETER RuleId
        The unique identifier of a specific rule to retrieve.
        If specified, returns only the rule with the matching ID.

    .PARAMETER RuleType
        Filters rules by type. Valid values are "Predefined" and "CreatedByUser".
        If not specified, all rules are returned.

    .PARAMETER Enabled
        Filters rules by enabled status. When specified, returns only rules
        where isEnabled matches the specified value.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .PARAMETER IncludeAffectedAssets
        When specified, retrieves the list of affected assets for each rule by making
        additional API calls to the querybuilder/assets endpoint. This adds an 'affectedAssets'
        property to each rule containing the detailed asset information.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification
        Retrieves all critical asset management rules using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleId "55a3f458c38a4b53b7d6a5564e0d1ac7"
        Retrieves a specific critical asset management rule by its ID.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType Predefined
        Retrieves only predefined critical asset management rules.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType CreatedByUser
        Retrieves only user-created critical asset management rules.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -Enabled $true
        Retrieves only enabled critical asset management rules.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType Predefined -Enabled $false
        Retrieves predefined rules that are currently disabled.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -Force
        Forces a fresh retrieval of the critical asset management configuration, bypassing the cache.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleId "b65d8e2e4e2f496d975a3987e43811f8" -IncludeAffectedAssets
        Retrieves a specific rule and includes the list of affected assets.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType Predefined -IncludeAffectedAssets | Where-Object { $_.affectedAssetsCount -gt 0 }
        Retrieves predefined rules that have affected assets and includes the asset details.

    .EXAMPLE
        # Pipeline to Set: Enable all disabled predefined rules
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType Predefined -Enabled $false |
            Set-XdrConfigurationCriticalAssetManagementClassification -Enabled $true

        Enables all disabled predefined critical asset management rules.

    .EXAMPLE
        # Pipeline to Remove: Clean up test rules
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType CreatedByUser |
            Where-Object { $_.ruleName -like "*Test*" } |
            Remove-XdrConfigurationCriticalAssetManagementClassification -Force

        Removes all user-created rules with "Test" in the name.

    .OUTPUTS
        System.Object[]
        Returns the rules array containing critical asset management configuration.
        Each rule object contains properties such as:
        - ruleId: Unique identifier for the rule
        - ruleName: Display name of the rule
        - ruleDescription: Description of what the rule identifies
        - ruleType: Either "Predefined" or "CreatedByUser"
        - isDisabled: Whether the rule is currently disabled
        - criticalityLevel: The criticality level assigned to matching assets
        - affectedAssetsCount: Number of assets matching this rule
        - affectedAssets: (when -IncludeAffectedAssets) Array of asset objects with details
    #>
    [OutputType([PSCustomObject[]])]
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [string]$RuleId,

        [Parameter()]
        [ValidateSet('Predefined', 'CreatedByUser')]
        [string]$RuleType,

        [Parameter()]
        [bool]$Enabled,

        [Parameter()]
        [switch]$IncludeAffectedAssets,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrConfigurationCriticalAssetManagementClassification"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue

        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR critical asset management configuration"
            $criticalAssetRules = $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
            $criticalAssetRules = $null
        } else {
            Write-Verbose "XDR critical asset management configuration cache is missing or expired"
            $criticalAssetRules = $null
        }

        # Fetch from API if not cached
        if (-not $criticalAssetRules) {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/assetrules"
            Write-Verbose "Retrieving XDR critical asset management configuration"
            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Return only the rules property
                $criticalAssetRules = $result.rules

                Set-XdrCache -CacheKey $CacheKey -Value $criticalAssetRules -TTLMinutes 30
            } catch {
                Write-Error "Failed to retrieve critical asset management configuration: $_"
                return
            }
        }

        # Filter by RuleId if specified
        if ($PSBoundParameters.ContainsKey('RuleId')) {
            Write-Verbose "Filtering rules by RuleId: $RuleId"
            $criticalAssetRules = $criticalAssetRules | Where-Object { $_.ruleId -eq $RuleId }
        }

        # Filter by RuleType if specified
        if ($PSBoundParameters.ContainsKey('RuleType')) {
            Write-Verbose "Filtering rules by RuleType: $RuleType"
            $criticalAssetRules = $criticalAssetRules | Where-Object { $_.ruleType -eq $RuleType }
        }

        # Filter by Enabled status if specified (API uses isDisabled, so we invert)
        if ($PSBoundParameters.ContainsKey('Enabled')) {
            Write-Verbose "Filtering rules by Enabled status: $Enabled"
            $criticalAssetRules = $criticalAssetRules | Where-Object { $_.isDisabled -ne $Enabled }
        }

        # Fetch affected assets for each rule if requested
        if ($IncludeAffectedAssets -and $criticalAssetRules) {
            Write-Verbose "Fetching affected assets for rules"
            # Clone rules to avoid mutating cached objects with Add-Member
            $criticalAssetRules = $criticalAssetRules | ForEach-Object {
                [PSCustomObject]($_ | ConvertTo-Json -Depth 10 | ConvertFrom-Json)
            }
            foreach ($rule in $criticalAssetRules) {
                if ($rule.affectedAssetsCount -gt 0 -and $rule.ruleName) {
                    $encodedRuleName = [System.Uri]::EscapeDataString($rule.ruleName)
                    $assetsUri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/assetrules/querybuilder/assets/$encodedRuleName"
                    try {
                        Write-Verbose "Fetching affected assets for rule: $($rule.ruleName)"
                        $assetsResult = Invoke-RestMethod -Uri $assetsUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        $rule | Add-Member -NotePropertyName 'affectedAssets' -NotePropertyValue $assetsResult.assets -Force
                    } catch {
                        Write-Verbose "Failed to retrieve affected assets for rule '$($rule.ruleName)': $_"
                        $rule | Add-Member -NotePropertyName 'affectedAssets' -NotePropertyValue @() -Force
                    }
                } else {
                    $rule | Add-Member -NotePropertyName 'affectedAssets' -NotePropertyValue @() -Force
                }
            }
        }

        return $criticalAssetRules
    }

    end {

    }
}
