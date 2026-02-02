function Set-XdrConfigurationCriticalAssetManagementClassification {
    <#
    .SYNOPSIS
        Updates critical asset management classification rule metadata in Microsoft Defender XDR.

    .DESCRIPTION
        Modifies critical asset management rules in the Microsoft Defender XDR portal.
        This function allows enabling or disabling rules by updating their metadata.

        Critical asset management allows you to define classification rules that identify
        high-value assets in your organization, such as privileged accounts, critical servers,
        or sensitive data repositories.

    .PARAMETER RuleId
        The unique identifier of the rule to update.
        This parameter is mandatory when not using -InputObject.

    .PARAMETER InputObject
        A rule object from Get-XdrConfigurationCriticalAssetManagementClassification.
        When provided, avoids an extra API call to fetch rule details.
        Can be piped directly to this cmdlet.

    .PARAMETER Enabled
        Sets whether the rule should be enabled or disabled.
        Use $true to enable the rule or $false to disable it.

    .PARAMETER PassThru
        When specified, returns the updated rule object after the operation completes.
        By default, this cmdlet does not generate any output.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .EXAMPLE
        Set-XdrConfigurationCriticalAssetManagementClassification -RuleId "55a3f458c38a4b53b7d6a5564e0d1ac7" -Enabled $true
        Enables the critical asset management rule with the specified ID.

    .EXAMPLE
        Set-XdrConfigurationCriticalAssetManagementClassification -RuleId "55a3f458c38a4b53b7d6a5564e0d1ac7" -Enabled $false
        Disables the critical asset management rule with the specified ID.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType Predefined -Enabled $false |
            Set-XdrConfigurationCriticalAssetManagementClassification -Enabled $true
        Enables all disabled predefined critical asset management rules using pipeline.

    .EXAMPLE
        Set-XdrConfigurationCriticalAssetManagementClassification -RuleId "55a3f458c38a4b53b7d6a5564e0d1ac7" -Enabled $true -PassThru
        Enables the rule and returns the updated rule object.

    .EXAMPLE
        Set-XdrConfigurationCriticalAssetManagementClassification -RuleId "55a3f458c38a4b53b7d6a5564e0d1ac7" -Enabled $true -WhatIf
        Shows what would happen if the rule were enabled, without making any changes.

    .EXAMPLE
        # Create a rule, then disable it
        $rule = New-XdrConfigurationCriticalAssetManagementClassification `
            -RuleName "Temp Rule" -RuleDescription "Test" `
            -AssetType Devices -CriticalityLevel Low `
            -Property "Tags" -Operator Contains -Value "Test" -PassThru

        $rule | Set-XdrConfigurationCriticalAssetManagementClassification -Enabled $false

        Creates a new rule and immediately disables it using the pipeline.

    .INPUTS
        System.Object
        You can pipe objects containing a 'ruleId', 'RuleId', or 'id' property to this cmdlet.

    .OUTPUTS
        None by default. System.Object if -PassThru is specified.
        When PassThru is used, returns the updated rule object from Get-XdrConfigurationCriticalAssetManagementClassification.

    .NOTES
        The PATCH endpoint updates rule metadata including the enabled state.
        After modifying a rule, the local cache is cleared to ensure subsequent
        Get-XdrConfigurationCriticalAssetManagementClassification calls return fresh data.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is implemented')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByRuleId')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByRuleId')]
        [Alias('id')]
        [ValidateNotNullOrEmpty()]
        [string]$RuleId,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'ByInputObject')]
        [ValidateNotNull()]
        [PSObject]$InputObject,

        [Parameter(Mandatory)]
        [bool]$Enabled,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Get rule information from InputObject or fetch it
        if ($PSCmdlet.ParameterSetName -eq 'ByInputObject') {
            if (-not $InputObject.ruleId) {
                Write-Error "InputObject does not contain a ruleId property."
                return
            }
            $RuleId = $InputObject.ruleId
            # Use InputObject if it has all required properties for the PATCH body
            if ($InputObject.ruleName -and $InputObject.ruleDescription -and
                $InputObject.ruleDefinition -and $InputObject.actions -and
                $InputObject.ruleType -and $InputObject.assetType -and
                $null -ne $InputObject.isDisabled) {
                $currentRule = $InputObject
            } else {
                # Fetch full rule if InputObject is missing required properties
                $currentRule = Get-XdrConfigurationCriticalAssetManagementClassification -RuleId $RuleId -Force
            }
        } else {
            $currentRule = Get-XdrConfigurationCriticalAssetManagementClassification -RuleId $RuleId -Force
        }

        if (-not $currentRule) {
            Write-Error "Rule with ID '$RuleId' not found."
            return
        }

        $ruleName = $currentRule.ruleName
        $currentlyEnabled = -not $currentRule.isDisabled
        $currentState = if ($currentlyEnabled) { "enabled" } else { "disabled" }
        $targetState = if ($Enabled) { "enabled" } else { "disabled" }

        # Skip if already in desired state
        if ($currentlyEnabled -eq $Enabled) {
            Write-Verbose "Rule '$ruleName' ($RuleId) is already $targetState. No changes needed."
            if ($PassThru) {
                return $currentRule
            }
            return
        }

        $actionDescription = "Set critical asset rule '$ruleName' ($RuleId) from $currentState to $targetState"

        if ($PSCmdlet.ShouldProcess($actionDescription, "Update Critical Asset Management Rule")) {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/assetrules/$RuleId/metadata"
            Write-Verbose "Updating critical asset management rule: $ruleName ($RuleId)"

            # Build the request body - Portal sends full rule object with isDisabled
            $body = @{
                ruleId          = $currentRule.ruleId
                ruleName        = $currentRule.ruleName
                ruleDescription = $currentRule.ruleDescription
                ruleDefinition  = $currentRule.ruleDefinition
                isDisabled      = -not $Enabled
                actions         = $currentRule.actions
                ruleType        = $currentRule.ruleType
                assetType       = $currentRule.assetType
            } | ConvertTo-Json -Depth 10 -Compress

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Patch -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                Write-Verbose "Successfully updated rule '$ruleName' ($RuleId) to $targetState"

                # Clear the cache to ensure fresh data on next Get
                Clear-XdrCache -CacheKey "XdrConfigurationCriticalAssetManagementClassification"

                if ($PassThru) {
                    # Return fresh rule data
                    return Get-XdrConfigurationCriticalAssetManagementClassification -RuleId $RuleId -Force
                }
            } catch {
                Write-Error "Failed to update critical asset management rule '$ruleName' ($RuleId): $_"
            }
        }
    }

    end {

    }
}
