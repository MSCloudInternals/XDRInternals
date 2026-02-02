function Remove-XdrConfigurationCriticalAssetManagementClassification {
    <#
    .SYNOPSIS
        Removes a Critical Asset Management classification rule from Microsoft Defender XDR.

    .DESCRIPTION
        Deletes a user-created Critical Asset Management classification rule. This operation
        marks the rule as deleted and it will no longer be evaluated against assets.

        Note: Only user-created rules (ruleType = "CreatedByUser") can be deleted.
        Predefined rules cannot be deleted, only disabled.

    .PARAMETER RuleId
        The unique identifier of the rule to delete.

    .PARAMETER InputObject
        A rule object from Get-XdrConfigurationCriticalAssetManagementClassification to delete.
        Can be piped to this cmdlet.

    .PARAMETER Force
        Suppresses the confirmation prompt before deleting the rule.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Remove-XdrConfigurationCriticalAssetManagementClassification -RuleId "b2ccb988-5761-4947-93da-12e7c0ae6171"
        Deletes the specified rule after confirmation.

    .EXAMPLE
        Remove-XdrConfigurationCriticalAssetManagementClassification -RuleId "b2ccb988-5761-4947-93da-12e7c0ae6171" -Force
        Deletes the specified rule without confirmation.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleId "b2ccb988-5761-4947-93da-12e7c0ae6171" |
            Remove-XdrConfigurationCriticalAssetManagementClassification
        Pipes a rule object to delete it.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleType CreatedByUser |
            Where-Object { $_.ruleName -like "*Test*" } |
            Remove-XdrConfigurationCriticalAssetManagementClassification -Force
        Deletes all user-created rules with "Test" in the name.

    .EXAMPLE
        # Full create and cleanup workflow
        $rule = New-XdrConfigurationCriticalAssetManagementClassification `
            -RuleName "Temporary Test Rule" `
            -RuleDescription "Rule for testing" `
            -AssetType Devices -CriticalityLevel Low `
            -Property "Tags" -Operator Contains -Value "TestTag" `
            -PassThru

        # Verify creation
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleId $rule.ruleId

        # Remove when done testing
        $rule | Remove-XdrConfigurationCriticalAssetManagementClassification -Force

        Creates a rule, verifies it exists, then removes it.

    .OUTPUTS
        None
        This cmdlet does not return any output on success.

    .NOTES
        - Only user-created rules can be deleted
        - Predefined rules cannot be deleted; use Set-XdrConfigurationCriticalAssetManagementClassification to disable them
        - This operation is permanent and cannot be undone
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'This function implements its own confirmation logic')]
    [CmdletBinding(DefaultParameterSetName = 'ByRuleId', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByRuleId', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$RuleId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByInputObject', ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [PSObject]$InputObject,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Get RuleId from input object if provided
        if ($PSCmdlet.ParameterSetName -eq 'ByInputObject') {
            if (-not $InputObject.ruleId) {
                throw "InputObject does not contain a ruleId property."
            }
            $RuleId = $InputObject.ruleId
            $ruleName = $InputObject.ruleName
            $ruleType = $InputObject.ruleType
        } else {
            # Fetch the rule to get its name and type for confirmation
            try {
                $rule = Get-XdrConfigurationCriticalAssetManagementClassification -RuleId $RuleId -Force
                if (-not $rule) {
                    throw "Rule with ID '$RuleId' not found."
                }
                $ruleName = $rule.ruleName
                $ruleType = $rule.ruleType
            } catch {
                throw "Failed to retrieve rule '$RuleId': $_"
            }
        }

        # Check if this is a predefined rule
        if ($ruleType -eq 'Predefined') {
            throw "Cannot delete predefined rule '$ruleName'. Use Set-XdrConfigurationCriticalAssetManagementClassification -Enabled `$false to disable it instead."
        }

        # Handle -Force to suppress confirmation while still honoring -WhatIf
        if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = 'None'
        }

        # Always call ShouldProcess to honor -WhatIf and -Confirm
        if (-not $PSCmdlet.ShouldProcess($ruleName, "Delete Critical Asset Management rule")) {
            return
        }

        # Build the request body
        $body = @{
            ruleId    = $RuleId
            isDeleted = $true
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/assetrules/$RuleId"
        Write-Verbose "Deleting Critical Asset Management rule: $ruleName ($RuleId)"

        try {
            $null = Invoke-RestMethod -Uri $Uri -Method Patch -ContentType "application/json" -Body ($body | ConvertTo-Json) -WebSession $script:session -Headers $script:headers

            # Clear the rules cache since we've deleted a rule
            Clear-XdrCache -CacheKey "XdrConfigurationCriticalAssetManagementClassification" -ErrorAction SilentlyContinue

            Write-Verbose "Successfully deleted rule: $ruleName"
        } catch {
            $errorMessage = $_.Exception.Message
            if ($_.ErrorDetails.Message) {
                $errorMessage = $_.ErrorDetails.Message
            }
            throw "Failed to delete Critical Asset Management rule '$ruleName': $errorMessage"
        }
    }

    end {
    }
}
