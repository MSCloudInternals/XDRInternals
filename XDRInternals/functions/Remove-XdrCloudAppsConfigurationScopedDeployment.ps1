function Remove-XdrCloudAppsConfigurationScopedDeployment {
    <#
    .SYNOPSIS
        Removes a scoped deployment rule from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Deletes a scoped deployment rule (Include, Exclude, or Activity Privacy) from
        Microsoft Defender for Cloud Apps. This permanently removes the rule and its
        associated user/group assignments.

    .PARAMETER RuleType
        Specifies the type of scoped deployment rule to remove.
        Valid values are 'Include', 'Exclude', or 'ActivityPrivacy'.

    .PARAMETER RuleId
        The unique identifier of the rule to remove.
        Accepts pipeline input from the _id property of scoped deployment rule objects.

    .PARAMETER Confirm
        Prompts for confirmation before removing the rule.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The rule is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationScopedDeployment -RuleType Include -RuleId "697e49cc807b6351d0e2e880"
        Removes the specified Include scoped deployment rule.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationScopedDeployment -RuleType Exclude -RuleId "697e49f6f13122849c3f9092"
        Removes the specified Exclude scoped deployment rule.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationScopedDeployment -RuleType ActivityPrivacy -RuleId "697e49fbaa56aafce66e2fcc"
        Removes the specified Activity Privacy scoped deployment rule.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedDeployment -RuleType Include | Where-Object { $_.name -eq 'Test Rule' } | Remove-XdrCloudAppsConfigurationScopedDeployment -RuleType Include
        Finds an Include rule by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedDeployment -RuleType Exclude | Remove-XdrCloudAppsConfigurationScopedDeployment -RuleType Exclude -WhatIf
        Shows what would happen if all Exclude rules were removed.

    .OUTPUTS
        None
        This cmdlet does not return any output upon successful deletion.

    .NOTES
        This operation requires confirmation by default due to high impact.
        Use -Confirm:$false to bypass confirmation in scripts.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is implemented')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude', 'ActivityPrivacy')]
        [string]$RuleType,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$RuleId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $endpoint = switch ($RuleType) {
            'Include' { 'include' }
            'Exclude' { 'exclude' }
            'ActivityPrivacy' { 'activity_privacy' }
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_deployment/$endpoint/$RuleId/"

        if ($PSCmdlet.ShouldProcess($RuleId, "Remove $RuleType scoped deployment rule")) {
            Write-Verbose "Removing $RuleType scoped deployment rule: $RuleId"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationScopedDeployment*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed $RuleType scoped deployment rule: $RuleId"
            } catch {
                Write-Error "Failed to remove $RuleType scoped deployment rule '$RuleId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
