function Set-XdrCloudAppsConfigurationScopedDeployment {
    <#
    .SYNOPSIS
        Updates a scoped deployment rule in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Updates an existing scoped deployment rule in Microsoft Defender for Cloud Apps.
        Scoped deployment rules control which users and groups are included or excluded
        from Cloud Apps monitoring, or have activity privacy applied.

    .PARAMETER RuleType
        Specifies the type of scoped deployment rule being updated.
        Valid values are 'Include', 'Exclude', or 'ActivityPrivacy'.

    .PARAMETER RuleId
        The unique identifier of the scoped deployment rule to update.

    .PARAMETER Name
        The new name for the scoped deployment rule.

    .PARAMETER UserTags
        An array of user tag IDs to associate with this scoped deployment rule.

    .PARAMETER AppIds
        An optional array of application IDs to associate with this scoped deployment rule.
        When specified along with OverrideAppIdsScope set to 'appIds', the rule applies
        only to the specified apps.

    .PARAMETER Appstances
        An optional array of app instance IDs to associate with this scoped deployment rule.

    .PARAMETER OverrideAppIdsScope
        Specifies whether the rule applies to all apps or specific apps.
        Valid values are 'all' or 'appIds'. When set to 'appIds', use the AppIds
        parameter to specify which apps the rule applies to.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationScopedDeployment -RuleType Include -RuleId "697e49cc807b6351d0e2e880" -Name "Updated Rule" -UserTags @("tagId1", "tagId2")
        Updates the specified include rule with a new name and user tags.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedDeployment -RuleType Exclude | Where-Object { $_.name -eq "Okta Exclude" } | Set-XdrCloudAppsConfigurationScopedDeployment -RuleType Exclude -Name "Okta Exclude Updated" -UserTags @("tagId1")
        Gets an exclude rule by name and updates it using pipeline input.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationScopedDeployment -RuleType Include -RuleId "697e49cc807b6351d0e2e880" -Name "Specific Apps Rule" -UserTags @("tagId1") -AppIds @(17152, 11599) -OverrideAppIdsScope "appIds"
        Updates an include rule to apply only to specific apps.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationScopedDeployment -RuleType ActivityPrivacy -RuleId "abc123" -Name "Privacy Rule" -UserTags @("tagId1") -OverrideAppIdsScope "all" -WhatIf
        Shows what would happen if the activity privacy rule were updated.

    .OUTPUTS
        System.Object
        Returns the API response confirming the update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude', 'ActivityPrivacy')]
        [string]$RuleType,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('_id')]
        [string]$RuleId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [string[]]$UserTags = @(),

        [Parameter()]
        [int[]]$AppIds,

        [Parameter()]
        [int[]]$Appstances,

        [Parameter()]
        [ValidateSet('all', 'appIds')]
        [string]$OverrideAppIdsScope
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

        $target = "Scoped Deployment Rule '$Name' ($RuleId) of type '$RuleType'"
        $action = "Update scoped deployment rule"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Updating scoped deployment rule: $RuleId (Type: $RuleType)"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_deployment/$endpoint/$RuleId/update_rule/"

                # Build the request body
                $Body = @{
                    _id      = $RuleId
                    name     = $Name
                    userTags = $UserTags
                }

                # Add optional parameters
                if ($PSBoundParameters.ContainsKey('AppIds')) {
                    $Body.appIds = $AppIds
                } else {
                    $Body.appIds = @()
                }

                if ($PSBoundParameters.ContainsKey('Appstances')) {
                    $Body.appstances = $Appstances
                } else {
                    $Body.appstances = @()
                }

                if ($PSBoundParameters.ContainsKey('OverrideAppIdsScope')) {
                    $Body.overrideAppIdsScope = $OverrideAppIdsScope
                }

                $BodyJson = $Body | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $BodyJson"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $BodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful update
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationScopedDeployment*" -ErrorAction SilentlyContinue
                Write-Verbose "Scoped deployment rule updated successfully"

                return $result
            } catch {
                Write-Error "Failed to update scoped deployment rule: $_"
            }
        }
    }

    end {
    }
}
