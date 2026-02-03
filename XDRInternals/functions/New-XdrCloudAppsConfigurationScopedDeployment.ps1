function New-XdrCloudAppsConfigurationScopedDeployment {
    <#
    .SYNOPSIS
        Creates a new scoped deployment rule in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Creates a new scoped deployment rule in Microsoft Defender for Cloud Apps.
        Supports three rule types: Include (users to monitor), Exclude (users to exclude),
        and ActivityPrivacy (users with hidden activities).

    .PARAMETER RuleType
        The type of scoped deployment rule to create.
        Valid values are: Include, Exclude, ActivityPrivacy.

    .PARAMETER Name
        The name of the scoped deployment rule.

    .PARAMETER UserTags
        Array of user tag IDs to include in the rule.
        User tags can be retrieved using Get-XdrCloudAppsConfigurationUserTag.

    .PARAMETER AppIds
        Optional array of app IDs to scope the rule to specific apps.
        If not specified, the rule applies to all apps.

    .PARAMETER Appstances
        Optional array of app instance IDs to scope the rule to specific app instances.

    .PARAMETER Confirm
        Prompts for confirmation before creating each rule.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrCloudAppsConfigurationScopedDeployment -RuleType Include -Name "IT Admins" -UserTags "6965bdb191738775c75754ca"
        Creates a new include rule named "IT Admins" that monitors users with the specified user tag.

    .EXAMPLE
        New-XdrCloudAppsConfigurationScopedDeployment -RuleType Exclude -Name "Service Accounts" -UserTags "6965bdb191738775c75754cb"
        Creates a new exclude rule that excludes users with the specified user tag from monitoring.

    .EXAMPLE
        New-XdrCloudAppsConfigurationScopedDeployment -RuleType ActivityPrivacy -Name "Executives" -UserTags "6965bdb191738775c75754cc"
        Creates a new activity privacy rule that hides activities for users with the specified user tag.

    .EXAMPLE
        New-XdrCloudAppsConfigurationScopedDeployment -RuleType Include -Name "Okta Users" -UserTags "6965bdb191738775c75754ca" -AppIds 10489
        Creates a new include rule scoped to a specific app (Okta).

    .OUTPUTS
        PSObject
        Returns the created rule ID or the updated list of scoped deployment rules.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude', 'ActivityPrivacy')]
        [string]$RuleType,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [string[]]$UserTags,

        [Parameter()]
        [int[]]$AppIds,

        [Parameter()]
        [int[]]$Appstances
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Map RuleType to API path segment
        $ruleTypePath = switch ($RuleType) {
            'Include' { 'include' }
            'Exclude' { 'exclude' }
            'ActivityPrivacy' { 'activity_privacy' }
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_deployment/$ruleTypePath/create_rule/"

        # Build request body - convert arrays to JSON first to preserve array structure
        $userTagsJson = if ($UserTags -and $UserTags.Count -gt 0) { $UserTags | ConvertTo-Json -Compress -AsArray } else { "[]" }
        $appIdsJson = if ($AppIds -and $AppIds.Count -gt 0) { $AppIds | ConvertTo-Json -Compress -AsArray } else { "[]" }
        $appstancesJson = if ($Appstances -and $Appstances.Count -gt 0) { $Appstances | ConvertTo-Json -Compress -AsArray } else { "[]" }

        # Build the JSON body manually to preserve array structure
        $bodyJson = @"
{"name":"$Name","appIds":$appIdsJson,"appstances":$appstancesJson,"userTags":$userTagsJson,"overrideAppIdsScope":"all"}
"@

        $target = "Scoped Deployment $RuleType rule '$Name'"
        $action = "Create"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Creating scoped deployment $RuleType rule: $Name"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for scoped deployments
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationScopedDeployment*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully created scoped deployment rule. ID: $($result.id)"
                return $result
            }
            catch {
                Write-Error "Failed to create scoped deployment $RuleType rule '$Name': $_"
            }
        }
    }

    end {
    }
}
