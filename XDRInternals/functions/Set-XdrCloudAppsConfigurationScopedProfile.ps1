function Set-XdrCloudAppsConfigurationScopedProfile {
    <#
    .SYNOPSIS
        Updates a scoped profile in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Updates an existing scoped profile in Microsoft Defender for Cloud Apps.
        Scoped profiles allow you to define groups of users or organizational units
        for targeted policy application in cloud discovery.

    .PARAMETER ProfileId
        The unique identifier of the scoped profile to update.

    .PARAMETER Name
        The display name for the scoped profile.

    .PARAMETER GroupIds
        An array of group IDs (integers) to associate with this scoped profile.
        These correspond to machine groups or organizational units.

    .PARAMETER IsInclude
        Specifies whether this is an include profile ($true) or exclude profile ($false).
        Include profiles apply policies to the specified groups.
        Exclude profiles exempt the specified groups from policies.

    .PARAMETER Description
        Optional description for the scoped profile.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationScopedProfile -ProfileId "697e4d2960f6b181f94ff07d" -Name "Updated Profile" -GroupIds @(342, 343) -IsInclude $true
        Updates the specified scoped profile with a new name and group IDs as an include profile.

    .EXAMPLE
        $profile = Get-XdrCloudAppsConfigurationScopedProfile | Where-Object { $_.name -eq "Sales Team" }
        Set-XdrCloudAppsConfigurationScopedProfile -ProfileId $profile._id -Name "Sales Team Updated" -GroupIds $profile.groupIds -IsInclude $true
        Gets an existing profile and updates its name.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationScopedProfile -ProfileId "697e4d2960f6b181f94ff07d" -Name "Test" -GroupIds @(342) -IsInclude $false -WhatIf
        Shows what would happen if the profile were updated without making changes.

    .OUTPUTS
        System.Object
        Returns the API response confirming the update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('_id')]
        [string]$ProfileId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [int[]]$GroupIds,

        [Parameter(Mandatory = $true)]
        [bool]$IsInclude,

        [Parameter()]
        [string]$Description
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $target = "Scoped Profile '$Name' ($ProfileId)"
        $action = "Update profile settings"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Updating scoped profile: $ProfileId"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_profiles/$ProfileId/update_profile/"

                # Build the request body
                $Body = @{
                    _id       = $ProfileId
                    name      = $Name
                    groupIds  = $GroupIds
                    isInclude = $IsInclude.ToString().ToLower()
                }

                if ($PSBoundParameters.ContainsKey('Description')) {
                    $Body.description = $Description
                } else {
                    $Body.description = $null
                }

                $BodyJson = $Body | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $BodyJson"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $BodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful update
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationScopedProfile" -ErrorAction SilentlyContinue
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationScopedProfileTaggedApps_$ProfileId" -ErrorAction SilentlyContinue
                Write-Verbose "Scoped profile updated successfully"

                return $result
            } catch {
                Write-Error "Failed to update scoped profile: $_"
            }
        }
    }

    end {
    }
}
