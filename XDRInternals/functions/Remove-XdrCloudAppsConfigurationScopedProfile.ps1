function Remove-XdrCloudAppsConfigurationScopedProfile {
    <#
    .SYNOPSIS
        Removes a scoped profile from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Deletes a scoped profile from Microsoft Defender for Cloud Apps. Optionally,
        the profile can be removed from all apps before deletion using the -RemoveFromAllApps switch.

    .PARAMETER ProfileId
        The unique identifier of the scoped profile to remove.
        Accepts pipeline input from the _id property of scoped profile objects.

    .PARAMETER RemoveFromAllApps
        If specified, removes the profile from all associated apps before deleting the profile.
        This calls the remove_from_all_apps API endpoint first, then deletes the profile.

    .PARAMETER Confirm
        Prompts for confirmation before removing the profile.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The profile is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationScopedProfile -ProfileId "abc123def456"
        Removes the specified scoped profile.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationScopedProfile -ProfileId "abc123def456" -RemoveFromAllApps
        Removes the profile from all apps first, then deletes the profile.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedProfile | Where-Object { $_.name -eq 'Test Profile' } | Remove-XdrCloudAppsConfigurationScopedProfile
        Finds a profile by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedProfile | Remove-XdrCloudAppsConfigurationScopedProfile -WhatIf
        Shows what would happen if all scoped profiles were removed.

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
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$ProfileId,

        [Parameter()]
        [switch]$RemoveFromAllApps
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $BaseUri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_profiles"

        if ($PSCmdlet.ShouldProcess($ProfileId, "Remove scoped profile")) {
            try {
                if ($RemoveFromAllApps) {
                    Write-Verbose "Removing scoped profile $ProfileId from all apps"
                    $RemoveFromAllAppsUri = "$BaseUri/remove_from_all_apps/"
                    $body = @{
                        profileId = $ProfileId
                    } | ConvertTo-Json -Compress

                    $null = Invoke-RestMethod -Uri $RemoveFromAllAppsUri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                    Write-Verbose "Successfully removed profile from all apps"
                }

                Write-Verbose "Deleting scoped profile: $ProfileId"
                $DeleteUri = "$BaseUri/$ProfileId/"

                $null = Invoke-RestMethod -Uri $DeleteUri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationScopedProfile*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed scoped profile: $ProfileId"
            } catch {
                Write-Error "Failed to remove scoped profile '$ProfileId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
