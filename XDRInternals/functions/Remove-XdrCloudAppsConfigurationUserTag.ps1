function Remove-XdrCloudAppsConfigurationUserTag {
    <#
    .SYNOPSIS
        Removes a user tag from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Removes a user tag from Microsoft Defender for Cloud Apps for a specific application.
        Note: This API uses POST with a body instead of DELETE.

    .PARAMETER TagId
        The unique identifier of the user tag to remove.
        Accepts pipeline input from the _id property of user tag objects.

    .PARAMETER AppId
        The application ID that the tag belongs to.
        For Microsoft Entra ID, use 11161.

    .PARAMETER Confirm
        Prompts for confirmation before removing the user tag.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The user tag is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationUserTag -TagId "abc123def456" -AppId 11161
        Removes the specified user tag from Microsoft Entra ID (AppId 11161).

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag | Where-Object { $_.name -eq 'Test Tag' } | Remove-XdrCloudAppsConfigurationUserTag -AppId 11161
        Finds a user tag by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag | Remove-XdrCloudAppsConfigurationUserTag -AppId 11161 -WhatIf
        Shows what would happen if all user tags were removed from the specified app.

    .OUTPUTS
        None
        This cmdlet does not return any output upon successful deletion.

    .NOTES
        This operation requires confirmation by default due to high impact.
        Use -Confirm:$false to bypass confirmation in scripts.
        Common AppId values:
        - 11161: Microsoft Entra ID (Azure AD)
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is implemented')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$TagId,

        [Parameter(Mandatory = $true)]
        [int]$AppId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/user_tags/$TagId/remove/"

        $body = @{
            appId = $AppId
        } | ConvertTo-Json -Compress

        if ($PSCmdlet.ShouldProcess($TagId, "Remove user tag")) {
            Write-Verbose "Removing user tag: $TagId from AppId: $AppId"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationUserTag*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed user tag: $TagId"
            } catch {
                Write-Error "Failed to remove user tag '$TagId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
