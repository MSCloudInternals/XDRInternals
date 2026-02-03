function Remove-XdrCloudAppsConfigurationDiscoveryAppTag {
    <#
    .SYNOPSIS
        Removes a discovery app tag from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Deletes a discovery app tag from Microsoft Defender for Cloud Apps.
        This permanently removes the app tag used for cloud discovery categorization.

    .PARAMETER TagName
        The name of the discovery app tag to remove.
        Accepts pipeline input from the name or id property of app tag objects.

    .PARAMETER Confirm
        Prompts for confirmation before removing the discovery app tag.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The discovery app tag is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationDiscoveryAppTag -TagName "Test Tag"
        Removes the specified discovery app tag by name.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryAppTag | Where-Object { $_.name -eq 'Test Tag' } | Remove-XdrCloudAppsConfigurationDiscoveryAppTag
        Finds a discovery app tag by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryAppTag | Remove-XdrCloudAppsConfigurationDiscoveryAppTag -WhatIf
        Shows what would happen if all discovery app tags were removed.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryAppTag | Remove-XdrCloudAppsConfigurationDiscoveryAppTag -Confirm:$false
        Removes all discovery app tags without confirmation (use with caution).

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
        [Alias('name', 'id')]
        [string]$TagName
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # The API requires the tag name to be base64 encoded in the URL path
        $encodedTagName = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($TagName))
        $Uri = "https://security.microsoft.com/apiproxy/mcas/api/v1/discovery/app_tags/$encodedTagName/"

        if ($PSCmdlet.ShouldProcess($TagName, "Remove discovery app tag")) {
            Write-Verbose "Removing discovery app tag: $TagName (encoded: $encodedTagName)"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationDiscoveryAppTag*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed discovery app tag: $TagName"
            } catch {
                Write-Error "Failed to remove discovery app tag '$TagName': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
