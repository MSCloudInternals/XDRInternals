function Revoke-XdrCloudAppsConfigurationApiToken {
    <#
    .SYNOPSIS
        Revokes an API token in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Revokes an API token in Microsoft Defender for Cloud Apps.
        This permanently invalidates the token, preventing any further API access using it.

    .PARAMETER TokenId
        The unique identifier of the API token to revoke.
        Accepts pipeline input from the _id property of API token objects.

    .PARAMETER Confirm
        Prompts for confirmation before revoking the API token.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The API token is not revoked.

    .EXAMPLE
        Revoke-XdrCloudAppsConfigurationApiToken -TokenId "abc123def456"
        Revokes the specified API token.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationApiToken | Where-Object { $_.name -eq 'Test Token' } | Revoke-XdrCloudAppsConfigurationApiToken
        Finds an API token by name and revokes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationApiToken | Revoke-XdrCloudAppsConfigurationApiToken -WhatIf
        Shows what would happen if all API tokens were revoked.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationApiToken | Where-Object { $_.expired -eq $true } | Revoke-XdrCloudAppsConfigurationApiToken -Confirm:$false
        Revokes all expired API tokens without confirmation.

    .OUTPUTS
        None
        This cmdlet does not return any output upon successful revocation.

    .NOTES
        This operation requires confirmation by default due to high impact.
        Use -Confirm:$false to bypass confirmation in scripts.
        This cmdlet uses POST method instead of DELETE as required by the API.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is implemented')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$TokenId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/tokens/$TokenId/revoke/"

        if ($PSCmdlet.ShouldProcess($TokenId, "Revoke API token")) {
            Write-Verbose "Revoking API token: $TokenId"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlets
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationApiToken*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully revoked API token: $TokenId"
            } catch {
                Write-Error "Failed to revoke API token '$TokenId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
