function Remove-XdrCloudAppsPolicy {
    <#
    .SYNOPSIS
        Removes a Cloud Apps policy.

    .DESCRIPTION
        Removes (deletes) a policy from Microsoft Defender for Cloud Apps.
        This operation is irreversible and will permanently delete the specified policy.

    .PARAMETER PolicyId
        The unique identifier of the policy to remove. This parameter is required.
        Accepts pipeline input by property name.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet does not run.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .EXAMPLE
        Remove-XdrCloudAppsPolicy -PolicyId "abc123"

        Removes the policy with the specified ID after confirmation.

    .EXAMPLE
        Remove-XdrCloudAppsPolicy -PolicyId "abc123" -Confirm:$false

        Removes the policy without confirmation prompt.

    .EXAMPLE
        Get-XdrCloudAppsFilePolicy | Where-Object { $_.name -like "*test*" } | Remove-XdrCloudAppsPolicy

        Removes all file policies with "test" in their name using pipeline input.

    .EXAMPLE
        "policy1", "policy2" | Remove-XdrCloudAppsPolicy -WhatIf

        Shows what would happen if the specified policies were removed.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
        This cmdlet supports ShouldProcess for -WhatIf and -Confirm parameters.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policies/$PolicyId/"

        Write-Verbose "Preparing to remove Cloud Apps policy: $PolicyId"

        if ($PSCmdlet.ShouldProcess($PolicyId, "Remove Cloud Apps policy")) {
            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Write-Verbose "Successfully removed policy: $PolicyId"

                if ($result) {
                    return $result
                }
                else {
                    Write-Verbose "Policy $PolicyId deleted successfully (no response body)"
                }
            }
            catch {
                Write-Error "Failed to remove policy '$PolicyId': $_"
                throw
            }
        }
    }
}
