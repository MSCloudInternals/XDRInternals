function Remove-XdrIdentityConfigurationRemediationActionAccount {
    <#
    .SYNOPSIS
        Removes a remediation action account from Microsoft Defender for Identity.

    .DESCRIPTION
        Deletes a registered Group Managed Service Account (gMSA) from Microsoft Defender for Identity
        remediation actions. The account will no longer be used for automatic remediation actions.

    .PARAMETER Id
        The User Principal Name (UPN) of the remediation account to remove.
        Must be in the format: accountname@domain.com
        Accepts pipeline input.

    .PARAMETER Confirm
        Prompts for confirmation before removing each account.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Remove-XdrIdentityConfigurationRemediationActionAccount -Id "MDIRemediation@contoso.com"
        Removes the specified remediation action account.

    .EXAMPLE
        "DefenderRemediator@corp.contoso.com" | Remove-XdrIdentityConfigurationRemediationActionAccount
        Removes the remediation account using pipeline input.

    .EXAMPLE
        $accounts = Get-XdrIdentityConfigurationRemediationActionAccount
        $accounts.RemediationAccounts | ForEach-Object {
            Remove-XdrIdentityConfigurationRemediationActionAccount -Id $_.Id
        }
        Removes all registered remediation accounts.

    .EXAMPLE
        Get-XdrIdentityConfigurationRemediationActionAccount |
            Select-Object -ExpandProperty RemediationAccounts |
            Remove-XdrIdentityConfigurationRemediationActionAccount
        Removes all remediation accounts using pipeline input.

    .OUTPUTS
        None
        This cmdlet does not return any output.

    .NOTES
        - The Id parameter must be a valid UPN format (accountname@domain.com)
        - No response is expected from the API after successful deletion
        - After removing an account, consider configuring MDI to use Local System or registering a new account
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^[^@]+@[^@]+\.[^@]+$', ErrorMessage = "Id must be a valid UPN format (accountname@domain.com)")]
        [string]$Id
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/aatp/odata/EntityRemediatorCredentials/delete"

        $body = @{
            id = $Id
        } | ConvertTo-Json

        if ($PSCmdlet.ShouldProcess($Id, "Remove remediation action account")) {
            Write-Verbose "Removing remediation action account: $Id"

            try {
                # No response expected from the API
                $null = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "XdrIdentityConfigurationRemediationActionAccount" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed remediation action account: $Id"
            } catch {
                Write-Error "Failed to remove remediation action account '$Id': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
