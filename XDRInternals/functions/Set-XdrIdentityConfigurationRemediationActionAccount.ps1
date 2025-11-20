function Set-XdrIdentityConfigurationRemediationActionAccount {
    <#
    .SYNOPSIS
        Configures the remediation action account type for Microsoft Defender for Identity.

    .DESCRIPTION
        Sets whether Microsoft Defender for Identity uses the Local System account or a dedicated
        account for remediation actions. This configuration determines which account type is used
        when MDI performs automatic remediation actions on identified threats.

    .PARAMETER UseLocalSystem
        Switch parameter to enable the use of Local System account for remediation actions.
        If not specified, the configuration is set to use a dedicated remediation account.

    .PARAMETER Confirm
        Prompts for confirmation before creating each rule.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrIdentityConfigurationRemediationActionAccount -UseLocalSystem
        Configures MDI to use the Local System account for remediation actions.

    .EXAMPLE
        Set-XdrIdentityConfigurationRemediationActionAccount
        Configures MDI to use a dedicated account for remediation actions.

    .OUTPUTS
        Object
        Returns the configuration response from the API.

    .NOTES
        After switching to a dedicated account, you need to use New-XdrIdentityConfigurationRemediationActionAccount
        to register the account credentials.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter()]
        [bool]$UseLocalSystem = $true
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/aatp/api/remediationActions/configuration"

        $body = @{
            IsRemediationWithLocalSystemEnabled = $UseLocalSystem
        } | ConvertTo-Json

        $accountType = if ($UseLocalSystem) { "Local System" } else { "dedicated account" }

        if ($PSCmdlet.ShouldProcess("MDI Remediation Action Configuration", "Set remediation account type to $accountType")) {
            Write-Verbose "Configuring MDI remediation to use $accountType"
            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

            # Clear the cache for the Get cmdlet
            Clear-XdrCache -CacheKey "XdrIdentityConfigurationRemediationActionAccount" -ErrorAction SilentlyContinue

            Write-Verbose "Successfully configured remediation account type"
            return $result
        }
    }

    end {

    }
}
