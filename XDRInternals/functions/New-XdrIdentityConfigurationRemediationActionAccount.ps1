function New-XdrIdentityConfigurationRemediationActionAccount {
    <#
    .SYNOPSIS
        Registers a new remediation action account for Microsoft Defender for Identity.

    .DESCRIPTION
        Creates a new Group Managed Service Account (gMSA) registration for Microsoft Defender for Identity
        remediation actions. This account will be used by MDI to perform automatic remediation actions
        when the system is configured to use a dedicated account instead of Local System.

    .PARAMETER AccountName
        The name of the Group Managed Service Account (without domain suffix).

    .PARAMETER DomainDnsName
        The fully qualified domain name (FQDN) where the account exists.

    .PARAMETER IsSingleLabelAccountDomainName
        Switch parameter indicating if the domain is a single-label domain name.
        Use this for non-standard domain configurations.

    .EXAMPLE
        New-XdrIdentityConfigurationRemediationActionAccount -AccountName "MDIRemediation" -DomainDnsName "contoso.com"
        Registers a gMSA account named "MDIRemediation" in the contoso.com domain for MDI remediation actions.

    .EXAMPLE
        New-XdrIdentityConfigurationRemediationActionAccount -AccountName "DefenderRemediator" -DomainDnsName "corp.contoso.com" -IsSingleLabelAccountDomainName
        Registers a gMSA account with single-label domain name configuration.

    .PARAMETER Confirm
        Prompts for confirmation before registering the account.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .OUTPUTS
        Object
        Returns the registration response from the API including the account configuration details.

    .NOTES
        - The account must be a Group Managed Service Account (gMSA)
        - The account must already exist in Active Directory before registration
        - The MDI sensor must have permissions to retrieve the gMSA password
        - Before using this, ensure Set-XdrIdentityConfigurationRemediationActionAccount is configured to not use Local System
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName,

        [Parameter()]
        [switch]$IsSingleLabelAccountDomainName
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/aatp/odata/EntityRemediatorCredentials"
        
        $body = @{
            Id                             = ""
            AccountName                    = $AccountName
            DomainDnsName                  = $DomainDnsName
            AccountPassword                = $null
            IsGroupManagedServiceAccount   = $true
            IsSingleLabelAccountDomainName = $IsSingleLabelAccountDomainName.IsPresent
        } | ConvertTo-Json

        $fullAccountName = "$AccountName@$DomainDnsName"
        
        if ($PSCmdlet.ShouldProcess($fullAccountName, "Register new remediation action account")) {
            try {
                Write-Verbose "Registering remediation action account: $fullAccountName"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers -AllowInsecureRedirect
            
                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "XdrIdentityConfigurationRemediationActionAccount" -ErrorAction SilentlyContinue
            
                Write-Verbose "Successfully registered remediation action account"
                return $result
            } catch {
                Write-Error "Failed to register remediation action account: $_"
            }
        }
    }

    end {

    }
}
