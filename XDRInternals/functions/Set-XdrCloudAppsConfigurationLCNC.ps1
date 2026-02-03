function Set-XdrCloudAppsConfigurationLCNC {
    <#
    .SYNOPSIS
        Sets the Low-Code/No-Code (LCNC) AI agent protection consent in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Updates the consent setting for Low-Code/No-Code (LCNC) AI agent protection
        in Microsoft Defender for Cloud Apps. This setting controls whether
        Copilot Studio AI agents are monitored and protected by Cloud Apps security.

    .PARAMETER AgentProtectionIsConsent
        Specifies whether to enable ($true) or disable ($false) the consent for
        AI agent protection monitoring in Cloud Apps.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationLCNC -AgentProtectionIsConsent $true
        Enables consent for AI agent protection monitoring.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationLCNC -AgentProtectionIsConsent $false
        Disables consent for AI agent protection monitoring.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationLCNC -AgentProtectionIsConsent $true -WhatIf
        Shows what would happen if consent were enabled without making changes.

    .OUTPUTS
        System.Object
        Returns the API response confirming the update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [bool]$AgentProtectionIsConsent
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $consentStatus = if ($AgentProtectionIsConsent) { "enabled" } else { "disabled" }
        $target = "LCNC AI Agent Protection Consent"
        $action = "Set consent to $consentStatus"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Setting LCNC AI agent protection consent to: $AgentProtectionIsConsent"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/lcnc_settings/save_consent/"

                # Build the request body
                $Body = @{
                    payload = @{
                        agentProtectionIsConsent = $AgentProtectionIsConsent
                    }
                } | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $Body"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear any related cache after successful update
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationLCNC" -ErrorAction SilentlyContinue
                Write-Verbose "LCNC consent setting updated successfully"

                return $result
            } catch {
                Write-Error "Failed to update LCNC consent setting: $_"
            }
        }
    }

    end {
    }
}
