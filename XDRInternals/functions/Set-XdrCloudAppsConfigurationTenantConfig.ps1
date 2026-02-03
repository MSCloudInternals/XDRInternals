function Set-XdrCloudAppsConfigurationTenantConfig {
    <#
    .SYNOPSIS
        Updates an individual tenant configuration setting in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Updates an individual tenant configuration setting in Microsoft Defender for Cloud Apps.
        This cmdlet allows you to modify specific configuration values by providing the configuration
        key and the new value. Configuration values can be booleans, strings, or other types depending
        on the specific setting.

    .PARAMETER ConfigKey
        The configuration key to set. Common keys include:
        - 'resolveDiscoveryUserWithAAD' - Enable/disable user enrichment with Entra ID

    .PARAMETER ConfigValue
        The value to set for the configuration key. Can be a boolean, string, integer, or other
        types depending on the configuration key.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The configuration is not changed.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationTenantConfig -ConfigKey 'resolveDiscoveryUserWithAAD' -ConfigValue $true
        Enables user enrichment with Entra ID for cloud discovery.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationTenantConfig -ConfigKey 'resolveDiscoveryUserWithAAD' -ConfigValue $false -WhatIf
        Shows what would happen if user enrichment were disabled.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationTenantConfig -ConfigKey 'resolveDiscoveryUserWithAAD' -ConfigValue $true -Confirm:$false
        Enables user enrichment without prompting for confirmation.

    .OUTPUTS
        System.Object
        Returns the API response confirming the configuration change.

    .NOTES
        This cmdlet clears the tenant configuration cache after a successful update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigKey,

        [Parameter(Mandatory = $true)]
        [object]$ConfigValue
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $target = "Tenant Configuration '$ConfigKey'"
        $action = "Set value to '$ConfigValue'"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Setting tenant configuration: $ConfigKey = $ConfigValue"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/tenant_config/set_config/"

                # Build the request body
                $Body = @{
                    pk    = $ConfigKey
                    value = $ConfigValue
                }

                $BodyJson = $Body | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $BodyJson"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $BodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful update
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationTenantConfig" -ErrorAction SilentlyContinue
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationInfo" -ErrorAction SilentlyContinue
                Write-Verbose "Tenant configuration updated successfully"

                return $result
            } catch {
                Write-Error "Failed to update tenant configuration: $_"
            }
        }
    }

    end {
    }
}
