function Set-XdrCloudAppsConfigurationDiscoveryEncryption {
    <#
    .SYNOPSIS
        Sets discovery encryption settings in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Configures the anonymization settings for Cloud Discovery in Microsoft Defender for Cloud Apps.
        This controls whether user names and machine names are anonymized in Cloud Discovery reports.
        Anonymizing data helps protect privacy by replacing identifiable information with anonymized values.

    .PARAMETER AnonymizeUsers
        Specifies whether to anonymize user names in Cloud Discovery reports.
        Set to $true to enable user anonymization, $false to disable it.

    .PARAMETER AnonymizeMachines
        Specifies whether to anonymize machine names in Cloud Discovery reports.
        Set to $true to enable machine anonymization, $false to disable it.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationDiscoveryEncryption -AnonymizeUsers $true
        Enables anonymization of user names in Cloud Discovery reports.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationDiscoveryEncryption -AnonymizeMachines $true
        Enables anonymization of machine names in Cloud Discovery reports.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationDiscoveryEncryption -AnonymizeUsers $false -AnonymizeMachines $false
        Disables anonymization for both users and machines in Cloud Discovery reports.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationDiscoveryEncryption -AnonymizeUsers $true -WhatIf
        Shows what would happen if user anonymization were enabled.

    .OUTPUTS
        System.Object
        Returns the API response confirming the update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter()]
        [bool]$AnonymizeUsers,

        [Parameter()]
        [bool]$AnonymizeMachines
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Build the request body based on provided parameters
        $Body = @{}

        if ($PSBoundParameters.ContainsKey('AnonymizeUsers')) {
            $Body['anonymizeUsers'] = $AnonymizeUsers
        }

        if ($PSBoundParameters.ContainsKey('AnonymizeMachines')) {
            $Body['anonymizeMachines'] = $AnonymizeMachines
        }

        if ($Body.Count -eq 0) {
            Write-Warning "No parameters specified. Please provide at least one of -AnonymizeUsers or -AnonymizeMachines."
            return
        }

        $target = "Cloud Apps Discovery Encryption Settings"
        $changes = @()
        if ($PSBoundParameters.ContainsKey('AnonymizeUsers')) {
            $changes += "AnonymizeUsers=$AnonymizeUsers"
        }
        if ($PSBoundParameters.ContainsKey('AnonymizeMachines')) {
            $changes += "AnonymizeMachines=$AnonymizeMachines"
        }
        $action = "Update: $($changes -join ', ')"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Updating discovery encryption settings"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/settings/anonymize_users/"

                $JsonBody = $Body | ConvertTo-Json

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $JsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful update
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationDiscoveryEncryption" -ErrorAction SilentlyContinue
                Write-Verbose "Discovery encryption settings updated successfully"

                return $result
            } catch {
                Write-Error "Failed to update discovery encryption settings: $_"
            }
        }
    }

    end {
    }
}
