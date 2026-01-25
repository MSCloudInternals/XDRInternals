function Set-XdrConfigurationPreviewFeatures {
    <#
    .SYNOPSIS
        Sets the configuration for Defender XDR Preview features.

    .DESCRIPTION
        Sets the configuration for Defender XDR Preview features.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER EnableXdrAndMdi
        Boolean to enable or disable preview features for Microsoft Defender XDR + Microsoft Defender for Identity.

    .PARAMETER EnableMde
        Boolean to enable or disable preview features for Microsoft Defender for Endpoint.

    .PARAMETER EnableMda
        Boolean to enable or disable preview features for Microsoft Defender for Cloud Apps.

    .PARAMETER Confirm
    Prompts for confirmation before creating each rule.

    .PARAMETER WhatIf
    Shows what would happen if the cmdlet runs. The cmdlet is not run.
    
    .EXAMPLE
        Set-XdrConfigurationPreviewFeatures
        Sets the configuration for Defender XDR Preview features.

    .EXAMPLE
        Set-XdrConfigurationPreviewFeatures -EnableXdrAndMdi $true
        Enables preview features for Microsoft Defender XDR + Microsoft Defender for Identity.

    .EXAMPLE
        Set-XdrConfigurationPreviewFeatures -EnableMde $false
        Disables preview features for Microsoft Defender for Endpoint.

    .EXAMPLE
        Set-XdrConfigurationPreviewFeatures -EnableMda $true
        Enables preview features for Microsoft Defender for Cloud Apps.

    .EXAMPLE
        Set-XdrConfigurationPreviewFeatures -EnableXdrAndMdi $true -WhatIf
        Shows what would happen if preview features were enabled for XDR and MDI.

    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter()]
        [bool]$EnableXdrAndMdi,

        [Parameter()]
        [bool]$EnableMde,

        [Parameter()]
        [bool]$EnableMda
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Enable or disable preview features for XDR and MDI (if not null)
        if ($PSBoundParameters.ContainsKey('EnableXdrAndMdi')) {
            $target = "Microsoft Defender XDR + Microsoft Defender for Identity"
            $action = if ($EnableXdrAndMdi) { "Enable" } else { "Disable" }
            if ($PSCmdlet.ShouldProcess($target, "$action preview features")) {
                try {
                    Write-Verbose "Setting preview features for $target"
                    $XdrAndMdiBody = @{ "IsOptIn" = $EnableXdrAndMdi } | ConvertTo-Json
                    $null = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/SavePreviewExperienceSetting?context=MtpContext" -Method POST -Body $XdrAndMdiBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                } catch {
                    Write-Error "Failed to update preview features for ${target}: $_"
                }
            }
        }

        # Enable or disable preview features for MDE (if not null)
        if ($PSBoundParameters.ContainsKey('EnableMde')) {
            $target = "Microsoft Defender for Endpoint"
            $action = if ($EnableMde) { "Enable" } else { "Disable" }
            if ($PSCmdlet.ShouldProcess($target, "$action preview features")) {
                try {
                    Write-Verbose "Setting preview features for $target"
                    $MdeBody = @{ "IsOptIn" = $EnableMde } | ConvertTo-Json
                    $null = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext" -Method POST -Body $MdeBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                } catch {
                    Write-Error "Failed to update preview features for ${target}: $_"
                }
            }
        }
    
        # Enable or disable preview features for MDA (if not null)
        if ($PSBoundParameters.ContainsKey('EnableMda')) {
            $target = "Microsoft Defender for Cloud Apps"
            $action = if ($EnableMda) { "Enable" } else { "Disable" }
            if ($PSCmdlet.ShouldProcess($target, "$action preview features")) {
                try {
                    Write-Verbose "Setting preview features for $target"
                    $MdaBody = @{ "previewFeaturesEnabled" = $EnableMda } | ConvertTo-Json
                    $null = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/preview_features/update/" -Method POST -Body $MdaBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                } catch {
                    Write-Error "Failed to update preview features for ${target}: $_"
                }
            }
        }

        # Clear cache for preview features configuration before re-reading values
        Clear-XdrCache -CacheKey "GetXdrConfigurationPreviewFeatures" -ErrorAction SilentlyContinue
        # Check current values after changes (skip when running with -WhatIf)
        if (-not $WhatIfPreference) {
            $result = Get-XdrConfigurationPreviewFeatures -Force
            return $result
        }
    }

    end {

    }
}