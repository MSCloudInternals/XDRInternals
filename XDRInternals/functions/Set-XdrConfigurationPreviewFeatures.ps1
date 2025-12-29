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

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
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
            Write-Verbose "Setting preview features for Microsoft Defender XDR + Microsoft Defender for Identity"
            $XdrAndMdiBody = @{ "IsOptIn" = $EnableXdrAndMdi } | ConvertTo-Json
            Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/SavePreviewExperienceSetting?context=MtpContext" -Method POST -Body $XdrAndMdiBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        }

        # Enable or disable preview features for MDE (if not null)
        if ($PSBoundParameters.ContainsKey('EnableMde')) {
            Write-Verbose "Setting preview features for Microsoft Defender for Endpoint"
            $MdeBody = @{ "IsOptIn" = $EnableMde } | ConvertTo-Json
            Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext" -Method POST -Body $MdeBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        }
    
        # Enable or disable preview features for MDA (if not null)
        if ($PSBoundParameters.ContainsKey('EnableMda')) {
            Write-Verbose "Setting preview features for Microsoft Defender for Cloud Apps"
            $MdaBody = @{ "previewFeaturesEnabled" = $EnableMda } | ConvertTo-Json
            Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/preview_features/update/" -Method POST -Body $MdaBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        }

        # Check current values after changes
        $result = Get-XdrConfigurationPreviewFeatures -Force

        return $result
    }

    end {

    }
}