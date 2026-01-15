function Get-XdrConfigurationPreviewFeatures {
    <#
    .SYNOPSIS
        Retrieves the configuration for Defender XDR Preview features.

    .DESCRIPTION
        Retrieves the configuration for Defender XDR Preview features.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationPreviewFeatures
        Retrieves the configuration for Defender XDR Preview features.

    .EXAMPLE
        Get-XdrConfigurationPreviewFeatures -Force
        Forces a fresh retrieval, bypassing the cache.

    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrConfigurationPreviewFeatures" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Get-XdrConfigurationPreviewFeatures data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrConfigurationPreviewFeatures"
        } else {
            Write-Verbose "Get-XdrConfigurationPreviewFeatures cache is missing or expired"
        }

        Write-Verbose "Retrieving Get-XdrConfigurationPreviewFeatures data for Microsoft Defender XDR + Microsoft Defender for Identity"
        $XdrAndMdi = "https://security.microsoft.com/apiproxy/mtp/settings/GetPreviewExperienceSetting?context=MtpContext"
        $XdrAndMdiResult = Invoke-RestMethod -Uri $XdrAndMdi -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        
        Write-Verbose "Retrieving Get-XdrConfigurationPreviewFeatures data for Microsoft Defender for Endpoint"
        $Mde = "https://security.microsoft.com/apiproxy/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext"
        $MdeResult = Invoke-RestMethod -Uri $Mde -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        
        Write-Verbose "Retrieving Get-XdrConfigurationPreviewFeatures data for Defender for Cloud Apps"
        $Mda = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/preview_features/get/"
        $MdaResult = Invoke-RestMethod -Uri $Mda -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Write-Verbose "Retrieving Get-XdrConfigurationPreviewFeatures data for Defender for Cloud"
        $Mdc = "https://security.microsoft.com/apiproxy/mdc/management/optin"
        $MdcResult = Invoke-RestMethod -Uri $Mdc -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        $result = [ordered]@{
            "XDR+MDI" = if ($XdrAndMdiResult.IsOptIn -eq $true) { "Enabled" } elseif ($XdrAndMdiResult.IsOptIn -eq $false) { "Disabled" } else { "Unknown" }
            "MDE"     = if ($MdeResult.IsOptIn -eq $true) { "Enabled" } elseif ($MdeResult.IsOptIn -eq $false) { "Disabled" } else { "Unknown" }
            "MDA"     = if ($MdaResult.previewFeaturesEnabled -eq $true) { "Enabled" } elseif ($MdaResult.previewFeaturesEnabled -eq $false) { "Disabled" } else { "Unknown" }
            "MDC"     = if ($MdcResult.isOptIn -eq $true) { "Enabled" } elseif ($MdcResult.isOptIn -eq $false) { "Disabled" } else { "Unknown" }
        }

        Set-XdrCache -CacheKey "GetXdrConfigurationPreviewFeatures" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}