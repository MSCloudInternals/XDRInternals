function Get-XdrCloudAppsCustomWarnUrl {
    <#
    .SYNOPSIS
        Gets the Cloud Apps customWarnURL list.

    .DESCRIPTION
        Returns the value of customWarnURL from Cloud Apps general settings.
        Uses the same cache as Get-XdrCloudAppsGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsCustomWarnUrl
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrCloudAppsGeneralSetting -Force:$Force
    return $settings.customWarnURL
}

