function Get-XdrCloudAppsAppControlEnabled {
    <#
    .SYNOPSIS
        Gets the Cloud Apps App Control enabled state.

    .DESCRIPTION
        Returns the value of appControlEnabled from Cloud Apps general settings.
        Uses the same cache as Get-XdrCloudAppsGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppControlEnabled

    .EXAMPLE
        Get-XdrCloudAppsAppControlEnabled -Force
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrCloudAppsGeneralSetting -Force:$Force
    return $settings.appControlEnabled
}

