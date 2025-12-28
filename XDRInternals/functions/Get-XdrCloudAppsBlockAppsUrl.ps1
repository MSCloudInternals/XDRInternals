function Get-XdrCloudAppsBlockAppsUrl {
    <#
    .SYNOPSIS
        Gets the Cloud Apps blockAppsURL list.

    .DESCRIPTION
        Returns the value of blockAppsURL from Cloud Apps general settings.
        Uses the same cache as Get-XdrCloudAppsGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsBlockAppsUrl
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrCloudAppsGeneralSetting -Force:$Force
    return $settings.blockAppsURL
}
