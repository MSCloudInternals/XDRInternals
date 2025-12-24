function Get-XdrMcasBlockAppsUrl {
    <#
    .SYNOPSIS
        Gets the MCAS blockAppsURL list.

    .DESCRIPTION
        Returns the value of blockAppsURL from MCAS general settings.
        Uses the same cache as Get-XdrMcasGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrMcasBlockAppsUrl
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrMcasGeneralSetting -Force:$Force
    return $settings.blockAppsURL
}
