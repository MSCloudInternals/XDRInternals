function Get-XdrMcasCustomWarnUrl {
    <#
    .SYNOPSIS
        Gets the MCAS customWarnURL list.

    .DESCRIPTION
        Returns the value of customWarnURL from MCAS general settings.
        Uses the same cache as Get-XdrMcasGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrMcasCustomWarnUrl
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrMcasGeneralSetting -Force:$Force
    return $settings.customWarnURL
}
