function Get-XdrMcasAppControlEnabled {
    <#
    .SYNOPSIS
        Gets the MCAS App Control enabled state.

    .DESCRIPTION
        Returns the value of appControlEnabled from MCAS general settings.
        Uses the same cache as Get-XdrMcasGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrMcasAppControlEnabled

    .EXAMPLE
        Get-XdrMcasAppControlEnabled -Force
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrMcasGeneralSetting -Force:$Force
    return $settings.appControlEnabled
}
