function Get-XdrMcasMdatpGlobalSeverityLevel {
    <#
    .SYNOPSIS
        Gets the MCAS global severity level for Defender integration.

    .DESCRIPTION
        Returns the value of mdatpGlobalSeverityLevel from MCAS general settings.
        Uses the same cache as Get-XdrMcasGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrMcasMdatpGlobalSeverityLevel
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrMcasGeneralSetting -Force:$Force
    return $settings.mdatpGlobalSeverityLevel
}
