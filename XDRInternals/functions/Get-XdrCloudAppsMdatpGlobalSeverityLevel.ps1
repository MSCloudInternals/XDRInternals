function Get-XdrCloudAppsMdatpGlobalSeverityLevel {
    <#
    .SYNOPSIS
        Gets the Cloud Apps global severity level for Defender integration.

    .DESCRIPTION
        Returns the value of mdatpGlobalSeverityLevel from Cloud Apps general settings.
        Uses the same cache as Get-XdrCloudAppsGeneralSetting and supports -Force to bypass it.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsMdatpGlobalSeverityLevel
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    $settings = Get-XdrCloudAppsGeneralSetting -Force:$Force
    return $settings.mdatpGlobalSeverityLevel
}

