function Get-XdrCloudAppsGeneralSetting {
    <#
    .SYNOPSIS
        Retrieves general settings from Microsoft Defender for Cloud Apps (Cloud Apps).

    .DESCRIPTION
        Compatibility wrapper for the legacy Cloud Apps general settings cmdlet.
        Calls the grouped configuration cmdlet and returns the settings object with
        the legacy output shape so existing scripts do not break.

    .PARAMETER Force
        Bypasses cache-backed requests.

    .EXAMPLE
        Get-XdrCloudAppsGeneralSetting

        Retrieves the Cloud Apps general settings.

    .EXAMPLE
        Get-XdrCloudAppsGeneralSetting -Force

        Forces a fresh retrieval of the Cloud Apps general settings.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    process {
        foreach ($item in @(Get-XdrCloudAppsConfiguration -Type Settings -Force:$Force)) {
            if ($null -eq $item) {
                continue
            }

            if ($item.PSObject.TypeNames -contains 'XdrCloudAppsConfigurationSettings') {
                [void]$item.PSObject.TypeNames.Remove('XdrCloudAppsConfigurationSettings')
            }

            $item
        }
    }
}