function Get-XdrAdvancedFeaturesConfiguration {
    <#
    .SYNOPSIS
        Retrieves the advanced features configuration settings for XDR.
    
    .DESCRIPTION
        Gets the advanced features settings from the Microsoft Defender XDR portal.
    
    .PARAMETER session
        The web session to use for the request. Defaults to the global session variable.
    
    .PARAMETER headers
        The headers to use for the request. Defaults to the global headers variable.
    
    .EXAMPLE
        Get-XdrAdvancedFeaturesConfiguration
        Retrieves the advanced features configuration using the global session and headers.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$session = $global:session,

        [Parameter()]
        [string]$headers = $global:headers
    )
    
    Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetAdvancedFeaturesSetting" -ContentType "application/json" -WebSession $global:session -Headers $global:headers
}
