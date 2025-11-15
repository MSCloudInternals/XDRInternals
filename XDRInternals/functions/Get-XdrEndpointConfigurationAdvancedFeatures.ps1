function Get-XdrEndpointConfigurationAdvancedFeatures {
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
        Get-XdrEndpointConfigurationAdvancedFeatures
        Retrieves the advanced features configuration using the global session and headers.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Advanced Features configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetAdvancedFeaturesSetting" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
