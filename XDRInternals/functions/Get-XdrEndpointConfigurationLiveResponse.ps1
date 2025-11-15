function Get-XdrEndpointConfigurationLiveResponse {
    <#
    .SYNOPSIS
        Retrieves the Live Response configuration settings for XDR.
    
    .DESCRIPTION
        Gets the Live Response configuration settings from the Microsoft Defender XDR portal.
    
    .PARAMETER session
        The web session to use for the request. Defaults to the global session variable.
    
    .PARAMETER headers
        The headers to use for the request. Defaults to the global headers variable.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationLiveResponse
        Retrieves the Live Response configuration using the global session and headers.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Live Response configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/get_properties?useV2Api=true&useV3Api=true" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
