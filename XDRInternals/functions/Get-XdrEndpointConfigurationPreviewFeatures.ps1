function Get-XdrEndpointConfigurationPreviewFeatures {
    <#
    .SYNOPSIS
        Retrieves the preview features configuration for XDR.
    
    .DESCRIPTION
        Gets the preview experience settings from the Microsoft Defender XDR portal.
    
    .PARAMETER session
        The web session to use for the request. Defaults to the global session variable.
    
    .PARAMETER headers
        The headers to use for the request. Defaults to the global headers variable.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPreviewFeatures
        Retrieves the preview features configuration using the global session and headers.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Preview Features configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
