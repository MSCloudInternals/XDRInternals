function Get-XdrEndpointConfigurationPotentiallyUnwantedApplications {
    <#
    .SYNOPSIS
        Retrieves the potentially unwanted applications (PUA) configuration for XDR.
    
    .DESCRIPTION
        Gets the configuration settings for potentially unwanted applications from the Microsoft Defender XDR portal.
    
    .PARAMETER session
        The web session to use for the request. Defaults to the global session variable.
    
    .PARAMETER headers
        The headers to use for the request. Defaults to the global headers variable.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPotentiallyUnwantedApplications
        Retrieves the PUA configuration using the global session and headers.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Potentially Unwanted Applications configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/ui/properties/" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
