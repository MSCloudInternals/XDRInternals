function Get-XdrEndpointConfigurationIntuneConnection {
    <#
    .SYNOPSIS
        Retrieves the Intune connection status for XDR.
    
    .DESCRIPTION
        Gets the Intune onboarding connection status from the Microsoft Defender XDR portal.
    
    .PARAMETER session
        The web session to use for the request. Defaults to the global session variable.
    
    .PARAMETER headers
        The headers to use for the request. Defaults to the global headers variable.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationIntuneConnection
        Retrieves the Intune connection status using the global session and headers.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Intune Connection configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/onboarding/intune/status" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
