function Get-XdrEndpointConfigurationPurviewSharing {
    <#
    .SYNOPSIS
        Retrieves the Purview alert sharing configuration for XDR.
    
    .DESCRIPTION
        Gets the Purview alert sharing status and configuration from the Microsoft Defender XDR portal.
    
    .PARAMETER session
        The web session to use for the request. Defaults to the global session variable.
    
    .PARAMETER headers
        The headers to use for the request. Defaults to the global headers variable.
    
    .EXAMPLE
        Get-XdrEndpointConfigurationPurviewSharing
        Retrieves the Purview sharing configuration using the global session and headers.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Write-Verbose "Retrieving XDR Purview Sharing configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/wdatpInternalApi/compliance/alertSharing/status" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
