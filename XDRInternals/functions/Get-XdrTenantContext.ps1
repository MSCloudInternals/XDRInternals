function Get-XdrTenantContext {
    <#
    .SYNOPSIS
        Retrieves the tenant context information for XDR.
    
    .DESCRIPTION
        Gets the tenant context information from the Microsoft Defender XDR portal,
        including tenant settings and configuration details.
    
    .PARAMETER session
        The web session to use for the request. Defaults to the global session variable.
    
    .PARAMETER headers
        The headers to use for the request. Defaults to the global headers variable.
    
    .EXAMPLE
        Get-XdrTenantContext
        Retrieves the tenant context using the global session and headers.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }
    process {
        Write-Verbose "Retrieving XDR Tenant Context"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext?realTime=true" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
