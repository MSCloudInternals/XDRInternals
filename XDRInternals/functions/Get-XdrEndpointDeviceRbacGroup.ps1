function Get-XdrEndpointDeviceRbacGroup {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/userExposedRbacGroups/UserExposedRbacGroups"
        Write-Verbose "Retrieving XDR Endpoint device RBAC groups"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
        
    }
}