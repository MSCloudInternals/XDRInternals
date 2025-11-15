function Get-XdrEndpointDeviceModel {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allModels"
        Write-Verbose "Retrieving XDR Endpoint device models"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
        
    }
}