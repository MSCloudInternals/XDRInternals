function Get-XdrEndpointDeviceVendors {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allVendors"
        Write-Verbose "Retrieving XDR Endpoint device vendors"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
        
    }
}