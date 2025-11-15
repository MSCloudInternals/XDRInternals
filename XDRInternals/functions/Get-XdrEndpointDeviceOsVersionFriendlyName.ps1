function Get-XdrEndpointDeviceOsVersionFriendlyName {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allOsVersionFriendlyNames"
        Write-Verbose "Retrieving XDR Endpoint device OS version friendly names"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
        
    }
}