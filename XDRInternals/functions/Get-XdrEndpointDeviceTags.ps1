function Get-XdrEndpointDeviceTags {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allMachinesTags"
        Write-Verbose "Retrieving XDR Endpoint Device Tags"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
        
    }
}