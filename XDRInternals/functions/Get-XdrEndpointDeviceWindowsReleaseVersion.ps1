function Get-XdrEndpointDeviceWindowsReleaseVersion {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allWindowsReleaseVersions"
        Write-Verbose "Retrieving XDR Endpoint device Windows release versions"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
        
    }
}