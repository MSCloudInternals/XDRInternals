function Invoke-XdrRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",
        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",
        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = $script:session,
        [Parameter(Mandatory = $false)]
        [Hashtable]$Headers = $script:headers
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        Invoke-RestMethod -Uri $Uri -Method $Method -ContentType $ContentType -WebSession $WebSession -Headers $Headers
    }
    
    end {
        
    }
}