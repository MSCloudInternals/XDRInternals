function Get-XdrIdentityIdentityCount {
    <#
    .SYNOPSIS
        Retrieves the total count of identities matching the specified filters.
    
    .DESCRIPTION
        Gets the total count of identities from Microsoft Defender for Identity based on the provided filters and search text.
        This is an internal function used for pagination support.
    
    .PARAMETER Filters
        The filters to apply when counting identities.
    
    .PARAMETER SearchText
        Text to search for in identities.
    
    .EXAMPLE
        Get-XdrIdentityIdentityCount -Filters @{} -SearchText ""
        Gets the total count of all identities.
    
    .EXAMPLE
        Get-XdrIdentityIdentityCount -Filters @{ IdentityProviders = @{ has = @('ActiveDirectory') } } -SearchText "admin"
        Gets the count of Active Directory identities matching "admin".
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Filters,
        
        [Parameter()]
        [string]$SearchText = ""
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $body = @{
            Filters    = $Filters
            SearchText = $SearchText
        }
        
        try {
            $Uri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/identities/count"
            Write-Verbose "Retrieving XDR identity count (SearchText: '$SearchText')"
            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers
        
            return $result
        } catch {
            Write-Error "Failed to retrieve XDR identity count: $_"
            throw
        }
    }
    
    end {
        
    }
}
