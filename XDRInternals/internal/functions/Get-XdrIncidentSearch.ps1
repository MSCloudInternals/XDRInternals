function Get-XdrIncidentSearch {
    <#
    .SYNOPSIS
        Internal helper function to search for incidents by partial ID or term.

    .DESCRIPTION
        Searches for incidents using a partial incident ID or search term.
        This is an internal function used for incident validation and lookup.
        Maximum page size is 300.

    .PARAMETER Term
        Search term or partial incident ID to search for.

    .PARAMETER PageSize
        Number of results to return. Maximum is 300. Default is 300.

    .EXAMPLE
        Get-XdrIncidentSearch -Term "2581"
        Searches for incidents matching the term "2581".

    .EXAMPLE
        Get-XdrIncidentSearch -Term "phishing" -PageSize 50
        Searches for incidents with "phishing" in the title, returning up to 50 results.

    .OUTPUTS
        Object[]
        Returns an array of incident objects with IncidentId and Title properties.

    .NOTES
        This is an internal helper function not exported from the module.
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Term,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$PageSize = 3
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/incidentSearch?term=$([System.Web.HttpUtility]::UrlEncode($Term))&pageSize=$PageSize"
            Write-Verbose "Searching for incidents with term: $Term (PageSize: $PageSize)"
            
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            if ($result) {
                Write-Verbose "Found $($result.Count) incident(s) matching term: $Term"
                return $result
            } else {
                Write-Verbose "No incidents found matching term: $Term"
                return @()
            }
        } catch {
            Write-Error "Failed to search for incidents with term '$Term': $($_.Exception.Message)"
            throw
        }
    }

    end {

    }
}
