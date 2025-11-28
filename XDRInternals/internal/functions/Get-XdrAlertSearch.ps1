function Get-XdrAlertSearch {
    <#
    .SYNOPSIS
        Internal helper function to search for alerts by ID or title.

    .DESCRIPTION
        Searches for alerts using a search term (ID or title).
        This is an internal function used for alert validation and lookup.

    .PARAMETER SearchTerm
        The term to search for (Alert ID or Title).

    .PARAMETER Limit
        Number of results to return. Default is 10.
    
    .EXAMPLE
        Get-XdrAlertSearch -SearchTerm "ed638962183442188554_-691007355"
        Searches for alerts matching the specified alert ID.

    .OUTPUTS
        Object[]
        Returns an array of alert objects with name and id properties.
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchTerm,

        [Parameter()]
        [int]$Limit = 10
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/alerts/searchAlertTitlesandId?searchTerm=$([System.Web.HttpUtility]::UrlEncode($SearchTerm))&limit=$Limit"

            $response = Invoke-XdrRestMethod -Uri $Uri -Method GET -ErrorAction Stop

            return $response
        } catch {
            Write-Error "Failed to search for alert: $_"
        }
    }
}
