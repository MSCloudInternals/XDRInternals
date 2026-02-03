function Get-XdrCloudAppsConfigurationLocation {
    <#
    .SYNOPSIS
        Searches for locations in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Searches for locations in Microsoft Defender for Cloud Apps based on a query string.
        This function is useful for finding geographic locations by name, city, or country
        when configuring location-based policies or IP range assignments.
        This function does not use caching as it performs search-based queries.

    .PARAMETER Query
        The search query string to find locations. This can be a city name,
        country name, or partial location string.

    .PARAMETER MaxResults
        The maximum number of results to return. Default is 20.
        Valid range is 1 to 100.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLocation -Query "Seattle"
        Searches for locations matching "Seattle".

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLocation -Query "United States" -MaxResults 50
        Searches for locations matching "United States" and returns up to 50 results.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLocation -Query "London" -MaxResults 10
        Searches for locations matching "London" and returns up to 10 results.

    .OUTPUTS
        XdrCloudAppsConfigurationLocation[]
        Returns an array of location objects matching the search query.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Query,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$MaxResults = 20
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $EncodedQuery = [System.Uri]::EscapeDataString($Query)
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/locations/find_location/?query=$EncodedQuery&max_results=$MaxResults"

        Write-Verbose "Searching for Cloud Apps locations matching '$Query'"

        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationLocation')
                }
            }

            return $result
        } catch {
            Write-Error "Failed to search Cloud Apps locations: $_"
        }
    }

    end {
    }
}
