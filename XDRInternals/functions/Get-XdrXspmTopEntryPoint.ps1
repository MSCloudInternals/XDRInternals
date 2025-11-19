function Get-XdrXspmTopEntryPoint {
    <#
    .SYNOPSIS
        Retrieves top entry points from Microsoft Defender XDR XSPM attack paths.

    .DESCRIPTION
        Gets the top entry points from active and new attack paths in the XSPM (Extended Security Posture Management) API.
        Entry points are the initial access points that attackers could use to begin an attack path.
        Results are summarized by entry point ID and ordered by the number of attack paths using each entry point.
        Returns the top 10 entry points by default.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Top
        The maximum number of top entry points to return. Default is 10.
        Note: The query includes "top 10" logic, so values other than 10 may not affect results unless the query is modified.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrXspmTopEntryPoint
        Retrieves the top 10 entry points from active and new attack paths.

    .EXAMPLE
        Get-XdrXspmTopEntryPoint -Force
        Retrieves the top entry points, bypassing the cache.

    .OUTPUTS
        Array
        Returns an array of entry point objects containing EntryPointId, EntryPointName, and AttackPathsCount.
    #>
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$Top = 10,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Define the top entry points query
        $query = @"
AttackPathsV2
| where Status in ('Active', 'New')
| summarize AttackPathsCount=count(), EntryPointName=take_any(tostring(EntryPoint.Name)) by EntryPointId=tostring(EntryPoint.Id)
| top $Top by AttackPathsCount
"@

        Write-Verbose "Retrieving top $Top entry points from attack paths"

        try {
            $queryResult = Invoke-XdrXspmHuntingQuery -Query $query -ScenarioName "AttackPathOverview_get_attack_paths_top_entry_points" -Top 0 -Skip 0 -Force:$Force

            if ($queryResult.data) {
                Write-Verbose "Retrieved $($queryResult.data.Count) top entry points"
                return $queryResult.data
            } else {
                Write-Verbose "No entry points found"
                return @()
            }
        } catch {
            Write-Error "Failed to retrieve top entry points: $_"
            throw
        }
    }

    end {

    }
}
