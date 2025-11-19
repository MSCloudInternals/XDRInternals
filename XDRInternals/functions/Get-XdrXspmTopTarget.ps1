function Get-XdrXspmTopTarget {
    <#
    .SYNOPSIS
        Retrieves top targets from Microsoft Defender XDR XSPM attack paths.

    .DESCRIPTION
        Gets the top targets from active and new attack paths in the XSPM (Extended Security Posture Management) API.
        Targets are the critical assets that attackers are attempting to compromise through attack paths.
        Results are summarized by target ID and ordered by the number of attack paths targeting each asset.
        Returns the top 3 targets by default.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Top
        The maximum number of top targets to return. Default is 3.
        Note: The query includes "top N" logic embedded.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrXspmTopTarget
        Retrieves the top 3 targets from active and new attack paths.

    .EXAMPLE
        Get-XdrXspmTopTarget -Top 10
        Retrieves the top 10 targets from active and new attack paths.

    .EXAMPLE
        Get-XdrXspmTopTarget -Force
        Retrieves the top targets, bypassing the cache.

    .OUTPUTS
        Array
        Returns an array of target objects containing TargetId, TargetName, and count (number of attack paths).
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
        # Define the top targets query
        $query = @"
AttackPathsV2
| where Status in ('Active', 'New')
| summarize AttackPathsCount=count(), TargetName=take_any(tostring(Target.Name)) by TargetId=tostring(Target.Id)
| top $Top by AttackPathsCount
"@

        Write-Verbose "Retrieving top $Top targets from attack paths"

        try {
            $queryResult = Invoke-XdrXspmHuntingQuery -Query $query -ScenarioName "AttackPathOverview_get_attack_paths_top_targets" -Top 0 -Skip 0 -Force:$Force

            if ($queryResult.data) {
                Write-Verbose "Retrieved $($queryResult.data.Count) top targets"
                return $queryResult.data
            } else {
                Write-Verbose "No targets found"
                return @()
            }
        } catch {
            Write-Error "Failed to retrieve top targets: $_"
            throw
        }
    }

    end {

    }
}
