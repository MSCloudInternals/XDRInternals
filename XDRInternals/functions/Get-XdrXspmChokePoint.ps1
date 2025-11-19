function Get-XdrXspmChokePoint {
    <#
    .SYNOPSIS
        Retrieves choke point data from Microsoft Defender XDR XSPM.

    .DESCRIPTION
        Gets choke point information from the XSPM (Extended Security Posture Management) attack surface API.
        Choke points are critical nodes in the network that appear in multiple attack paths, making them
        high-value targets for security hardening and monitoring.
        The results are ordered by risk level (Critical, High, Medium, Low) and attack path count.
        Supports pagination and can retrieve all available choke points when using the -All parameter.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Top
        The maximum number of choke points to return per page. Default is 100.
        Ignored when -All is specified.

    .PARAMETER Skip
        The number of choke points to skip for pagination. Default is 0.
        Ignored when -All is specified.

    .PARAMETER All
        When specified, retrieves all available choke points by handling pagination automatically.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrXspmChokePoint
        Retrieves the first 100 choke points, ordered by risk level and attack path count.

    .EXAMPLE
        Get-XdrXspmChokePoint -Top 50
        Retrieves the first 50 choke points.

    .EXAMPLE
        Get-XdrXspmChokePoint -Top 100 -Skip 100
        Retrieves choke points 101-200 (pagination).

    .EXAMPLE
        Get-XdrXspmChokePoint -All
        Retrieves all available choke points by automatically handling pagination.

    .EXAMPLE
        Get-XdrXspmChokePoint -All -Force
        Retrieves all choke points, bypassing the cache.

    .OUTPUTS
        Array
        Returns an array of choke point objects containing node information, attack path counts, and risk levels.
    #>
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$Top = 100,

        [Parameter()]
        [int]$Skip = 0,

        [Parameter()]
        [switch]$All,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Define the choke point query
        $query = @"
AttackPathDiscovery
| where AttackPathsCount > 1
| extend RiskOrder=case(MaxRiskLevel == 'Critical', 0,
	MaxRiskLevel == 'High', 1,
	MaxRiskLevel == 'Medium', 2,
	MaxRiskLevel == 'Low', 3, 4)
| order by RiskOrder asc, AttackPathsCount desc
"@

        if ($All) {
            Write-Verbose "Retrieving all choke points with automatic pagination"

            $allChokePoints = @()
            $currentSkip = 0
            $pageSize = 100

            do {
                Write-Verbose "Fetching page starting at record $currentSkip"

                try {
                    $queryResult = Invoke-XdrXspmHuntingQuery -Query $query -ScenarioName "ChokePoints_get_choke_point_types_filter" -Top $pageSize -Skip $currentSkip -Force:$Force

                    if ($queryResult.data -and $queryResult.data.Count -gt 0) {
                        $allChokePoints += $queryResult.data
                        Write-Verbose "Retrieved $($queryResult.data.Count) choke points (Total so far: $($allChokePoints.Count))"

                        # Check if we've retrieved all records
                        if ($queryResult.totalRecords -le ($currentSkip + $queryResult.data.Count)) {
                            Write-Verbose "All choke points retrieved. Total: $($allChokePoints.Count)"
                            break
                        }

                        $currentSkip += $pageSize
                    } else {
                        Write-Verbose "No more choke points to retrieve"
                        break
                    }
                } catch {
                    Write-Error "Failed to retrieve choke points at skip position $currentSkip : $_"
                    throw
                }
            } while ($true)

            return $allChokePoints
        } else {
            # Single page retrieval
            Write-Verbose "Retrieving choke points (Top: $Top, Skip: $Skip)"

            try {
                $queryResult = Invoke-XdrXspmHuntingQuery -Query $query -ScenarioName "ChokePoints_get_choke_point_types_filter" -Top $Top -Skip $Skip -Force:$Force

                if ($queryResult.data) {
                    Write-Verbose "Retrieved $($queryResult.data.Count) of $($queryResult.totalRecords) total choke points"
                    return $queryResult.data
                } else {
                    Write-Verbose "No choke points found"
                    return @()
                }
            } catch {
                Write-Error "Failed to retrieve choke points: $_"
                throw
            }
        }
    }

    end {

    }
}
