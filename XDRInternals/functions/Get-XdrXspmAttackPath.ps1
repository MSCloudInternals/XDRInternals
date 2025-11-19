function Get-XdrXspmAttackPath {
    <#
    .SYNOPSIS
        Retrieves attack path data from Microsoft Defender XDR XSPM.

    .DESCRIPTION
        Gets attack path information from the XSPM (Extended Security Posture Management) attack surface API.
        Attack paths represent potential routes attackers could take to compromise critical assets.
        Supports pagination and can retrieve all available attack paths when using the -All parameter.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Top
        The maximum number of attack paths to return per page. Default is 100.
        Ignored when -All is specified.

    .PARAMETER Skip
        The number of attack paths to skip for pagination. Default is 0.
        Ignored when -All is specified.

    .PARAMETER All
        When specified, retrieves all available attack paths by handling pagination automatically.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrXspmAttackPath
        Retrieves the first 100 attack paths.

    .EXAMPLE
        Get-XdrXspmAttackPath -Top 50
        Retrieves the first 50 attack paths.

    .EXAMPLE
        Get-XdrXspmAttackPath -Top 100 -Skip 100
        Retrieves attack paths 101-200 (pagination).

    .EXAMPLE
        Get-XdrXspmAttackPath -All
        Retrieves all available attack paths by automatically handling pagination.

    .EXAMPLE
        Get-XdrXspmAttackPath -All -Force
        Retrieves all attack paths, bypassing the cache.

    .OUTPUTS
        Array
        Returns an array of attack path objects containing entry points, targets, paths, risk scores, and status information.
    #>
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$Top = 0,

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
        if ($All) {
            Write-Verbose "Retrieving all attack paths with automatic pagination"

            $allAttackPaths = @()
            $currentSkip = 0
            $pageSize = 100

            do {
                Write-Verbose "Fetching page starting at record $currentSkip"

                try {
                    $queryResult = Invoke-XdrXspmHuntingQuery -Query "AttackPathsV2" -ScenarioName "AttackPathOverview_get_has_attack_paths" -Top $pageSize -Skip $currentSkip -Force:$Force

                    if ($queryResult.data -and $queryResult.data.Count -gt 0) {
                        $allAttackPaths += $queryResult.data
                        Write-Verbose "Retrieved $($queryResult.data.Count) attack paths (Total so far: $($allAttackPaths.Count))"

                        # Check if we've retrieved all records
                        if ($queryResult.totalRecords -le ($currentSkip + $queryResult.data.Count)) {
                            Write-Verbose "All attack paths retrieved. Total: $($allAttackPaths.Count)"
                            break
                        }

                        $currentSkip += $pageSize
                    } else {
                        Write-Verbose "No more attack paths to retrieve"
                        break
                    }
                } catch {
                    Write-Error "Failed to retrieve attack paths at skip position $currentSkip : $_"
                    throw
                }
            } while ($true)

            return $allAttackPaths
        } else {
            # Single page retrieval
            Write-Verbose "Retrieving attack paths (Top: $Top, Skip: $Skip)"

            try {
                $queryResult = Invoke-XdrXspmHuntingQuery -Query "AttackPathsV2" -ScenarioName "AttackPathOverview_get_has_attack_paths" -Top $Top -Skip $Skip -Force:$Force

                if ($queryResult.data) {
                    Write-Verbose "Retrieved $($queryResult.data.Count) of $($queryResult.totalRecords) total attack paths"
                    return $queryResult.data
                } else {
                    Write-Verbose "No attack paths found"
                    return @()
                }
            } catch {
                Write-Error "Failed to retrieve attack paths: $_"
                throw
            }
        }
    }

    end {

    }
}
