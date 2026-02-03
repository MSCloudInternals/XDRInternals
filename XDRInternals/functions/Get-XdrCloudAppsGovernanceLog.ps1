function Get-XdrCloudAppsGovernanceLog {
    <#
    .SYNOPSIS
        Retrieves governance actions from Microsoft Defender for Cloud Apps governance log.

    .DESCRIPTION
        The Get-XdrCloudAppsGovernanceLog cmdlet retrieves governance actions from the Microsoft Defender
        for Cloud Apps governance log. Governance actions include policy enforcement actions,
        remediation activities, and administrative actions. You can filter, sort, and paginate
        the results using the available parameters.
        Use -Metadata to retrieve filter and sorting field definitions.
        Use -CountOnly to retrieve just the governance action count without full data.

    .PARAMETER Metadata
        Returns metadata about available filters and sorting options instead of governance actions.

    .PARAMETER CountOnly
        Returns only the count of matching governance actions without the full data.

    .PARAMETER Limit
        The maximum number of governance actions to return. Default is 20.

    .PARAMETER Skip
        The number of governance actions to skip for pagination. Default is 0.

    .PARAMETER SortField
        The field to sort results by. Default is "timestamp".

    .PARAMETER SortDirection
        The sort direction. Valid values are "asc" or "desc". Default is "desc".

    .PARAMETER Filters
        A hashtable of filters to apply to the governance query.
        Use -Metadata to see available filter options.

    .PARAMETER Force
        Bypasses the cache and retrieves fresh data from the API.

    .EXAMPLE
        Get-XdrCloudAppsGovernanceLog

        Retrieves the 20 most recent governance actions.

    .EXAMPLE
        Get-XdrCloudAppsGovernanceLog -Limit 50 -Skip 0

        Retrieves the first 50 governance actions.

    .EXAMPLE
        Get-XdrCloudAppsGovernanceLog -Metadata

        Retrieves metadata about available filters and sorting options.

    .EXAMPLE
        Get-XdrCloudAppsGovernanceLog -CountOnly

        Retrieves only the count of all governance actions.

    .EXAMPLE
        $filters = @{ "status" = @{ "eq" = @(1) } }
        Get-XdrCloudAppsGovernanceLog -Filters $filters -Limit 50

        Retrieves up to 50 governance actions with a specific status using a filter.

    .EXAMPLE
        Get-XdrCloudAppsGovernanceLog -CountOnly -Filters @{ "status" = @{ "eq" = @(1) } }

        Retrieves the count of governance actions with a specific status.

    .EXAMPLE
        Get-XdrCloudAppsGovernanceLog -Force

        Forces a fresh retrieval of governance actions, bypassing the cache.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Metadata')]
        [switch]$Metadata,

        [Parameter(ParameterSetName = 'CountOnly')]
        [switch]$CountOnly,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 5000)]
        [int]$Limit = 20,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter(ParameterSetName = 'Default')]
        [string]$SortField = "timestamp",

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("asc", "desc")]
        [string]$SortDirection = "desc",

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [hashtable]$Filters = @{},

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($Metadata) {
            $CacheKey = "XdrCloudAppsGovernanceLogMetadata"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached governance log metadata"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/governance/metadata/"
            Write-Verbose "Retrieving governance log metadata from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                return $result
            } catch {
                Write-Error "Failed to retrieve governance log metadata: $_"
            }
        } elseif ($CountOnly) {
            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/governance/count/"

            $body = @{
                filters = $Filters
            }

            $jsonBody = $body | ConvertTo-Json -Depth 10
            Write-Verbose "Retrieving governance action count from $Uri"
            Write-Verbose "Request body: $jsonBody"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to retrieve governance action count: $_"
            }
        } else {
            # Create cache key based on parameters
            $filterHash = if ($Filters.Count -gt 0) { ($Filters | ConvertTo-Json -Compress) } else { "none" }
            $CacheKey = "XdrCloudAppsGovernanceLog_${Limit}_${Skip}_${SortField}_${SortDirection}_${filterHash}"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached governance log entries"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/governance/"

            $body = @{
                filters             = $Filters
                limit               = $Limit
                performAsyncTotal   = $true
                skip                = $Skip
                sortDirection       = $SortDirection
                sortField           = $SortField
            }

            $jsonBody = $body | ConvertTo-Json -Depth 10

            Write-Verbose "Retrieving governance log entries from $Uri"
            Write-Verbose "Request body: $jsonBody"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result) {
                    foreach ($item in @($result)) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsGovernanceLog')
                    }
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5

                return $result
            } catch {
                Write-Error "Failed to retrieve governance log entries: $_"
            }
        }
    }

    end {
    }
}
