function Get-XdrExposureManagementRecommendations {
    <#
    .SYNOPSIS
        Retrieves recommendations from Exposure Management.

    .DESCRIPTION
        Gets security recommendations from Microsoft Defender XDR Exposure Management.
        Supports multiple data sources including TVM recommendations, vulnerability assessments, and device misconfigurations.
        This function includes caching support with a 30-minute TTL to reduce API calls.
        By default, returns the recommendations array.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .PARAMETER CountOnly
        Returns only the total count of recommendations (numOfResults).

    .PARAMETER Top
        Limits the number of results returned. Useful for previewing data without fetching all pages.

    .PARAMETER Tags
        Retrieves vulnerability assessment recommendation tags.

    .PARAMETER ActiveVulnerabilities
        Retrieves vulnerability assessment recommendations with filters (Active or PartialException status).

    .PARAMETER AllVulnerabilities
        Retrieves all vulnerability assessment recommendations without status filters.

    .PARAMETER Misconfigurations
        Retrieves device misconfiguration recommendations from the posture/oversight API.

    .PARAMETER ByAssets
        Retrieves assets for a specific recommendation. Requires -RecommendationId.

    .PARAMETER ByOperatingSystems
        Retrieves operating systems for a specific recommendation. Requires -RecommendationId.

    .PARAMETER RecommendationId
        The recommendation ID required for -ByAssets and -ByOperatingSystems parameters.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations
        Retrieves all recommendations using cached data if available.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -Force
        Forces a fresh retrieval of recommendations, bypassing the cache.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -CountOnly
        Returns only the total number of recommendations.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -Top 10
        Returns only the first 10 recommendations.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -Tags
        Retrieves vulnerability assessment recommendation tags.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -ActiveVulnerabilities
        Retrieves vulnerability assessment recommendations with Active or PartialException status.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -AllVulnerabilities
        Retrieves all vulnerability assessment recommendations regardless of status.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -Misconfigurations
        Retrieves device misconfiguration recommendations.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -ByAssets -RecommendationId "sca-_-scid-69"
        Retrieves assets for a specific recommendation.

    .EXAMPLE
        Get-XdrExposureManagementRecommendations -ByOperatingSystems -RecommendationId "va-_-microsoft-_-windows_11"
        Retrieves operating system breakdown for a specific recommendation.

    .OUTPUTS
        System.Object[]
        Returns an array of recommendation objects. Output varies based on parameters used.

    .OUTPUTS
        System.Int64
        When -CountOnly is specified, returns the total count as an integer.
    #>
    # Suppress false positive: Switch parameters are used via $PSCmdlet.ParameterSetName, not direct reference
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([System.Object[]])]
    [OutputType([System.Int64], ParameterSetName = 'CountOnly')]
    param (
        [Parameter()]
        [switch]$Force,

        [Parameter(ParameterSetName = 'CountOnly')]
        [switch]$CountOnly,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$Top,

        [Parameter(ParameterSetName = 'Tags')]
        [switch]$Tags,

        [Parameter(ParameterSetName = 'ActiveVulnerabilities')]
        [switch]$ActiveVulnerabilities,

        [Parameter(ParameterSetName = 'AllVulnerabilities')]
        [switch]$AllVulnerabilities,

        [Parameter(ParameterSetName = 'Misconfigurations')]
        [switch]$Misconfigurations,

        [Parameter(ParameterSetName = 'ByAssets')]
        [switch]$ByAssets,

        [Parameter(ParameterSetName = 'ByOperatingSystems')]
        [switch]$ByOperatingSystems,

        [Parameter(ParameterSetName = 'ByAssets', Mandatory = $true)]
        [Parameter(ParameterSetName = 'ByOperatingSystems', Mandatory = $true)]
        [string]$RecommendationId
    )

    begin {
        Update-XdrConnectionSettings

        # Helper function for paginated requests
        function Invoke-PaginatedRequest {
            param (
                [hashtable]$Headers,
                [scriptblock]$BuildUri,
                [string]$CountProperty = 'numOfResults',
                [string]$DisplayName,
                [int]$MaxResults = 0
            )

            $maxPages = 1000
            $pageNum = 1

            try {
                # Get first page
                $uri = & $BuildUri $pageNum
                Write-Verbose "Fetching $DisplayName page 1"
                $response = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $Headers

                $totalResults = $response.$CountProperty
                $targetResults = if ($MaxResults -gt 0 -and $MaxResults -lt $totalResults) { $MaxResults } else { $totalResults }
                Write-Information "Total $DisplayName`: $totalResults$(if ($MaxResults -gt 0) { " (fetching $targetResults)" })" -InformationAction Continue

                # Collect results with pagination
                $allResults = [System.Collections.Generic.List[object]]::new()
                if ($response.results) { $allResults.AddRange($response.results) }
                $pageNum = 2

                # Show progress for larger result sets (more than one page)
                $showProgress = $targetResults -gt 25

                while ($allResults.Count -lt $targetResults -and $pageNum -le $maxPages) {
                    if ($showProgress) {
                        $percentComplete = [math]::Min(100, [math]::Round(($allResults.Count / $targetResults) * 100))
                        Write-Progress -Activity "Retrieving $DisplayName" -Status "$($allResults.Count) of $targetResults" -PercentComplete $percentComplete
                    }

                    $uri = & $BuildUri $pageNum
                    Write-Verbose "Fetching $DisplayName page $pageNum"
                    $response = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $Headers
                    if ($response.results) { $allResults.AddRange($response.results) }
                    Write-Verbose "Retrieved $($allResults.Count) of $targetResults $DisplayName"
                    $pageNum++
                }

                if ($showProgress) {
                    Write-Progress -Activity "Retrieving $DisplayName" -Completed
                }

                # Trim to MaxResults if specified
                $finalResults = if ($MaxResults -gt 0 -and $allResults.Count -gt $MaxResults) {
                    $allResults.GetRange(0, $MaxResults).ToArray()
                } else {
                    $allResults.ToArray()
                }

                return [PSCustomObject]@{
                    Count   = $totalResults
                    Results = $finalResults
                }
            } catch {
                Write-Progress -Activity "Retrieving $DisplayName" -Completed
                throw "Failed to retrieve $DisplayName`: $_"
            }
        }
    }

    process {
        # Define configuration for each parameter set
        $config = switch ($PSCmdlet.ParameterSetName) {
            'Tags' {
                @{
                    CacheKey = "XdrExposureManagementRecommendations_Tags"
                    Simple   = $true
                    Endpoint = "/va/tags"
                    Extract  = 'tags'
                }
            }
            'ByOperatingSystems' {
                @{
                    CacheKey = "XdrExposureManagementRecommendations_OS_$RecommendationId"
                    Simple   = $true
                    Endpoint = "/recommendation/operatingSystems?recommendationId=$RecommendationId"
                }
            }
            'ByAssets' {
                @{
                    CacheKey      = "XdrExposureManagementRecommendations_Assets_$RecommendationId"
                    UseTvmHeaders = $true
                    DisplayName   = "assets for recommendation"
                    BuildUri      = { param($p) "https://security.microsoft.com/apiproxy/mtp/tvm/analytics/recommendations/recommendation/assets?recommendationId=$RecommendationId&pageIndex=$p" }
                }
            }
            'ActiveVulnerabilities' {
                $filter = "`$filter=(status+eq+%27Active%27+or+status+eq+%27PartialException%27)"
                @{
                    CacheKey      = "XdrExposureManagementRecommendations_ActiveVulnerabilities"
                    UseTvmHeaders = $true
                    DisplayName   = "ActiveVulnerabilities recommendations"
                    BuildUri      = { param($p) "https://security.microsoft.com/apiproxy/mtp/tvm/analytics/recommendations/va?pageIndex=$p&pageSize=25&$filter" }.GetNewClosure()
                }
            }
            'AllVulnerabilities' {
                @{
                    CacheKey      = "XdrExposureManagementRecommendations_AllVulnerabilities"
                    UseTvmHeaders = $true
                    DisplayName   = "AllVulnerabilities recommendations"
                    BuildUri      = { param($p) "https://security.microsoft.com/apiproxy/mtp/tvm/analytics/recommendations/va?pageIndex=$p&pageSize=25" }
                }
            }
            'Misconfigurations' {
                $miscFilter = "filters[0].key=category&filters[0].value[0]=DeviceMisconfiguration&filters[0].operator=Contains"
                @{
                    CacheKey      = "XdrExposureManagementRecommendations_Misconfigurations"
                    UseTvmHeaders = $false
                    DisplayName   = "Misconfigurations recommendations"
                    CountProperty = 'recordsCount'
                    BuildUri      = { param($p) "https://security.microsoft.com/apiproxy/mtp/posture/oversight/recommendations?calculationId=undefined&sort.sortDirection=desc&sort.sortByField=domainScoreImpact&pagination.pageNumber=$p&pagination.numberOfPageRecords=25&$miscFilter&highlights=false" }.GetNewClosure()
                }
            }
            { $_ -in 'Default', 'CountOnly' } {
                @{
                    CacheKey      = "XdrExposureManagementRecommendations"
                    UseTvmHeaders = $true
                    DisplayName   = "recommendations"
                    BuildUri      = { param($p) "https://security.microsoft.com/apiproxy/mtp/tvm/analytics/recommendations?pageIndex=$p" }
                }
            }
        }

        # Check cache first (skip if -Top is specified as we may need subset)
        $useCache = -not $Top -or $Top -eq 0
        $currentCacheValue = Get-XdrCache -CacheKey $config.CacheKey -ErrorAction SilentlyContinue
        if ($useCache -and -not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached data for $($config.CacheKey)"

            if ($config.Simple) {
                return $currentCacheValue.Value
            }

            $countProp = if ($config.CountProperty) { $config.CountProperty } else { 'numOfResults' }
            Write-Information "Total $($config.DisplayName): $($currentCacheValue.Value.$countProp)" -InformationAction Continue

            if ($PSCmdlet.ParameterSetName -eq 'CountOnly') {
                return $currentCacheValue.Value.$countProp
            }
            return $currentCacheValue.Value.results
        }

        if ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $config.CacheKey
        } elseif (-not $useCache) {
            Write-Verbose "Top parameter specified, fetching fresh data"
        } else {
            Write-Verbose "Cache is missing or expired for $($config.CacheKey)"
        }

        # Prepare headers
        $requestHeaders = if ($config.UseTvmHeaders -or $config.Simple) {
            $h = $script:headers.Clone()
            $h["api-version"] = "1.0"
            $h
        } else {
            $script:headers
        }

        try {
            # Handle simple (non-paginated) endpoints
            if ($config.Simple) {
                $uri = "https://security.microsoft.com/apiproxy/mtp/tvm/analytics/recommendations" + $config.Endpoint
                Write-Verbose "Retrieving from: $uri"
                $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $requestHeaders

                $valueToCache = if ($config.Extract) { $result.$($config.Extract) } else { $result }
                # Handle null/empty results gracefully
                if ($null -eq $valueToCache) { $valueToCache = @() }
                Set-XdrCache -CacheKey $config.CacheKey -Value $valueToCache -TTLMinutes 30

                # Apply -Top if specified
                if ($Top -gt 0 -and $valueToCache.Count -gt $Top) {
                    return $valueToCache | Select-Object -First $Top
                }
                return $valueToCache
            }

            # Handle paginated endpoints
            $countProp = if ($config.CountProperty) { $config.CountProperty } else { 'numOfResults' }
            $paginatedResult = Invoke-PaginatedRequest -Headers $requestHeaders -DisplayName $config.DisplayName -BuildUri $config.BuildUri -CountProperty $countProp -MaxResults $Top

            # Cache the full response only if we fetched everything
            if (-not $Top -or $Top -eq 0) {
                $cacheValue = [PSCustomObject]@{
                    $countProp = $paginatedResult.Count
                    results    = $paginatedResult.Results
                }
                Set-XdrCache -CacheKey $config.CacheKey -Value $cacheValue -TTLMinutes 30
            }

            # Return based on parameters
            if ($PSCmdlet.ParameterSetName -eq 'CountOnly') {
                return $paginatedResult.Count
            }
            return $paginatedResult.Results

        } catch {
            Write-Error "Failed to retrieve $($config.DisplayName): $_"
        }
    }

    end {
    }
}

