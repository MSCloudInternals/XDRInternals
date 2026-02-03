function Get-XdrCloudAppsFile {
    <#
    .SYNOPSIS
        Retrieves files from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets files discovered by Microsoft Defender for Cloud Apps with support for filtering,
        sorting, and pagination. Note: This endpoint may require a policy filter to return results.
        Use -Metadata to retrieve filter and sorting field definitions.
        Use -CountOnly to retrieve just the file count without full data.

    .PARAMETER Metadata
        Returns metadata about available filters and sorting options instead of files.

    .PARAMETER CountOnly
        Returns only the count of matching files without the full file data.

    .PARAMETER Limit
        Maximum number of files to return. Default is 20.

    .PARAMETER Skip
        Number of files to skip for pagination. Default is 0.

    .PARAMETER SortField
        Field to sort results by. Default is "lastGlobalMatchDate".

    .PARAMETER SortDirection
        Sort direction, either "asc" or "desc". Default is "desc".

    .PARAMETER Filters
        Hashtable of filters to apply to the query. Overrides default filters if specified.

    .PARAMETER PolicyId
        Optional policy ID to filter files by a specific policy match.

    .PARAMETER Force
        Bypass the cache and retrieve fresh data from the API.

    .EXAMPLE
        Get-XdrCloudAppsFile

        Retrieves the first 20 files sorted by last global match date descending.

    .EXAMPLE
        Get-XdrCloudAppsFile -Limit 50 -Skip 20

        Retrieves files 21-70 for pagination.

    .EXAMPLE
        Get-XdrCloudAppsFile -PolicyId "5f1234567890abcdef123456"

        Retrieves files matching a specific policy.

    .EXAMPLE
        Get-XdrCloudAppsFile -Metadata

        Retrieves metadata about available filters and sorting options.

    .EXAMPLE
        Get-XdrCloudAppsFile -CountOnly

        Retrieves only the count of files.

    .EXAMPLE
        Get-XdrCloudAppsFile -CountOnly -PolicyId "5f1234567890abcdef123456"

        Retrieves the count of files matching a specific policy.

    .EXAMPLE
        Get-XdrCloudAppsFile -Filters @{ "fileType" = @{ "eq" = @(1) } }

        Retrieves files with custom filter for file type.

    .EXAMPLE
        Get-XdrCloudAppsFile -SortField "name" -SortDirection "asc"

        Retrieves files sorted by name in ascending order.

    .NOTES
        This cmdlet requires an active XDR connection established via Connect-XdrByEstsCookie.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
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
        [string]$SortField = "lastGlobalMatchDate",

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("asc", "desc")]
        [string]$SortDirection = "desc",

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [hashtable]$Filters,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [string]$PolicyId,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($Metadata) {
            $CacheKey = "XdrCloudAppsFileMetadata"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached file metadata"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/files/metadata/"
            Write-Verbose "Retrieving Cloud Apps file metadata from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps file metadata: $_"
            }
        } elseif ($CountOnly) {
            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/files/count/"

            if (-not $Filters) {
                $Filters = @{}
            }

            if ($PolicyId) {
                $Filters["policy"] = @{ eq = @($PolicyId) }
            }

            $Body = @{
                filters = $Filters
            } | ConvertTo-Json -Depth 10

            Write-Verbose "Retrieving Cloud Apps file count from $Uri"
            Write-Verbose "Request body: $Body"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps file count: $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsFile_${Limit}_${Skip}_${SortField}_${SortDirection}_${PolicyId}"

            if (-not $Force -and -not $Filters) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached file data"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/files/"

            if (-not $Filters) {
                $Filters = @{}
            }

            if ($PolicyId) {
                $Filters["policy"] = @{ eq = @($PolicyId) }
            }

            $Body = @{
                filters = $Filters
                limit = $Limit
                performAsyncTotal = $true
                skip = $Skip
                sortDirection = $SortDirection
                sortField = $SortField
            } | ConvertTo-Json -Depth 10

            Write-Verbose "Retrieving Cloud Apps files from $Uri"
            Write-Verbose "Request body: $Body"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result -and $result -is [array]) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsFile')
                    }
                }

                if (-not $Filters -or $PSBoundParameters.ContainsKey('PolicyId')) {
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps files: $_"
            }
        }
    }
}
