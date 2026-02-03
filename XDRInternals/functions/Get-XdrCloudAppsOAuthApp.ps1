function Get-XdrCloudAppsOAuthApp {
    <#
    .SYNOPSIS
        Retrieves OAuth connected apps from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        The Get-XdrCloudAppsOAuthApp cmdlet retrieves OAuth connected apps (third-party apps
        that have been granted permissions) from Microsoft Defender for Cloud Apps. These are
        applications that users have authorized to access organizational data through OAuth.
        You can filter, sort, and paginate the results using the available parameters.
        Use -Metadata to retrieve filter and sorting field definitions.

    .PARAMETER Metadata
        Returns metadata about available filters and sorting options instead of OAuth apps.

    .PARAMETER Limit
        The maximum number of OAuth apps to return. Default is 20.

    .PARAMETER Skip
        The number of OAuth apps to skip for pagination. Default is 0.

    .PARAMETER SortField
        The field to sort results by. Valid values are: name, userCount, severity, lastInstalled.
        Default is "lastInstalled".

    .PARAMETER SortDirection
        The sort direction. Valid values are "asc" or "desc". Default is "desc".

    .PARAMETER Filters
        A hashtable of filters to apply to the OAuth apps query.
        Use -Metadata to see available filter options.

    .PARAMETER Force
        Bypasses the cache and retrieves fresh data from the API.

    .EXAMPLE
        Get-XdrCloudAppsOAuthApp

        Retrieves the 20 most recently used OAuth connected apps.

    .EXAMPLE
        Get-XdrCloudAppsOAuthApp -Limit 50 -Skip 0

        Retrieves the first 50 OAuth connected apps.

    .EXAMPLE
        Get-XdrCloudAppsOAuthApp -Metadata

        Retrieves metadata about available filters and sorting options.

    .EXAMPLE
        Get-XdrCloudAppsOAuthApp -Limit 100 -SortField "name" -SortDirection "asc"

        Retrieves 100 OAuth apps sorted by name ascending.

    .EXAMPLE
        $filters = @{ "permission" = @{ "eq" = @(3) } }
        Get-XdrCloudAppsOAuthApp -Filters $filters -Limit 50

        Retrieves up to 50 OAuth apps with a specific permission level using a filter.

    .EXAMPLE
        Get-XdrCloudAppsOAuthApp -Force

        Forces a fresh retrieval of OAuth apps, bypassing the cache.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Metadata')]
        [switch]$Metadata,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 5000)]
        [int]$Limit = 20,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("name", "userCount", "severity", "lastInstalled")]
        [string]$SortField = "lastInstalled",

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("asc", "desc")]
        [string]$SortDirection = "desc",

        [Parameter(ParameterSetName = 'Default')]
        [hashtable]$Filters = @{},

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($Metadata) {
            $CacheKey = "XdrCloudAppsOAuthAppMetadata"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached OAuth app permissions metadata"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/app_permissions/metadata/"
            Write-Verbose "Retrieving OAuth app permissions metadata from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                return $result
            } catch {
                Write-Error "Failed to retrieve OAuth app permissions metadata: $_"
            }
        } else {
            # Create cache key based on parameters
            $filterHash = if ($Filters.Count -gt 0) { ($Filters | ConvertTo-Json -Compress) } else { "none" }
            $CacheKey = "XdrCloudAppsOAuthApp_${Limit}_${Skip}_${SortField}_${SortDirection}_${filterHash}"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached OAuth apps"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/app_permissions/"

            $body = @{
                filters             = $Filters
                limit               = $Limit
                performAsyncTotal   = $true
                skip                = $Skip
                sortDirection       = $SortDirection
                sortField           = $SortField
            }

            $jsonBody = $body | ConvertTo-Json -Depth 10

            Write-Verbose "Retrieving OAuth apps from $Uri"
            Write-Verbose "Request body: $jsonBody"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result -and $result -is [array]) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsOAuthApp')
                    }
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5

                return $result
            } catch {
                Write-Error "Failed to retrieve OAuth apps: $_"
            }
        }
    }
}
