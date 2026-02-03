function Get-XdrCloudAppsAutocomplete {
    <#
    .SYNOPSIS
        Retrieves autocomplete suggestions from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets autocomplete suggestions from Microsoft Defender for Cloud Apps for various types
        including Domain, Entity (users/groups), OrgUnit, and Tag. This is useful for finding
        identifiers when building filters or queries in other Cloud Apps cmdlets.
        Results are cached for 5 minutes to reduce API calls.

    .PARAMETER Type
        The type of autocomplete data to retrieve. Valid values are:
        - Domain: Domain autocomplete suggestions
        - Entity: Entity (user/group) autocomplete suggestions
        - OrgUnit: Organizational unit autocomplete suggestions
        - Tag: Tag autocomplete suggestions

    .PARAMETER Search
        The search string to filter autocomplete results. Default is empty string.

    .PARAMETER Limit
        The maximum number of results to return. Only applies to Entity type. Default is 50.

    .PARAMETER EntityTypes
        An array of entity type IDs to include when Type is Entity.
        Default is @(1,2) which includes users and groups. Only applies to Entity type.

    .PARAMETER ExcludedApps
        An array of app IDs to exclude from the results. Only applies to Entity type.

    .PARAMETER RemoveChildAccounts
        When specified, removes child accounts from the results. Only applies to Entity type.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAutocomplete -Type Domain
        Retrieves all domain suggestions using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsAutocomplete -Type Domain -Search "contoso"
        Retrieves domain suggestions matching "contoso".

    .EXAMPLE
        Get-XdrCloudAppsAutocomplete -Type Entity -Search "john"
        Retrieves entity (user/group) suggestions matching "john".

    .EXAMPLE
        Get-XdrCloudAppsAutocomplete -Type Entity -Search "admin" -Limit 100 -EntityTypes @(1)
        Retrieves up to 100 user entities matching "admin".

    .EXAMPLE
        Get-XdrCloudAppsAutocomplete -Type OrgUnit -Search "sales"
        Retrieves organizational unit suggestions matching "sales".

    .EXAMPLE
        Get-XdrCloudAppsAutocomplete -Type Tag -Search "sensitive"
        Retrieves tag suggestions matching "sensitive".

    .EXAMPLE
        Get-XdrCloudAppsAutocomplete -Type Domain -Force
        Forces a fresh retrieval of domain suggestions, bypassing the cache.

    .OUTPUTS
        PSObject
        Returns autocomplete suggestions from Cloud Apps based on the specified type.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Domain", "Entity", "OrgUnit", "Tag")]
        [string]$Type,

        [Parameter()]
        [string]$Search = "",

        [Parameter()]
        [ValidateRange(1, 500)]
        [int]$Limit = 50,

        [Parameter()]
        [int[]]$EntityTypes = @(1, 2),

        [Parameter()]
        [string[]]$ExcludedApps = @(),

        [Parameter()]
        [switch]$RemoveChildAccounts,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        switch ($Type) {
            "Domain" {
                $CacheKey = "XdrCloudAppsAutocompleteDomain_$Search"

                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps autocomplete domain suggestions"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps autocomplete domain cache is missing or expired"
                }

                $searchEncoded = [System.Web.HttpUtility]::UrlEncode($Search)
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/domains/?search=$searchEncoded"

                Write-Verbose "Retrieving Cloud Apps autocomplete domain suggestions"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete domain suggestions: $_"
                }
            }

            "Entity" {
                # Build cache key based on parameters
                $typesString = ($EntityTypes | Sort-Object) -join ","
                $excludedAppsString = ($ExcludedApps | Sort-Object) -join ","
                $CacheKey = "XdrCloudAppsAutocompleteEntity_${Search}_${Limit}_${typesString}_${excludedAppsString}_$($RemoveChildAccounts.IsPresent)"

                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps autocomplete entity suggestions"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps autocomplete entity cache is missing or expired"
                }

                # Build query parameters
                $typesEncoded = [System.Web.HttpUtility]::UrlEncode(($EntityTypes | ConvertTo-Json -Compress))
                $excludedAppsEncoded = [System.Web.HttpUtility]::UrlEncode(($ExcludedApps | ConvertTo-Json -Compress))
                $searchEncoded = [System.Web.HttpUtility]::UrlEncode($Search)
                $removeChildAccountsValue = $RemoveChildAccounts.IsPresent.ToString().ToLower()

                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/entities/?excludedApps=$excludedAppsEncoded&limit=$Limit&removeChildAccounts=$removeChildAccountsValue&search=$searchEncoded&types=$typesEncoded"

                Write-Verbose "Retrieving Cloud Apps autocomplete entity suggestions"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete entity suggestions: $_"
                }
            }

            "OrgUnit" {
                $CacheKey = "XdrCloudAppsAutocompleteOrgUnit_$Search"

                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps autocomplete org unit suggestions"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps autocomplete org unit cache is missing or expired"
                }

                $searchEncoded = [System.Web.HttpUtility]::UrlEncode($Search)
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/org-units/?search=$searchEncoded"

                Write-Verbose "Retrieving Cloud Apps autocomplete org unit suggestions"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete org unit suggestions: $_"
                }
            }

            "Tag" {
                $CacheKey = "XdrCloudAppsAutocompleteTag_$Search"

                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps autocomplete tag suggestions"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps autocomplete tag cache is missing or expired"
                }

                $searchEncoded = [System.Web.HttpUtility]::UrlEncode($Search)
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/tags/?search=$searchEncoded"

                Write-Verbose "Retrieving Cloud Apps autocomplete tag suggestions"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete tag suggestions: $_"
                }
            }
        }
    }

    end {
    }
}
