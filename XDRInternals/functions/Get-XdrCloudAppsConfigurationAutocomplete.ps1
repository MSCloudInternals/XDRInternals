function Get-XdrCloudAppsConfigurationAutocomplete {
    <#
    .SYNOPSIS
        Retrieves autocomplete data from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets autocomplete data from Microsoft Defender for Cloud Apps for various types
        including Tags, Users, Groups, MachineGroups, and Services. This is useful for
        building filters and queries in the Cloud Apps interface.
        Services type includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Type
        The type of autocomplete data to retrieve. Valid values are:
        - Tags: Retrieves available tags
        - Users: Retrieves matching users based on search
        - Groups: Retrieves groups for a specific app (requires AppId)
        - MachineGroups: Retrieves machine groups
        - Services: Retrieves available services (cacheable)

    .PARAMETER Search
        The search string to filter autocomplete results. URL encoding is handled automatically.

    .PARAMETER AppId
        The application ID required when retrieving Groups. This parameter is mandatory for Groups type.

    .PARAMETER Limit
        The maximum number of results to return. Default is 50.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API. Only applicable for Services type.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationAutocomplete -Type Tags
        Retrieves all available tags.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationAutocomplete -Type Tags -Search "finance"
        Retrieves tags matching "finance".

    .EXAMPLE
        Get-XdrCloudAppsConfigurationAutocomplete -Type Users -Search "john"
        Retrieves users matching "john".

    .EXAMPLE
        Get-XdrCloudAppsConfigurationAutocomplete -Type Groups -AppId 11161 -Search "admin"
        Retrieves groups matching "admin" for the specified application.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationAutocomplete -Type MachineGroups -Search "server"
        Retrieves machine groups matching "server".

    .EXAMPLE
        Get-XdrCloudAppsConfigurationAutocomplete -Type Services
        Retrieves all available services using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationAutocomplete -Type Services -Force
        Forces a fresh retrieval of all available services, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationAutocomplete[]
        Returns an array of autocomplete objects for the specified type.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Tags', 'Users', 'Groups', 'MachineGroups', 'Services')]
        [string]$Type,

        [Parameter()]
        [string]$Search,

        [Parameter()]
        [int]$AppId,

        [Parameter()]
        [int]$Limit = 50,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        # Validate AppId is provided when Type is Groups
        if ($Type -eq 'Groups' -and -not $PSBoundParameters.ContainsKey('AppId')) {
            throw "AppId parameter is required when Type is 'Groups'."
        }
    }

    process {
        $encodedSearch = if ($Search) { [System.Uri]::EscapeDataString($Search) } else { "" }

        switch ($Type) {
            'Tags' {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/tags/?limit=$Limit&search=$encodedSearch"

                Write-Verbose "Retrieving Cloud Apps autocomplete tags"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationAutocomplete')
                        }
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete tags: $_"
                }
            }

            'Users' {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/users/?search=$encodedSearch"

                Write-Verbose "Retrieving Cloud Apps autocomplete users"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationAutocomplete')
                        }
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete users: $_"
                }
            }

            'Groups' {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/groups/?appId=$AppId&search=$encodedSearch"

                Write-Verbose "Retrieving Cloud Apps autocomplete groups for AppId: $AppId"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationAutocomplete')
                        }
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete groups: $_"
                }
            }

            'MachineGroups' {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/autocomplete/machine-groups/?search=$encodedSearch"

                Write-Verbose "Retrieving Cloud Apps autocomplete machine groups"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationAutocomplete')
                        }
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete machine groups: $_"
                }
            }

            'Services' {
                $CacheKey = "XdrCloudAppsConfigurationAutocompleteServices"
                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps autocomplete services"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps autocomplete services cache is missing or expired"
                }

                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/services/"

                Write-Verbose "Retrieving Cloud Apps autocomplete services"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationAutocomplete')
                        }
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                    }

                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps autocomplete services: $_"
                }
            }
        }
    }

    end {
    }
}
