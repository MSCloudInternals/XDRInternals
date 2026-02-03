function Get-XdrCloudAppsConfigurationUserTag {
    <#
    .SYNOPSIS
        Retrieves user tags from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured user tags from Microsoft Defender for Cloud Apps.
        User tags allow you to categorize and group users for policy application
        and reporting purposes.
        Use the -Metadata switch to retrieve filter and sorting field definitions.
        Use the -Member switch with -TagId to retrieve members of a specific tag.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Metadata
        Returns metadata about available filters and sorting options instead of user tags.

    .PARAMETER Member
        Returns the members (users) of a specific user tag. Requires -TagId parameter.

    .PARAMETER TagId
        The ID of the user tag to retrieve members for. Required when -Member is specified.
        Accepts pipeline input by property name with alias '_id' for piping from user tag objects.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag
        Retrieves all user tags using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag -Force
        Forces a fresh retrieval of all user tags, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag | Where-Object { $_.name -like '*Admin*' }
        Retrieves all user tags and filters for those with 'Admin' in the name.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag -Metadata
        Retrieves metadata about available filters and sorting options for user tags.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag -Member -TagId "abc123def456"
        Retrieves the members of the specified user tag.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationUserTag | ForEach-Object { Get-XdrCloudAppsConfigurationUserTag -Member -TagId $_._id }
        Retrieves members for all user tags.

    .EXAMPLE
        $tag = Get-XdrCloudAppsConfigurationUserTag | Where-Object { $_.name -eq 'Admins' }
        Get-XdrCloudAppsConfigurationUserTag -Member -TagId $tag._id
        Retrieves members of the 'Admins' user tag.

    .OUTPUTS
        XdrCloudAppsConfigurationUserTag[]
        Returns an array of user tag objects, metadata if -Metadata is specified,
        or user tag members if -Member is specified.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ParameterSetName = 'Metadata')]
        [switch]$Metadata,

        [Parameter(ParameterSetName = 'Member', Mandatory = $true)]
        [switch]$Member,

        [Parameter(ParameterSetName = 'Member', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$TagId,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($Metadata) {
            $CacheKey = "XdrCloudAppsConfigurationUserTagMetadata"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps user tag metadata"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps user tag metadata cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/user_tags/metadata/"
            Write-Verbose "Retrieving Cloud Apps user tag metadata"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $result) {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationUserTagMetadata')
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps user tag metadata: $_"
            }
        } elseif ($Member) {
            $CacheKey = "XdrCloudAppsConfigurationUserTagMember_$TagId"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps user tag members for tag $TagId"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps user tag members cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/user_tags/$TagId/users/"
            Write-Verbose "Retrieving Cloud Apps user tag members for tag $TagId"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationUserTagMember')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps user tag members for tag $TagId : $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsConfigurationUserTag"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps user tags"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps user tags cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/user_tags/"
            $Body = @{
                skip              = 0
                limit             = 100
                filters           = @{}
                performAsyncTotal = $false
                sortDirection     = "desc"
                sortField         = "name"
            } | ConvertTo-Json -Compress

            Write-Verbose "Retrieving Cloud Apps user tags"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = $response.data
                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationUserTag')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps user tags: $_"
            }
        }
    }

    end {
    }
}
