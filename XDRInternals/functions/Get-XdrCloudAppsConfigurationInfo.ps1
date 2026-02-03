function Get-XdrCloudAppsConfigurationInfo {
    <#
    .SYNOPSIS
        Retrieves configuration information from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets configuration information from Microsoft Defender for Cloud Apps including version,
        server URL, and general info. You can retrieve specific information types or all at once.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER InfoType
        The type of information to retrieve. Valid values are 'Version', 'ServerUrl', 'Info', or 'All'.
        Default is 'All' which combines all three API results into a single object.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationInfo
        Retrieves all Cloud Apps configuration information using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationInfo -InfoType Version
        Retrieves only the Cloud Apps version information.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationInfo -InfoType ServerUrl
        Retrieves only the Cloud Apps server URL information.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationInfo -InfoType Info
        Retrieves only the Cloud Apps general info.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationInfo -Force
        Forces a fresh retrieval of all Cloud Apps configuration information, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationInfo
        Returns a custom object containing the requested Cloud Apps configuration information.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('Version', 'ServerUrl', 'Info', 'All')]
        [string]$InfoType = 'All',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConfigurationInfo-$InfoType"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps configuration info for $InfoType"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps configuration info cache is missing or expired for $InfoType"
        }

        $BaseUri = "https://security.microsoft.com/apiproxy/mcas/cas/api"
        Write-Verbose "Retrieving Cloud Apps configuration info: $InfoType"

        try {
            $result = $null

            switch ($InfoType) {
                'Version' {
                    $Uri = "$BaseUri/version"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                }
                'ServerUrl' {
                    $Uri = "$BaseUri/about/server_url/"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                }
                'Info' {
                    $Uri = "$BaseUri/about/info"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                }
                'All' {
                    $versionUri = "$BaseUri/version"
                    $serverUrlUri = "$BaseUri/about/server_url/"
                    $infoUri = "$BaseUri/about/info"

                    $version = Invoke-RestMethod -Uri $versionUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $serverUrl = Invoke-RestMethod -Uri $serverUrlUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $info = Invoke-RestMethod -Uri $infoUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = [PSCustomObject]@{
                        Version   = $version
                        ServerUrl = $serverUrl
                        Info      = $info
                    }
                }
            }

            if ($null -ne $result) {
                $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationInfo')
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps configuration info: $_"
        }
    }

    end {
    }
}
