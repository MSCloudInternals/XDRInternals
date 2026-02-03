function Get-XdrCloudAppsConfigurationIpTag {
    <#
    .SYNOPSIS
        Retrieves IP tags from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured IP tags from Microsoft Defender for Cloud Apps.
        IP tags allow you to categorize IP addresses and ranges for policy
        application, reporting, and threat detection purposes.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Target
        Specifies the target type for tags. Valid values are 'ip' or 'user'.
        Default is 'ip'.

    .PARAMETER EnabledOnly
        When set to $true, returns only enabled tags. When set to $false,
        returns all tags including disabled ones. Default is $true.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationIpTag
        Retrieves all enabled IP tags using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationIpTag -EnabledOnly $false
        Retrieves all IP tags including disabled ones.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationIpTag -Target user
        Retrieves all enabled user tags.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationIpTag -Force
        Forces a fresh retrieval of all enabled IP tags, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationIpTag[]
        Returns an array of tag objects containing tag configuration details.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('ip', 'user')]
        [string]$Target = 'ip',

        [Parameter()]
        [bool]$EnabledOnly = $true,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConfigurationIpTag_${Target}_${EnabledOnly}"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps IP tags"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps IP tags cache is missing or expired"
        }

        $EnabledOnlyString = $EnabledOnly.ToString().ToLower()
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/tags/?target=$Target&enabledOnly=$EnabledOnlyString"

        Write-Verbose "Retrieving Cloud Apps IP tags (Target: $Target, EnabledOnly: $EnabledOnly)"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationIpTag')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps IP tags: $_"
        }
    }

    end {
    }
}
