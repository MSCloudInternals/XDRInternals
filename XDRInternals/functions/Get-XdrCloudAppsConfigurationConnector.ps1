function Get-XdrCloudAppsConfigurationConnector {
    <#
    .SYNOPSIS
        Retrieves app connectors from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the list of configured app connectors from Microsoft Defender for Cloud Apps.
        App connectors enable Microsoft Defender for Cloud Apps to connect to various cloud applications
        for visibility and control.

        Use -Config with AppId, SassId, or InstanceId to get connector configuration details.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Config
        When specified, retrieves connector configuration for a specific app.
        Requires at least one of AppId, SassId, or InstanceId.

    .PARAMETER AppId
        The application ID to get connector configuration for (e.g., 11161 for Microsoft 365, 10980 for Okta).
        Only used with -Config.

    .PARAMETER SassId
        The SaaS ID to get connector configuration for. Only used with -Config.

    .PARAMETER InstanceId
        The instance ID to get connector configuration for. Only used with -Config.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnector
        Retrieves all Cloud Apps connectors using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnector -Force
        Forces a fresh retrieval of all Cloud Apps connectors, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnector | Where-Object { $_.state -eq 'connected' }
        Retrieves all connectors and filters for those that are currently connected.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnector -Config -AppId 11161
        Retrieves the connector configuration for Microsoft 365.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnector -Config -AppId 10980 -Force
        Forces a fresh retrieval of the Okta connector configuration, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationConnector[]
        Returns an array of app connector objects containing connector configuration details.

        XdrCloudAppsConfigurationConnectorConfig
        When -Config is specified, returns the connector configuration object.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ParameterSetName = 'Config', Mandatory = $true)]
        [switch]$Config,

        [Parameter(ParameterSetName = 'Config')]
        [int]$AppId,

        [Parameter(ParameterSetName = 'Config')]
        [string]$SassId,

        [Parameter(ParameterSetName = 'Config')]
        [string]$InstanceId,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        # Validate that at least one identifier is provided when using -Config
        if ($Config -and
            -not $PSBoundParameters.ContainsKey('AppId') -and
            -not $PSBoundParameters.ContainsKey('SassId') -and
            -not $PSBoundParameters.ContainsKey('InstanceId')) {
            throw "At least one of AppId, SassId, or InstanceId must be specified when using -Config."
        }
    }

    process {
        if ($Config) {
            $cacheKeyParts = @("XdrCloudAppsConfigurationConnectorConfig")
            if ($AppId) { $cacheKeyParts += "AppId_$AppId" }
            if ($SassId) { $cacheKeyParts += "SassId_$SassId" }
            if ($InstanceId) { $cacheKeyParts += "InstanceId_$InstanceId" }
            $CacheKey = $cacheKeyParts -join "_"

            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps app connector configuration"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps app connector configuration cache is missing or expired"
            }

            # Build query parameters
            $queryParams = @()
            if ($AppId) { $queryParams += "appId=$AppId" }
            if ($SassId) { $queryParams += "sassId=$SassId" }
            if ($InstanceId) { $queryParams += "instanceId=$InstanceId" }
            $queryString = $queryParams -join "&"

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/app_connectors/get_app_connectors_config/?$queryString"
            Write-Verbose "Retrieving Cloud Apps app connector configuration"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationConnectorConfig')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps app connector configuration: $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsConfigurationConnector"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps connectors"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps connectors cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/app_connectors/"
            $Body = @{
                skip              = 0
                limit             = 100
                filters           = @{}
                performAsyncTotal = $false
                sortDirection     = "desc"
                sortField         = "app"
            } | ConvertTo-Json -Compress

            Write-Verbose "Retrieving Cloud Apps connectors"
            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = $response.data
                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationConnector')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps connectors: $_"
            }
        }
    }

    end {
    }
}
