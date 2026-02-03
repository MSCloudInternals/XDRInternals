function Get-XdrCloudAppsConfigurationSettings {
    <#
    .SYNOPSIS
        Retrieves configuration settings from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets various configuration settings from Microsoft Defender for Cloud Apps including
        general settings, mail settings, tenant configuration, LCNC settings, and notification settings.
        You can retrieve specific setting types or all at once.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER SettingType
        The type of settings to retrieve. Valid values are 'General', 'Mail', 'TenantConfig', 'LCNC', 'Notifications', or 'All'.
        Default is 'All' which combines all setting types into a single object.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSettings
        Retrieves all Cloud Apps configuration settings using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSettings -SettingType General
        Retrieves only the general settings.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSettings -SettingType Mail
        Retrieves only the mail settings.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSettings -SettingType TenantConfig
        Retrieves tenant configuration settings including proxy traffic logs and AAD user resolution.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSettings -SettingType LCNC
        Retrieves Low-Code/No-Code (LCNC) settings.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSettings -SettingType Notifications
        Retrieves notification center settings.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSettings -Force
        Forces a fresh retrieval of all Cloud Apps configuration settings, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationSettings
        Returns a custom object containing the requested Cloud Apps configuration settings.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Settings is plural by design')]
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('General', 'Mail', 'TenantConfig', 'LCNC', 'Notifications', 'All')]
        [string]$SettingType = 'All',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConfigurationSettings-$SettingType"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps configuration settings for $SettingType"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps configuration settings cache is missing or expired for $SettingType"
        }

        $BaseUri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1"
        Write-Verbose "Retrieving Cloud Apps configuration settings: $SettingType"

        try {
            $result = $null

            switch ($SettingType) {
                'General' {
                    $Uri = "$BaseUri/settings/"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                }
                'Mail' {
                    $Uri = "$BaseUri/mail_settings/get/"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                }
                'TenantConfig' {
                    $proxyTrafficLogsUri = "$BaseUri/tenant_config/enableProxyTrafficLogs/"
                    $resolveUserUri = "$BaseUri/tenant_config/resolveDiscoveryUserWithAAD/"

                    $proxyTrafficLogs = Invoke-RestMethod -Uri $proxyTrafficLogsUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $resolveUser = Invoke-RestMethod -Uri $resolveUserUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = [PSCustomObject]@{
                        EnableProxyTrafficLogs       = $proxyTrafficLogs
                        ResolveDiscoveryUserWithAAD  = $resolveUser
                    }
                }
                'LCNC' {
                    $Uri = "$BaseUri/lcnc_settings/"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                }
                'Notifications' {
                    $Uri = "$BaseUri/user_config/get_notifications_center_settings/"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                }
                'All' {
                    $generalUri = "$BaseUri/settings/"
                    $mailUri = "$BaseUri/mail_settings/get/"
                    $proxyTrafficLogsUri = "$BaseUri/tenant_config/enableProxyTrafficLogs/"
                    $resolveUserUri = "$BaseUri/tenant_config/resolveDiscoveryUserWithAAD/"
                    $lcncUri = "$BaseUri/lcnc_settings/"
                    $notificationsUri = "$BaseUri/user_config/get_notifications_center_settings/"

                    $general = Invoke-RestMethod -Uri $generalUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $mail = Invoke-RestMethod -Uri $mailUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $proxyTrafficLogs = Invoke-RestMethod -Uri $proxyTrafficLogsUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $resolveUser = Invoke-RestMethod -Uri $resolveUserUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $lcnc = Invoke-RestMethod -Uri $lcncUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $notifications = Invoke-RestMethod -Uri $notificationsUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = [PSCustomObject]@{
                        General       = $general
                        Mail          = $mail
                        TenantConfig  = [PSCustomObject]@{
                            EnableProxyTrafficLogs       = $proxyTrafficLogs
                            ResolveDiscoveryUserWithAAD  = $resolveUser
                        }
                        LCNC          = $lcnc
                        Notifications = $notifications
                    }
                }
            }

            if ($null -ne $result) {
                $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationSettings')
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps configuration settings: $_"
        }
    }

    end {
    }
}
