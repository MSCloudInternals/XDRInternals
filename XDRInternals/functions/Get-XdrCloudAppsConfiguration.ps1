function Get-XdrCloudAppsConfiguration {
    <#
    .SYNOPSIS
        Retrieves grouped Microsoft Defender for Cloud Apps configuration data.

    .DESCRIPTION
        Retrieves settings, about information, discovery streams, tags, connectors,
        and other configuration data through a single grouped command.

    .PARAMETER Type
        Configuration data type to retrieve.

    .PARAMETER Metadata
        Retrieves metadata for configuration surfaces that expose metadata.

    .PARAMETER Limit
        Maximum number of grid records to request.

    .PARAMETER Skip
        Number of grid records to skip.

    .PARAMETER SortField
        Field used to sort grid results.

    .PARAMETER SortDirection
        Sort direction for grid results.

    .PARAMETER Filters
        Cloud Apps filters to include in the query body.

    .PARAMETER Raw
        Returns the raw API response shape.

    .PARAMETER Force
        Bypasses cache-backed requests.

    .EXAMPLE
        Get-XdrCloudAppsConfiguration -Type DiscoveryStream

        Retrieves Cloud Discovery streams.

    .EXAMPLE
        Get-XdrCloudAppsConfiguration -Type Settings

        Retrieves tenant-wide Cloud Apps settings.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Configuration is the admin surface name')]
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('About', 'Settings', 'MailSettings', 'TenantConfig', 'LCNC', 'Notifications', 'ApiToken', 'Connector', 'CustomParser', 'DiscoveryAppTag', 'DiscoveryDataSource', 'DiscoveryEncryption', 'DiscoveryExclusion', 'DiscoveryReport', 'DiscoveryStream', 'DiscoveryWeight', 'IpTag', 'Location', 'LogCollector', 'ScopedDeployment', 'ScopedProfile', 'SiemAgent', 'Subnet', 'UserTag')]
        [string]$Type = 'Settings',

        [Parameter()]
        [switch]$Metadata,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$Limit = 100,

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter()]
        [string]$SortField = 'name',

        [Parameter()]
        [ValidateSet('asc', 'desc')]
        [string]$SortDirection = 'asc',

        [Parameter()]
        [hashtable]$Filters = @{},

        [Parameter()]
        [switch]$Raw,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $gridBody = @{
            filters           = $Filters
            limit             = $Limit
            performAsyncTotal = $true
            skip              = $Skip
            sortDirection     = $SortDirection
            sortField         = $SortField
        }

        switch ($Type) {
            'About' {
                [PSCustomObject]@{
                    PSTypeName = 'XdrCloudAppsConfigurationAbout'
                    Version    = Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/version/' -Raw -Force:$Force
                    ServerUrl  = Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/about/server_url/' -Raw -Force:$Force
                    Info       = Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/about/info/' -Raw -Force:$Force
                }
            }
            'Settings' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/settings/' -TypeName 'XdrCloudAppsConfigurationSettings' -CacheKey 'XdrCloudAppsConfigurationSettings' -TTLMinutes 30 -Raw:$Raw -Force:$Force }
            'MailSettings' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/mail_settings/get/' -TypeName 'XdrCloudAppsConfigurationMailSettings' -CacheKey 'XdrCloudAppsConfigurationMailSettings' -TTLMinutes 30 -Raw:$Raw -Force:$Force }
            'TenantConfig' {
                [PSCustomObject]@{
                    PSTypeName                   = 'XdrCloudAppsConfigurationTenantConfig'
                    EnableProxyTrafficLogs       = Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/tenant_config/enableProxyTrafficLogs/' -Raw -Force:$Force
                    ResolveDiscoveryUserWithAAD  = Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/tenant_config/resolveDiscoveryUserWithAAD/' -Raw -Force:$Force
                }
            }
            'LCNC' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/lcnc_settings/' -TypeName 'XdrCloudAppsConfigurationLCNC' -CacheKey 'XdrCloudAppsConfigurationLCNC' -TTLMinutes 30 -Raw:$Raw -Force:$Force }
            'Notifications' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/user_config/get_notifications_center_settings/' -TypeName 'XdrCloudAppsConfigurationNotifications' -CacheKey 'XdrCloudAppsConfigurationNotifications' -TTLMinutes 30 -Raw:$Raw -Force:$Force }
            'ApiToken' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/tokens/metadata/' -TypeName 'XdrCloudAppsConfigurationApiTokenMetadata' -CacheKey 'XdrCloudAppsConfigurationApiTokenMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/tokens/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationApiToken' -Raw:$Raw -Force:$Force
            }
            'Connector' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/app_connectors/metadata/' -TypeName 'XdrCloudAppsConfigurationConnectorMetadata' -CacheKey 'XdrCloudAppsConfigurationConnectorMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/app_connectors/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationConnector' -Raw:$Raw -Force:$Force
            }
            'DiscoveryStream' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/discovery/streams/' -TypeName 'XdrCloudAppsConfigurationDiscoveryStream' -CacheKey 'XdrCloudAppsConfigurationDiscoveryStream' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'DiscoveryDataSource' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/data_sources/' -TypeName 'XdrCloudAppsConfigurationDiscoveryDataSource' -Raw:$Raw -Force:$Force }
            'DiscoveryEncryption' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/encryption_settings/' -TypeName 'XdrCloudAppsConfigurationDiscoveryEncryption' -Raw:$Raw -Force:$Force }
            'DiscoveryWeight' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/discovered_app_weights/' -TypeName 'XdrCloudAppsConfigurationDiscoveryWeight' -Raw:$Raw -Force:$Force }
            'DiscoveryReport' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/reports/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationDiscoveryReport' -Raw:$Raw -Force:$Force }
            'DiscoveryAppTag' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/tags/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationDiscoveryAppTag' -Raw:$Raw -Force:$Force }
            'DiscoveryExclusion' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/exclusions/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationDiscoveryExclusion' -Raw:$Raw -Force:$Force }
            'CustomParser' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/custom_parsers/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationCustomParser' -Raw:$Raw -Force:$Force }
            'IpTag' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/ip_tags/' -TypeName 'XdrCloudAppsConfigurationIpTag' -Raw:$Raw -Force:$Force }
            'Location' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/locations/' -TypeName 'XdrCloudAppsConfigurationLocation' -Raw:$Raw -Force:$Force }
            'LogCollector' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/log_collectors/' -TypeName 'XdrCloudAppsConfigurationLogCollector' -Raw:$Raw -Force:$Force }
            'ScopedDeployment' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/scoped_deployments/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationScopedDeployment' -Raw:$Raw -Force:$Force }
            'ScopedProfile' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/scoped_profiles/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationScopedProfile' -Raw:$Raw -Force:$Force }
            'SiemAgent' { Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/siem_agents/' -TypeName 'XdrCloudAppsConfigurationSiemAgent' -Raw:$Raw -Force:$Force }
            'Subnet' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/subnet/metadata/' -TypeName 'XdrCloudAppsConfigurationSubnetMetadata' -CacheKey 'XdrCloudAppsConfigurationSubnetMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/subnet/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationSubnet' -Raw:$Raw -Force:$Force
            }
            'UserTag' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/tags/metadata/' -TypeName 'XdrCloudAppsConfigurationUserTagMetadata' -CacheKey 'XdrCloudAppsConfigurationUserTagMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/tags/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsConfigurationUserTag' -Raw:$Raw -Force:$Force
            }
        }
    }
}

