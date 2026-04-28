function Get-XdrCloudAppsGovernance {
    <#
    .SYNOPSIS
        Retrieves governance data from Microsoft Defender for Cloud Apps and App Governance.

    .DESCRIPTION
        Retrieves Cloud Apps governance action logs and App Governance summary,
        app, policy, label, and tenant metric data.

    .PARAMETER Type
        Governance data type to retrieve.

    .PARAMETER Metadata
        Retrieves metadata for governance action logs.

    .PARAMETER CountOnly
        Retrieves only a governance action count when supported.

    .PARAMETER Id
        Identifier for item-specific governance queries.

    .PARAMETER Limit
        Maximum number of records to request.

    .PARAMETER Skip
        Number of records to skip.

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
        Get-XdrCloudAppsGovernance

        Retrieves an App Governance summary.

    .EXAMPLE
        Get-XdrCloudAppsGovernance -Type ActionLog -Limit 100

        Retrieves governance action log entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Summary', 'ActionLog', 'App', 'Label', 'Policy', 'PolicyInsight', 'PredefinedPolicy', 'UserProfile', 'TenantStatus', 'TenantMetric', 'TenantDataTraffic', 'InsightsReady')]
        [string]$Type = 'Summary',

        [Parameter()]
        [switch]$Metadata,

        [Parameter()]
        [switch]$CountOnly,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('_id')]
        [string]$Id,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$Limit = 100,

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter()]
        [string]$SortField = 'date',

        [Parameter()]
        [ValidateSet('asc', 'desc')]
        [string]$SortDirection = 'desc',

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
            'TenantStatus' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantonboarded' -TypeName 'XdrCloudAppsGovernanceTenantStatus' -CacheKey 'XdrCloudAppsGovernanceTenantStatus' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'TenantMetric' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/tenantmetrics' -TypeName 'XdrCloudAppsGovernanceTenantMetric' -CacheKey 'XdrCloudAppsGovernanceTenantMetric' -Raw:$Raw -Force:$Force }
            'TenantDataTraffic' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/tenantdatatraffic?api-version=1.0&versionNumber=2' -TypeName 'XdrCloudAppsGovernanceTenantDataTraffic' -CacheKey 'XdrCloudAppsGovernanceTenantDataTraffic' -Raw:$Raw -Force:$Force }
            'InsightsReady' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantinsightsready' -TypeName 'XdrCloudAppsGovernanceInsightsReady' -CacheKey 'XdrCloudAppsGovernanceInsightsReady' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'App' {
                if ($Id) {
                    Invoke-XdrCloudAppsRequest -Path "/m365appprotection/mapg-glsservice/apps/$Id" -TypeName 'XdrCloudAppsGovernanceApp' -Raw:$Raw -Force:$Force
                }
                else {
                    Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/apps' -TypeName 'XdrCloudAppsGovernanceApp' -Raw:$Raw -Force:$Force
                }
            }
            'Label' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/labels' -TypeName 'XdrCloudAppsGovernanceLabel' -CacheKey 'XdrCloudAppsGovernanceLabel' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'Policy' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/policies' -TypeName 'XdrCloudAppsGovernancePolicy' -Raw:$Raw -Force:$Force }
            'PolicyInsight' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/policyinsights' -TypeName 'XdrCloudAppsGovernancePolicyInsight' -Raw:$Raw -Force:$Force }
            'PredefinedPolicy' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/predefinedpolicies' -TypeName 'XdrCloudAppsGovernancePredefinedPolicy' -CacheKey 'XdrCloudAppsGovernancePredefinedPolicy' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'UserProfile' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/userprofile' -TypeName 'XdrCloudAppsGovernanceUserProfile' -CacheKey 'XdrCloudAppsGovernanceUserProfile' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'ActionLog' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/governance/actions/metadata/' -TypeName 'XdrCloudAppsGovernanceActionMetadata' -CacheKey 'XdrCloudAppsGovernanceActionMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                if ($CountOnly) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/governance/actions/count/' -Method Post -Body @{ filters = $Filters } -Raw -Force:$Force
                    return
                }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/governance/actions/' -Method Post -Body $gridBody -TypeName 'XdrCloudAppsGovernanceAction' -Raw:$Raw -Force:$Force
            }
            'Summary' {
                $tenantStatus = Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantonboarded' -Raw -Force:$Force
                $tenantMetric = Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/tenantmetrics' -Raw -Force:$Force
                $insightsReady = Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantinsightsready' -Raw -Force:$Force
                [PSCustomObject]@{
                    PSTypeName            = 'XdrCloudAppsGovernanceSummary'
                    IsOnboarded           = [bool]$tenantStatus
                    IsInsightsReady       = [bool]$insightsReady
                    TotalApps             = $tenantMetric.totalApps
                    HighPrivilegeApps     = $tenantMetric.highPrivilegeApps
                    OverpermissionedApps  = $tenantMetric.overpermissionedApps
                    UnusedApps            = $tenantMetric.unusedApps
                    RiskyApps             = $tenantMetric.riskyApps
                    RawTenantMetric       = $tenantMetric
                }
            }
        }
    }
}

