function Get-XdrCloudAppsGovernance {
    <#
    .SYNOPSIS
        Retrieves governance data from Microsoft Defender for Cloud Apps and App Governance.

    .DESCRIPTION
        Retrieves live-validated App Governance summary, app, policy, label,
        user profile, and tenant metric data.

    .PARAMETER Type
        Governance data type to retrieve.

    .PARAMETER Id
        Identifier for item-specific governance queries.

    .PARAMETER Raw
        Returns the raw API response shape.

    .PARAMETER Force
        Bypasses cache-backed requests.

    .EXAMPLE
        Get-XdrCloudAppsGovernance

        Retrieves an App Governance summary.

    .EXAMPLE
        Get-XdrCloudAppsGovernance -Type App

        Retrieves App Governance app data.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Summary', 'App', 'Label', 'Policy', 'PolicyInsight', 'UserProfile', 'TenantStatus', 'TenantMetric', 'TenantDataTraffic', 'InsightsReady')]
        [string]$Type = 'Summary',

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('_id')]
        [string]$Id,

        [Parameter()]
        [switch]$Raw,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        switch ($Type) {
            'TenantStatus' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantonboarded' -TypeName 'XdrCloudAppsGovernanceTenantStatus' -CacheKey 'XdrCloudAppsGovernanceTenantStatus' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'TenantMetric' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/tenantmetrics' -TypeName 'XdrCloudAppsGovernanceTenantMetric' -CacheKey 'XdrCloudAppsGovernanceTenantMetric' -Raw:$Raw -Force:$Force }
            'TenantDataTraffic' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/tenantdatatraffic?api-version=1.0&versionNumber=2' -TypeName 'XdrCloudAppsGovernanceTenantDataTraffic' -CacheKey 'XdrCloudAppsGovernanceTenantDataTraffic' -Raw:$Raw -Force:$Force }
            'InsightsReady' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantinsightsready' -TypeName 'XdrCloudAppsGovernanceInsightsReady' -CacheKey 'XdrCloudAppsGovernanceInsightsReady' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'App' {
                if ($Id) {
                    Invoke-XdrCloudAppsRequest -Path "/m365appprotection/mapg-glsservice/compliance/apps/$Id" -TypeName 'XdrCloudAppsGovernanceApp' -Raw:$Raw -Force:$Force
                }
                else {
                    Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/apps' -TypeName 'XdrCloudAppsGovernanceApp' -Raw:$Raw -Force:$Force
                }
            }
            'Label' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/getLabels' -TypeName 'XdrCloudAppsGovernanceLabel' -CacheKey 'XdrCloudAppsGovernanceLabel' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'Policy' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/policies' -TypeName 'XdrCloudAppsGovernancePolicy' -Raw:$Raw -Force:$Force }
            'PolicyInsight' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/policyinsights' -TypeName 'XdrCloudAppsGovernancePolicyInsight' -Raw:$Raw -Force:$Force }
            'UserProfile' { Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/getUserProfile' -TypeName 'XdrCloudAppsGovernanceUserProfile' -CacheKey 'XdrCloudAppsGovernanceUserProfile' -TTLMinutes 15 -Raw:$Raw -Force:$Force }
            'Summary' {
                $tenantStatus = Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantonboarded' -Raw -Force:$Force
                $tenantMetric = Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/tenantmetrics' -Raw -Force:$Force
                $insightsReady = Invoke-XdrCloudAppsRequest -Path '/m365appprotection/mapg-glsservice/compliance/istenantinsightsready' -Raw -Force:$Force
                [PSCustomObject]@{
                    PSTypeName            = 'XdrCloudAppsGovernanceSummary'
                    IsOnboarded           = [bool]$tenantStatus
                    IsInsightsReady       = [bool]$insightsReady
                    TotalApps             = $tenantMetric.numberOfApps
                    HighPrivilegeApps     = $tenantMetric.numberOfHighPrivilegedApps
                    OverpermissionedApps  = $tenantMetric.numberOfOverPermissionedApps
                    UnusedApps            = $tenantMetric.numberOfUnusedApps
                    RiskyApps             = $tenantMetric.numberOfRiskyApps
                    RawTenantMetric       = $tenantMetric
                }
            }
        }
    }
}
