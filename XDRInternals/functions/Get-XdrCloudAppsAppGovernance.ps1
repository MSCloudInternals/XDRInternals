function Get-XdrCloudAppsAppGovernance {
    <#
    .SYNOPSIS
        Retrieves App Governance information from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        The Get-XdrCloudAppsAppGovernance cmdlet retrieves App Governance information
        from Microsoft Defender for Cloud Apps.

        By default (no parameters), returns a summary object with key metrics:
        - IsOnboarded: Whether the tenant is onboarded to App Governance
        - IsInsightsReady: Whether tenant insights are ready
        - TotalApps, HighPrivilegeApps, OverpermissionedApps, UnusedApps, RiskyApps

        Use switch parameters to retrieve specific raw API data:
        - -TenantStatus: Returns full tenant onboarding status
        - -TenantMetric: Returns full tenant metrics
        - -TenantDataTraffic: Returns tenant data traffic information
        - -InsightsReady: Returns full insights ready status
        - -All: Returns all raw data as a combined object

        When a single switch is specified, returns just that data directly.
        When multiple switches are specified, returns an object with those properties.

    .PARAMETER TenantStatus
        Returns the full tenant onboarding status API response.

    .PARAMETER TenantMetric
        Returns the full tenant metrics API response.

    .PARAMETER TenantDataTraffic
        Returns the full tenant data traffic API response.

    .PARAMETER InsightsReady
        Returns the full insights ready API response.

    .PARAMETER All
        Returns all raw API response data as an object with TenantStatus, TenantMetric,
        TenantDataTraffic, and InsightsReady properties.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernance

        Returns a summary of App Governance status and metrics:
        IsOnboarded          : True
        IsInsightsReady      : True
        TotalApps            : 50
        HighPrivilegeApps    : 24
        OverpermissionedApps : 3
        UnusedApps           : 25
        RiskyApps            : 4

    .EXAMPLE
        Get-XdrCloudAppsAppGovernance -TenantMetric

        Returns the full tenant metrics data directly.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernance -TenantStatus -TenantDataTraffic

        Returns an object with TenantStatus and TenantDataTraffic properties.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernance -All

        Returns an object with all raw API data (TenantStatus, TenantMetric,
        TenantDataTraffic, InsightsReady).

    .EXAMPLE
        (Get-XdrCloudAppsAppGovernance -TenantDataTraffic).last3MonthDataTraffic

        Gets the last 3 months of data traffic directly.

    .EXAMPLE
        if ((Get-XdrCloudAppsAppGovernance).IsOnboarded) {
            Write-Host "App Governance is enabled"
        }

        Checks if the tenant is onboarded to App Governance.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernance -Force

        Forces a fresh retrieval, bypassing the cache.

    .OUTPUTS
        PSCustomObject
        Returns either a summary object (default), raw API data (single switch),
        or a combined object (multiple switches or -All).

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$TenantStatus,

        [Parameter()]
        [switch]$TenantMetric,

        [Parameter()]
        [switch]$TenantDataTraffic,

        [Parameter()]
        [switch]$InsightsReady,

        [Parameter()]
        [switch]$All,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Helper function to get cached or fresh data
        function Get-AppGovernanceData {
            param (
                [string]$CacheKey,
                [string]$Uri,
                [string]$Description,
                [bool]$ForceRefresh,
                [int]$TTLMinutes = 5
            )

            if (-not $ForceRefresh) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached $Description"
                    return $cache.Value
                }
            }

            Write-Verbose "Retrieving $Description from API"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Handle JSON string responses (some endpoints return string instead of object)
                if ($response -is [string]) {
                    $response = $response | ConvertFrom-Json -AsHashtable
                    $response = [PSCustomObject]$response
                }

                $result = if ($null -ne $response.data) { $response.data } else { $response }

                if ($null -ne $result) {
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes $TTLMinutes
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve $Description`: $_"
                return $null
            }
        }

        # Define endpoints
        $endpoints = @{
            TenantStatus      = @{
                CacheKey    = "XdrCloudAppsAppGovernanceTenantStatus"
                Uri         = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/istenantonboarded"
                Description = "App Governance tenant status"
                TTLMinutes  = 15
            }
            TenantMetric      = @{
                CacheKey    = "XdrCloudAppsAppGovernanceTenantMetric"
                Uri         = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/tenantmetrics"
                Description = "App Governance tenant metrics"
                TTLMinutes  = 5
            }
            TenantDataTraffic = @{
                CacheKey    = "XdrCloudAppsAppGovernanceTenantDataTraffic"
                Uri         = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/tenantdatatraffic?api-version=1.0&versionNumber=2"
                Description = "App Governance tenant data traffic"
                TTLMinutes  = 5
            }
            InsightsReady     = @{
                CacheKey    = "XdrCloudAppsAppGovernanceInsightsReady"
                Uri         = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/istenantinsightsready"
                Description = "App Governance insights status"
                TTLMinutes  = 15
            }
        }

        # Count how many switches are specified
        $switchCount = 0
        if ($TenantStatus) { $switchCount++ }
        if ($TenantMetric) { $switchCount++ }
        if ($TenantDataTraffic) { $switchCount++ }
        if ($InsightsReady) { $switchCount++ }

        # If -All or multiple switches, return combined object
        if ($All -or $switchCount -gt 1) {
            $outputProperties = [ordered]@{}

            if ($All -or $TenantStatus) {
                $outputProperties['TenantStatus'] = Get-AppGovernanceData -CacheKey $endpoints.TenantStatus.CacheKey -Uri $endpoints.TenantStatus.Uri -Description $endpoints.TenantStatus.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantStatus.TTLMinutes
            }

            if ($All -or $TenantMetric) {
                $outputProperties['TenantMetric'] = Get-AppGovernanceData -CacheKey $endpoints.TenantMetric.CacheKey -Uri $endpoints.TenantMetric.Uri -Description $endpoints.TenantMetric.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantMetric.TTLMinutes
            }

            if ($All -or $TenantDataTraffic) {
                $outputProperties['TenantDataTraffic'] = Get-AppGovernanceData -CacheKey $endpoints.TenantDataTraffic.CacheKey -Uri $endpoints.TenantDataTraffic.Uri -Description $endpoints.TenantDataTraffic.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantDataTraffic.TTLMinutes
            }

            if ($All -or $InsightsReady) {
                $outputProperties['InsightsReady'] = Get-AppGovernanceData -CacheKey $endpoints.InsightsReady.CacheKey -Uri $endpoints.InsightsReady.Uri -Description $endpoints.InsightsReady.Description -ForceRefresh $Force -TTLMinutes $endpoints.InsightsReady.TTLMinutes
            }

            return [PSCustomObject]$outputProperties
        }

        # If single switch, return just that data directly
        if ($TenantStatus) {
            return Get-AppGovernanceData -CacheKey $endpoints.TenantStatus.CacheKey -Uri $endpoints.TenantStatus.Uri -Description $endpoints.TenantStatus.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantStatus.TTLMinutes
        }

        if ($TenantMetric) {
            return Get-AppGovernanceData -CacheKey $endpoints.TenantMetric.CacheKey -Uri $endpoints.TenantMetric.Uri -Description $endpoints.TenantMetric.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantMetric.TTLMinutes
        }

        if ($TenantDataTraffic) {
            return Get-AppGovernanceData -CacheKey $endpoints.TenantDataTraffic.CacheKey -Uri $endpoints.TenantDataTraffic.Uri -Description $endpoints.TenantDataTraffic.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantDataTraffic.TTLMinutes
        }

        if ($InsightsReady) {
            return Get-AppGovernanceData -CacheKey $endpoints.InsightsReady.CacheKey -Uri $endpoints.InsightsReady.Uri -Description $endpoints.InsightsReady.Description -ForceRefresh $Force -TTLMinutes $endpoints.InsightsReady.TTLMinutes
        }

        # Default: return summary
        $statusData = Get-AppGovernanceData -CacheKey $endpoints.TenantStatus.CacheKey -Uri $endpoints.TenantStatus.Uri -Description $endpoints.TenantStatus.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantStatus.TTLMinutes

        $metricsData = Get-AppGovernanceData -CacheKey $endpoints.TenantMetric.CacheKey -Uri $endpoints.TenantMetric.Uri -Description $endpoints.TenantMetric.Description -ForceRefresh $Force -TTLMinutes $endpoints.TenantMetric.TTLMinutes

        $insightsData = Get-AppGovernanceData -CacheKey $endpoints.InsightsReady.CacheKey -Uri $endpoints.InsightsReady.Uri -Description $endpoints.InsightsReady.Description -ForceRefresh $Force -TTLMinutes $endpoints.InsightsReady.TTLMinutes

        $summary = [PSCustomObject]@{
            IsOnboarded          = $statusData.isTenantOnboarded
            IsInsightsReady      = $insightsData.isTenantInsightsReady
            TotalApps            = $metricsData.numberOfApps
            HighPrivilegeApps    = $metricsData.numberOfHighPrivilegedApps
            OverpermissionedApps = $metricsData.numberOfOverPermissionedApps
            UnusedApps           = $metricsData.numberOfUnusedApps
            RiskyApps            = $metricsData.numberOfRiskyApps
        }

        $summary.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernanceSummary')
        return $summary
    }
}
