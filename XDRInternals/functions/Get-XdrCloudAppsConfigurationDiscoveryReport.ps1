function Get-XdrCloudAppsConfigurationDiscoveryReport {
    <#
    .SYNOPSIS
        Retrieves discovery reports from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the discovery reports from Microsoft Defender for Cloud Apps,
        including snapshot reports, continuous reports, or both.
        Discovery reports contain cloud app usage data collected from traffic logs.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER ReportType
        Specifies the type of discovery reports to retrieve.
        Valid values are 'Snapshot', 'Continuous', or 'All'.
        Default is 'All' which retrieves both types and adds a ReportType property.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryReport
        Retrieves all discovery reports (snapshot and continuous) using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryReport -ReportType Snapshot
        Retrieves only snapshot discovery reports.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryReport -ReportType Continuous
        Retrieves only continuous discovery reports.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryReport -Force
        Forces a fresh retrieval of all discovery reports, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationDiscoveryReport[]
        Returns an array of discovery report objects containing report configuration details.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('Snapshot', 'Continuous', 'All')]
        [string]$ReportType = 'All',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConfigurationDiscoveryReport_$ReportType"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps discovery reports"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps discovery reports cache is missing or expired"
        }

        $BaseUri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery"
        $Body = @{
            skip              = 0
            limit             = 100
            filters           = @{}
            performAsyncTotal = $false
        } | ConvertTo-Json -Compress

        Write-Verbose "Retrieving Cloud Apps discovery reports (Type: $ReportType)"

        try {
            $result = @()

            if ($ReportType -eq 'Snapshot' -or $ReportType -eq 'All') {
                $SnapshotUri = "$BaseUri/snapshot_reports/"
                Write-Verbose "Retrieving snapshot reports from $SnapshotUri"
                $snapshotResponse = Invoke-RestMethod -Uri $SnapshotUri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $snapshotData = if ($null -ne $snapshotResponse.data) { $snapshotResponse.data } else { $snapshotResponse }
                if ($null -ne $snapshotData) {
                    foreach ($item in $snapshotData) {
                        if ($ReportType -eq 'All') {
                            $item | Add-Member -NotePropertyName 'ReportType' -NotePropertyValue 'Snapshot' -Force
                        }
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryReport')
                    }
                    $result += $snapshotData
                }
            }

            if ($ReportType -eq 'Continuous' -or $ReportType -eq 'All') {
                $ContinuousUri = "$BaseUri/continuous_reports/"
                Write-Verbose "Retrieving continuous reports from $ContinuousUri"
                $continuousResponse = Invoke-RestMethod -Uri $ContinuousUri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $continuousData = if ($null -ne $continuousResponse.data) { $continuousResponse.data } else { $continuousResponse }
                if ($null -ne $continuousData) {
                    foreach ($item in $continuousData) {
                        if ($ReportType -eq 'All') {
                            $item | Add-Member -NotePropertyName 'ReportType' -NotePropertyValue 'Continuous' -Force
                        }
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryReport')
                    }
                    $result += $continuousData
                }
            }

            if ($result.Count -gt 0) {
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps discovery reports: $_"
        }
    }

    end {
    }
}
