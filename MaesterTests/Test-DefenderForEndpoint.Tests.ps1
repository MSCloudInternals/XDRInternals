BeforeDiscovery {
    try {
        $MdePlan = Get-XdrTenantWorkloadStatus -Workload "IsMdeActive" | Select-Object -ExpandProperty IsActive
    } catch {
        $MdePlan = "NotConnected"
    }
}

Describe "Custom Tests for Microsoft Defender for Endpoint" -Tag "XDRInternals", "MDE", "Security", "All" {
    BeforeAll {
        try {
            $MdePlan = Get-XdrTenantWorkloadStatus -Workload "IsMdeActive" | Select-Object -ExpandProperty IsActive
            $TotalLicenseCount = Invoke-XdrRestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/licenses/mgmt/aadlicenses/sums" -Method "GET" | Select-Object -ExpandProperty sums
            $MdeP1LicenseCount = $TotalLicenseCount.p1
            $MdeP2LicenseCount = $TotalLicenseCount.p2
            $LicenseReport = Get-XdrEndpointLicenseReport
            $MdeP1LicenseReport = $LicenseReport | Where-Object { $_.sku -eq "p1" }
            $MdeP2LicenseReport = $LicenseReport | Where-Object { $_.sku -eq "p2" }
        } catch {
            Write-Error "Failed to retrieve license information: $_"
        }
    }

    It "XDRInternal.101: License Validation P1" -Tag "XDRInternal.101" {
        if ( $MdePlan) {
            if ($MdeP1LicenseCount -lt $MdeP1LicenseReport.DetectedUsers) {
                Add-MtTestResultDetail -Description "Not enough MDE P1 licenses detected" -Result "Expected: $MdeP1LicenseCount, Assigned: $($MdeP1LicenseReport.DetectedUsers)"
            } else {
                Add-MtTestResultDetail -Description "Sufficient MDE P1 licenses detected" -Result "Expected: $MdeP1LicenseCount, Assigned: $($MdeP1LicenseReport.DetectedUsers)"
            }
            $MdeP1LicenseCount | Should -BeGreaterOrEqual $MdeP1LicenseReport.DetectedUsers -Because "There should be enough MDE P1 licenses for assigned users."
        } else {
            Add-MtTestResultDetail -SkippedCustomReason "MDE workload is not active in this tenant." -Status "Skip"
        }
    }

    It "XDRInternal.102: License Validation P2" -Tag "XDRInternal.102" {
        if ( $MdePlan) {
            if ($MdeP2LicenseCount -lt $MdeP2LicenseReport.DetectedUsers) {
                Add-MtTestResultDetail -Description "Not enough MDE P2 licenses detected" -Result "Expected: $MdeP2LicenseCount, Assigned: $($MdeP2LicenseReport.DetectedUsers)"
            } else {
                Add-MtTestResultDetail -Description "Sufficient MDE P2 licenses detected" -Result "Expected: $MdeP2LicenseCount, Assigned: $($MdeP2LicenseReport.DetectedUsers)"
            }
            $MdeP2LicenseCount | Should -BeGreaterOrEqual $MdeP2LicenseReport.DetectedUsers -Because "There should be enough MDE P2 licenses for assigned users."
        } else {
            Add-MtTestResultDetail -SkippedCustomReason "MDE workload is not active in this tenant." -Status "Skip"
        }
    }

    It "XDRInternal.103: Pending Actions Check" -Tag "XDRInternal.103" -Skip:( $MdePlan -ne $true ) {
        if ( $MdePlan) {
            $PendingActions = Get-XdrActionsCenterPending -PageSize 10
            $PendingCount = $PendingActions.Count

            if ($PendingCount -gt 0) {
                Add-MtTestResultDetail -Description "Pending actions found in Action Center" -Result "Total Pending Actions: $PendingCount"
            } else {
                Add-MtTestResultDetail -Description "No pending actions in Action Center" -Result "Total Pending Actions: $PendingCount"
            }
        } else {
            Add-MtTestResultDetail -SkippedCustomReason "MDE workload is not active in this tenant." -Status "Skip"
        }
    }
    # Get-XdrEndpointAdvancedFeatures checks

    It "XDRInternal.104: Configuration Best Practices" -Tag "XDRInternal.104" -Skip:( $MdePlan -ne $true ) {
        if ( $MdePlan) {
            $CriticalEnabledAdvancedFeatures = @(
                "EnableEDRInBlockMode",
                "DeviceDiscovery",
                "TamperProtection",
                "CustomNetworkIndicators",
                "LiveResponse",
                "LiveResponseForServers",
                "AlwaysRemediatePUA"
            )
            $CriticalDisabledAdvancedFeatures = @(
                "LiveResponseUnsignedScriptExecution"
            )
            $AdvancedFeatures = Get-XdrEndpointAdvancedFeatures

            $AdvancedFeaturesList = "#### Advanced Features `n`n| Result | Name | Expected value | Description |`n"
            $AdvancedFeaturesList += "| --- | --- | --- | --- |`n"

            foreach ($Feature in $CriticalEnabledAdvancedFeatures) {
                $CurrentFeature = $AdvancedFeatures | Where-Object Name -EQ $Feature
                if ($CurrentFeature.Value -ne $true) {
                    $FeatureResult = "❌ Fail"
                } else {
                    $FeatureResult = "✅ Pass"
                }
                $AdvancedFeaturesList += "| $($FeatureResult) | $($Feature) | Enabled | $($CurrentFeature.Description) |`n"
            }

            foreach ($Feature in $CriticalDisabledAdvancedFeatures) {
                $CurrentFeature = $AdvancedFeatures | Where-Object Name -EQ $Feature
                if ($CurrentFeature.Value -ne $false) {
                    $FeatureResult = "❌ Fail"
                } else {
                    $FeatureResult = "✅ Pass"
                }
                $AdvancedFeaturesList += "| $($FeatureResult) | $($Feature) | Disabled | $($CurrentFeature.Description) |`n"
            }

            Add-MtTestResultDetail -Description "Endpoint Advanced Features Configuration" -Result $AdvancedFeaturesList

            foreach ($Feature in $CriticalEnabledAdvancedFeatures) {
                $CurrentFeature = $AdvancedFeatures | Where-Object Name -EQ $Feature
                $CurrentFeature.Value | Should -Be $true -Because "Critical advanced feature '$Feature' should be enabled. $($CurrentFeature.Description)"
            }
            foreach ($Feature in $CriticalDisabledAdvancedFeatures) {
                $CurrentFeature = $AdvancedFeatures | Where-Object Name -EQ $Feature
                $CurrentFeature.Value | Should -Be $false -Because "Critical advanced feature '$Feature' should be disabled. $($CurrentFeature.Description)"
            }
        } else {
            Add-MtTestResultDetail -SkippedCustomReason "MDE workload is not active in this tenant." -Status "Skip"
        }
    }
}