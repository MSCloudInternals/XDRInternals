function Set-XdrEndpointAdvancedFeatures {
    <#
    .SYNOPSIS
        Configures advanced features settings for Microsoft Defender for Endpoint.

    .DESCRIPTION
        Sets advanced features configuration for Microsoft Defender for Endpoint.
        This function updates various advanced features across different configuration endpoints.
        
        Note: AlwaysRemediatePUA and EnableAutomaticAttackDisruption cannot be changed through this function
        as they are part of PotentiallyUnwantedApplications which is read-only.

    .PARAMETER EnableEDRInBlockMode
        Enable EDR in block mode.

    .PARAMETER EnableMicrosoftDefenderAntivirusInAuditMode
        Enable Microsoft Defender Antivirus in audit mode.

    .PARAMETER DeviceDiscovery
        Enable device discovery.

    .PARAMETER HidePotentialDuplicateDeviceRecords
        Hide potential duplicate device records.

    .PARAMETER AllowOrBlockFile
        Enable allow or block file feature.

    .PARAMETER SkypeForBusinessIntegration
        Enable Skype for Business integration.

    .PARAMETER ShowUserDetails
        Show user details.

    .PARAMETER MicrosoftDefenderForIdentityIntegration
        Enable Microsoft Defender for Identity integration.

    .PARAMETER AutomaticallyResolveAlerts
        Automatically resolve alerts.

    .PARAMETER MicrosoftDefenderForCloudApps
        Enable Microsoft Defender for Cloud Apps integration.

    .PARAMETER AzureInformationProtection
        Enable Azure Information Protection integration.

    .PARAMETER TamperProtection
        Enable tamper protection.

    .PARAMETER CustomNetworkIndicators
        Enable custom network indicators.

    .PARAMETER WebContentFiltering
        Enable web content filtering.

    .PARAMETER MicrosoftEndpointDLP
        Enable Microsoft Endpoint DLP.

    .PARAMETER DownloadQuarantinedFiles
        Enable download of quarantined files.

    .PARAMETER RestrictCorrelationToWithinScopedDeviceGroups
        Restrict correlation to within scoped device groups.

    .PARAMETER ExcludeDevices
        Enable exclude devices feature.

    .PARAMETER ActiveIncidentResponse
        Enable Active Incident Response (DART).

    .PARAMETER AggregatedReporting
        Enable aggregated reporting.

    .PARAMETER IsolationExclusionRules
        Enable isolation exclusion rules.

    .PARAMETER DefaultToStreamlinedConnectivityWhenOnboardingDevicesInDefenderPortal
        Default to streamlined connectivity when onboarding devices.

    .PARAMETER ApplyStreamlinedConnectivitySettingsToDevicesManagedByIntuneAndDefenderForCloud
        Apply streamlined connectivity settings to devices managed by Intune and Defender for Cloud.

    .PARAMETER PreviewFeatures
        Enable preview features.

    .PARAMETER PurviewSharing
        Enable Purview alert sharing.

    .PARAMETER LiveResponse
        Enable Live Response.

    .PARAMETER LiveResponseForServers
        Enable Live Response for servers.

    .PARAMETER LiveResponseUnsignedScriptExecution
        Enable unsigned script execution in Live Response.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .EXAMPLE
        Set-XdrEndpointAdvancedFeatures -EnableEDRInBlockMode $true
        Enables EDR in block mode.

    .EXAMPLE
        Set-XdrEndpointAdvancedFeatures -PreviewFeatures $true -WhatIf
        Shows what would happen when enabling preview features without actually making the change.

    .EXAMPLE
        Set-XdrEndpointAdvancedFeatures -LiveResponse $true -LiveResponseForServers $true
        Enables Live Response for both workstations and servers.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param (
        # Advanced Features parameters
        [Parameter()]
        [bool]$EnableEDRInBlockMode,

        [Parameter()]
        [bool]$EnableMicrosoftDefenderAntivirusInAuditMode,

        [Parameter()]
        [bool]$DeviceDiscovery,

        [Parameter()]
        [bool]$HidePotentialDuplicateDeviceRecords,

        [Parameter()]
        [bool]$AllowOrBlockFile,

        [Parameter()]
        [bool]$SkypeForBusinessIntegration,

        [Parameter()]
        [bool]$ShowUserDetails,

        [Parameter()]
        [bool]$MicrosoftDefenderForIdentityIntegration,

        [Parameter()]
        [bool]$AutomaticallyResolveAlerts,

        [Parameter()]
        [bool]$MicrosoftDefenderForCloudApps,

        [Parameter()]
        [bool]$AzureInformationProtection,

        [Parameter()]
        [bool]$TamperProtection,

        [Parameter()]
        [bool]$CustomNetworkIndicators,

        [Parameter()]
        [bool]$WebContentFiltering,

        [Parameter()]
        [bool]$MicrosoftEndpointDLP,

        [Parameter()]
        [bool]$DownloadQuarantinedFiles,

        [Parameter()]
        [bool]$RestrictCorrelationToWithinScopedDeviceGroups,

        [Parameter()]
        [bool]$ExcludeDevices,

        [Parameter()]
        [bool]$ActiveIncidentResponse,

        [Parameter()]
        [bool]$AggregatedReporting,

        [Parameter()]
        [bool]$IsolationExclusionRules,

        [Parameter()]
        [bool]$DefaultToStreamlinedConnectivityWhenOnboardingDevicesInDefenderPortal,

        [Parameter()]
        [bool]$ApplyStreamlinedConnectivitySettingsToDevicesManagedByIntuneAndDefenderForCloud,

        # Preview Features parameters
        [Parameter()]
        [bool]$PreviewFeatures,

        # Purview Sharing parameter
        [Parameter()]
        [bool]$PurviewSharing,

        # Live Response parameters
        [Parameter()]
        [bool]$LiveResponse,

        [Parameter()]
        [bool]$LiveResponseForServers,

        [Parameter()]
        [bool]$LiveResponseUnsignedScriptExecution
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Determine which settings need to be updated based on provided parameters
        $advancedFeaturesParams = @(
            'EnableEDRInBlockMode', 'EnableMicrosoftDefenderAntivirusInAuditMode', 'DeviceDiscovery',
            'HidePotentialDuplicateDeviceRecords', 'AllowOrBlockFile', 'SkypeForBusinessIntegration',
            'ShowUserDetails', 'MicrosoftDefenderForIdentityIntegration', 'AutomaticallyResolveAlerts',
            'MicrosoftDefenderForCloudApps', 'AzureInformationProtection', 'TamperProtection',
            'CustomNetworkIndicators', 'WebContentFiltering', 'MicrosoftEndpointDLP',
            'DownloadQuarantinedFiles', 'RestrictCorrelationToWithinScopedDeviceGroups', 'ExcludeDevices',
            'ActiveIncidentResponse', 'AggregatedReporting', 'IsolationExclusionRules',
            'DefaultToStreamlinedConnectivityWhenOnboardingDevicesInDefenderPortal',
            'ApplyStreamlinedConnectivitySettingsToDevicesManagedByIntuneAndDefenderForCloud'
        )
        
        $liveResponseParams = @('LiveResponse', 'LiveResponseForServers', 'LiveResponseUnsignedScriptExecution')
        $previewFeaturesParams = @('PreviewFeatures')
        $purviewSharingParams = @('PurviewSharing')

        # Check if any advanced features parameters were provided
        $hasAdvancedFeatures = $advancedFeaturesParams | Where-Object { $PSBoundParameters.ContainsKey($_) }
        $hasLiveResponse = $liveResponseParams | Where-Object { $PSBoundParameters.ContainsKey($_) }
        $hasPreviewFeatures = $previewFeaturesParams | Where-Object { $PSBoundParameters.ContainsKey($_) }
        $hasPurviewSharing = $purviewSharingParams | Where-Object { $PSBoundParameters.ContainsKey($_) }

        # Update Advanced Features
        if ($hasAdvancedFeatures) {
            Write-Verbose "Updating Advanced Features configuration"
            
            # Get current configuration
            $currentConfig = Get-XdrEndpointConfigurationAdvancedFeatures
            
            # Update only the properties that were specified
            if ($PSBoundParameters.ContainsKey('EnableEDRInBlockMode')) {
                $currentConfig.EnableWdavPassiveModeRemediation = $EnableEDRInBlockMode
            }
            if ($PSBoundParameters.ContainsKey('EnableMicrosoftDefenderAntivirusInAuditMode')) {
                $currentConfig.EnableWdavAuditMode = $EnableMicrosoftDefenderAntivirusInAuditMode
            }
            if ($PSBoundParameters.ContainsKey('DeviceDiscovery')) {
                $currentConfig.MagellanOptOut = -not $DeviceDiscovery
            }
            if ($PSBoundParameters.ContainsKey('HidePotentialDuplicateDeviceRecords')) {
                $currentConfig.HidePotentialDuplications = $HidePotentialDuplicateDeviceRecords
            }
            if ($PSBoundParameters.ContainsKey('AllowOrBlockFile')) {
                $currentConfig.BlockListEnabled = $AllowOrBlockFile
            }
            if ($PSBoundParameters.ContainsKey('SkypeForBusinessIntegration')) {
                $currentConfig.SkypeIntegrationEnabled = $SkypeForBusinessIntegration
            }
            if ($PSBoundParameters.ContainsKey('ShowUserDetails')) {
                $currentConfig.ShowUserAadProfile = $ShowUserDetails
            }
            if ($PSBoundParameters.ContainsKey('MicrosoftDefenderForIdentityIntegration')) {
                $currentConfig.AatpIntegrationEnabled = $MicrosoftDefenderForIdentityIntegration
            }
            if ($PSBoundParameters.ContainsKey('AutomaticallyResolveAlerts')) {
                $currentConfig.AutoResolveInvestigatedAlerts = $AutomaticallyResolveAlerts
            }
            if ($PSBoundParameters.ContainsKey('MicrosoftDefenderForCloudApps')) {
                $currentConfig.EnableMcasIntegration = $MicrosoftDefenderForCloudApps
            }
            if ($PSBoundParameters.ContainsKey('AzureInformationProtection')) {
                $currentConfig.EnableAipIntegration = $AzureInformationProtection
            }
            if ($PSBoundParameters.ContainsKey('TamperProtection')) {
                $currentConfig.EnableWdavAntiTampering = $TamperProtection
            }
            if ($PSBoundParameters.ContainsKey('CustomNetworkIndicators')) {
                $currentConfig.AllowWdavNetworkBlock = $CustomNetworkIndicators
            }
            if ($PSBoundParameters.ContainsKey('WebContentFiltering')) {
                $currentConfig.WebCategoriesEnabled = $WebContentFiltering
            }
            if ($PSBoundParameters.ContainsKey('MicrosoftEndpointDLP')) {
                $currentConfig.EnableEndpointDlp = $MicrosoftEndpointDLP
            }
            if ($PSBoundParameters.ContainsKey('DownloadQuarantinedFiles')) {
                $currentConfig.EnableQuarantinedFileDownload = $DownloadQuarantinedFiles
            }
            if ($PSBoundParameters.ContainsKey('RestrictCorrelationToWithinScopedDeviceGroups')) {
                $currentConfig.IsolateIncidentsWithDifferentDeviceGroups = $RestrictCorrelationToWithinScopedDeviceGroups
            }
            if ($PSBoundParameters.ContainsKey('ExcludeDevices')) {
                $currentConfig.EnableExcludedDevices = $ExcludeDevices
            }
            if ($PSBoundParameters.ContainsKey('ActiveIncidentResponse')) {
                $currentConfig.DartDataCollection = $ActiveIncidentResponse
            }
            if ($PSBoundParameters.ContainsKey('AggregatedReporting')) {
                $currentConfig.EnableAggregatedReporting = $AggregatedReporting
            }
            if ($PSBoundParameters.ContainsKey('IsolationExclusionRules')) {
                $currentConfig.IsolationExclusionOptIn = $IsolationExclusionRules
            }
            if ($PSBoundParameters.ContainsKey('DefaultToStreamlinedConnectivityWhenOnboardingDevicesInDefenderPortal')) {
                $currentConfig.UseSimplifiedConnectivity = $DefaultToStreamlinedConnectivityWhenOnboardingDevicesInDefenderPortal
            }
            if ($PSBoundParameters.ContainsKey('ApplyStreamlinedConnectivitySettingsToDevicesManagedByIntuneAndDefenderForCloud')) {
                $currentConfig.UseSimplifiedConnectivityViaApi = $ApplyStreamlinedConnectivitySettingsToDevicesManagedByIntuneAndDefenderForCloud
            }

            $uri = "https://security.microsoft.com/apiproxy/mtp/settings/SaveAdvancedFeaturesSetting"
            $method = "POST"
            $body = $currentConfig | ConvertTo-Json -Depth 10

            if ($WhatIfPreference) {
                Write-Host "`nAdvanced Features Update:" -ForegroundColor Cyan
                Write-Host "URI: $uri" -ForegroundColor Yellow
                Write-Host "Method: $method" -ForegroundColor Yellow
                Write-Host "Body:" -ForegroundColor Yellow
                Write-Host $body -ForegroundColor Gray
            }
            if ($PSCmdlet.ShouldProcess("Advanced Features Configuration", "Update")) {
                try {
                    $null = Invoke-RestMethod -Uri $uri -Method $method -Body $body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    Write-Host "Advanced Features configuration updated successfully"
                } catch {
                    Write-Error "Failed to update Advanced Features configuration: $_"
                }
            }
        }

        # Update Live Response
        if ($hasLiveResponse) {
            Write-Verbose "Updating Live Response configuration"
            
            # Get current configuration
            $currentConfig = Get-XdrEndpointConfigurationLiveResponse
            
            # Update only the properties that were specified
            if ($PSBoundParameters.ContainsKey('LiveResponse')) {
                $currentConfig.AutomatedIrLiveResponse = $LiveResponse
            }
            if ($PSBoundParameters.ContainsKey('LiveResponseForServers')) {
                $currentConfig.LiveResponseForServers = $LiveResponseForServers
            }
            if ($PSBoundParameters.ContainsKey('LiveResponseUnsignedScriptExecution')) {
                $currentConfig.AutomatedIrUnsignedScripts = $LiveResponseUnsignedScriptExecution
            }

            $uri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/update_properties?useV2Api=true&useV3Api=true"
            $method = "PATCH"
            $currentConfig = @{"properties" = $currentConfig }
            $body = $currentConfig | ConvertTo-Json -Depth 10

            if ($WhatIfPreference) {
                Write-Host "`nLive Response Update:" -ForegroundColor Cyan
                Write-Host "URI: $uri" -ForegroundColor Yellow
                Write-Host "Method: $method" -ForegroundColor Yellow
                Write-Host "Body:" -ForegroundColor Yellow
                Write-Host $body -ForegroundColor Gray
            }
            if ($PSCmdlet.ShouldProcess("Live Response Configuration", "Update")) {
                try {
                    $null = Invoke-RestMethod -Uri $uri -Method $method -Body $body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    Write-Host "Live Response configuration updated successfully"
                } catch {
                    Write-Error "Failed to update Live Response configuration: $_"
                }
            }
        }

        # Update Preview Features
        if ($hasPreviewFeatures) {
            Write-Verbose "Updating Preview Features configuration"
            
            $uri = "https://security.microsoft.com/apiproxy/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext"
            $method = "POST"
            $body = @{"IsOptIn" = $PreviewFeatures } | ConvertTo-Json -Depth 10

            if ($WhatIfPreference) {
                Write-Host "`nPreview Features Update:" -ForegroundColor Cyan
                Write-Host "URI: $uri" -ForegroundColor Yellow
                Write-Host "Method: $method" -ForegroundColor Yellow
                Write-Host "Body:" -ForegroundColor Yellow
                Write-Host $body -ForegroundColor Gray
            }
            if ($PSCmdlet.ShouldProcess("Preview Features Configuration", "Update")) {
                try {
                    $null = Invoke-RestMethod -Uri $uri -Method $method -Body $body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    Write-Host "Preview Features configuration updated successfully"
                } catch {
                    Write-Error "Failed to update Preview Features configuration: $_"
                }
            }
        }

        # Update Purview Sharing
        if ($hasPurviewSharing) {
            Write-Verbose "Updating Purview Sharing configuration"

            $uri = "https://security.microsoft.com/apiproxy/mtp/wdatpInternalApi/compliance/alertSharing/status/"
            $method = "POST"
            $body = $PurviewSharing.ToString().ToLower()

            if ($PSCmdlet.ShouldProcess("Purview Sharing Configuration", "Update")) {
                if ($WhatIfPreference) {
                    Write-Host "`nPurview Sharing Update:" -ForegroundColor Cyan
                    Write-Host "URI: $uri" -ForegroundColor Yellow
                    Write-Host "Method: $method" -ForegroundColor Yellow
                    Write-Host "Body:" -ForegroundColor Yellow
                    Write-Host $body -ForegroundColor Gray
                } else {
                    try {
                        $null = Invoke-RestMethod -Uri $uri -Method $method -Body $body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        Write-Host "Purview Sharing configuration updated successfully"
                    } catch {
                        Write-Error "Failed to update Purview Sharing configuration: $_"
                    }
                }
            }
        }
    }

    end {
    }
}
