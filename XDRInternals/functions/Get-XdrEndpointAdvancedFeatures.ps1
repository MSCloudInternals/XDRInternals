function Get-XdrEndpointAdvancedFeatures {
    <#
    .SYNOPSIS
        Retrieves comprehensive advanced features configuration for Microsoft Defender for Endpoint.

    .DESCRIPTION
        Gets a consolidated view of all advanced features settings from Microsoft Defender for Endpoint,
        including EDR in block mode, device discovery, integrations, and various security features.
        This is a wrapper function that combines multiple configuration endpoints into a single, formatted output.

    .EXAMPLE
        Get-XdrEndpointAdvancedFeatures
        Retrieves all advanced features configuration settings with detailed descriptions.

    .EXAMPLE
        Get-XdrEndpointAdvancedFeatures | Where-Object { $_.Value -eq $true }
        Retrieves only the advanced features that are currently enabled.

    .OUTPUTS
        PSCustomObject[]
        Returns an array of custom objects with Name, Value, and Description properties for each advanced feature.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Advanced Features is plural by design')]
    [CmdletBinding()]
    param (

    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # This is a wrapper function for multiple advanced features configurations
        Write-Verbose "Retrieving XDR Advanced Features configuration"
        $BasicAdvancedFeatures = Get-XdrEndpointConfigurationAdvancedFeatures
        if ( $BasicAdvancedFeatures.LicenseEnabled ) {
            $IntuneConnection = Get-XdrEndpointConfigurationIntuneConnection
            if ($IntuneConnection -eq 1) {
                $IntuneConnection = @{ IntuneConnectionStatus = $true }
            }
            else {
                $IntuneConnection = @{ IntuneConnectionStatus = $false }
            }
        }
        else {
            $IntuneConnection = @{ IntuneConnectionStatus = "Unlicensed" }
        }
        $LiveResponse = Get-XdrEndpointConfigurationLiveResponse
        $PotentiallyUnwantedApplications = Get-XdrEndpointConfigurationPotentiallyUnwantedApplications
        $PreviewFeatures = Get-XdrEndpointConfigurationPreviewFeature
        $PurviewSharing = Get-XdrEndpointConfigurationPurviewSharing
        $AuthenticatedTelemetry = Get-XdrEndpointConfigurationAuthenticatedTelemetry
        <# Overwrite specific properties with more detailed configurations
        if (-not $BasicAdvancedFeatures.AatpWorkspaceExists) {
            $BasicAdvancedFeatures.AatpIntegrationEnabled = "Feature has not been fully enabled in tenant"
        }
        #>
        $AdvancedSettings = @(
            [PSCustomObject]@{
                Name        = "EnableEDRInBlockMode"
                Value       = $BasicAdvancedFeatures.EnableWdavPassiveModeRemediation
                Description = "When turned on, Microsoft Defender for Endpoint leverages behavioral blocking and containment capabilities by blocking malicious artifacts or behaviors observed through post-breach endpoint detection and response (EDR) capabilities. This feature does not change how Microsoft Defender for Endpoint performs detection, alert generation, and incident correlation. To get the best protection, make sure to apply security baselines in Intune."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "EnableMicrosoftDefenderAntivirusInAuditMode"
                Value       = $BasicAdvancedFeatures.EnableWdavAuditMode
                Description = "In audit mode, Microsoft Defender Antivirus performs real-time detections without remediation  actions, such as quarantine or blocking. Detections are displayed in alerts, incidents, and reports. Microsoft Defender Antivirus can run alongside another antivirus solution."
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "DeviceDiscovery"
                Value       = ($BasicAdvancedFeatures.MagellanOptOut -eq $false) # Changed to reflect that opt-out = false means the feature is enabled
                Description  = "Device discovery improves your visibility over all the devices in your network so you can take action to protect them. Discovered devices appear in the device list."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "HidePotentialDuplicateDeviceRecords"
                Value       = $BasicAdvancedFeatures.HidePotentialDuplications
                Description = "When activated, this heuristic might hide some discovered devices in certain cases. You can always come back here and choose to view all devices."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "AllowOrBlockFile"
                Value       = $BasicAdvancedFeatures.BlockListEnabled
                Description = "Make sure that Windows Defender Antivirus is turned on and the cloud-based protection feature is enabled in your organization to use the allow or block file feature."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "SkypeForBusinessIntegration"
                Value       = $BasicAdvancedFeatures.SkypeIntegrationEnabled
                Description = "Enables 1-click communication with users."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "ShowUserDetails"
                Value       = $BasicAdvancedFeatures.ShowUserAadProfile
                Description = "Show user details"
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "MicrosoftDefenderForIdentityIntegration"
                Value       = $BasicAdvancedFeatures.AatpIntegrationEnabled
                Description = "Retrieves enriched user and device data from Microsoft Defender for Identity and forwards Microsoft Defender for Endpoint signals, resulting in better visibility, additional detections, and efficient investigations across both services. Forwarded data is stored and processed in the same location as your MDI data."
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "AutomaticallyResolveAlerts"
                Value       = $BasicAdvancedFeatures.AutoResolveInvestigatedAlerts
                Description = "Resolves an alert if Automated investigation finds no threats or has successfully remediated all malicious artifacts."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "MicrosoftDefenderForCloudApps"
                Value       = $BasicAdvancedFeatures.EnableMcasIntegration
                Description = "Forwards Microsoft Defender for Endpoint signals to Defender for Cloud Apps, giving administrators deeper visibility into both sanctioned cloud apps and shadow IT. It also gives them the ability to block unauthorized applications when the custom network indicators setting is turned on. Forwarded data is stored and processed in the same location as your Cloud App Security data."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "AzureInformationProtection"
                Value       = $BasicAdvancedFeatures.EnableAipIntegration
                Description = "Forwards signals to Azure Information Protection, giving data owners and administrators visibility into protected data on onboarded devices and device risk ratings."
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "EndpointAttackNotificationsApproved"
                Value       = $BasicAdvancedFeatures.BilbaoApproved
                Description = "Unknown"
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "EndpointAttackNotificationsEnabled"
                Value       = $BasicAdvancedFeatures.BilbaoEnabled
                Description = "Unknown"
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "TamperProtection"
                Value       = $BasicAdvancedFeatures.EnableWdavAntiTampering
                Description = "With tamper protection, malicious apps are prevented from turning off security features like virus & threat protection, behavior monitoring, cloud-delivered protection, and more."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "CustomNetworkIndicators"
                Value       = $BasicAdvancedFeatures.AllowWdavNetworkBlock
                Description = "Configures devices to allow or block connections to IP addresses, domains, or URLs in your custom indicator lists"
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "M365SecureScoreIntegrationEnabled"
                Value       = $BasicAdvancedFeatures.M365SecureScoreIntegrationEnabled
                Description = ""
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "WebContentFiltering"
                Value       = $BasicAdvancedFeatures.WebCategoriesEnabled
                Description = "Block access to websites containing unwanted content and track web activity across all domains."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "MicrosoftEndpointDLP"
                Value       = $BasicAdvancedFeatures.EnableEndpointDlp
                Description = "Enable Endpoint DLP solution on devices running Microsoft Defender for Endpoint."
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "DownloadQuarantinedFiles"
                Value       = $BasicAdvancedFeatures.EnableQuarantinedFileDownload
                Description = "Backup quarantined files in a secure and compliant location so they can be downloaded directly from quarantine."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "RestrictCorrelationToWithinScopedDeviceGroups"
                Value       = $BasicAdvancedFeatures.IsolateIncidentsWithDifferentDeviceGroups
                Description = "When this setting is turned on, alerts are correlated into separate incidents based on their scoped device group."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "ExcludeDevices"
                Value       = $BasicAdvancedFeatures.EnableExcludedDevices
                Description = "Allows the ability to exclude devices from vulnerability management pages and reports."
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "ActiveIncidentResponse"
                Value       = $BasicAdvancedFeatures.DartDataCollection
                Description = "Enable Microsoft IR team (DART) to perform advanced investigation and Incident Response in a large scale"
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "AggregatedReporting"
                Value       = $BasicAdvancedFeatures.EnableAggregatedReporting
                Description = "You can turn on aggregated reporting to view summaries of repeating events that might normally be filtered out due to similarity or low information value."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "IsolationExclusionRules"
                Value       = $BasicAdvancedFeatures.IsolationExclusionOptIn
                Description = "Define specific IP addresses, process paths, or services that remain accessible when a device is isolated, enabling uninterrupted investigations while maintaining device protection."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "DefaultToStreamlinedConnectivityWhenOnboardingDevicesInDefenderPortal"
                Value       = $BasicAdvancedFeatures.UseSimplifiedConnectivity
                Description = "Default to streamlined connectivity when onboarding devices in Defender portal"
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "ApplyStreamlinedConnectivitySettingsToDevicesManagedByIntuneAndDefenderForCloud"
                Value       = $BasicAdvancedFeatures.UseSimplifiedConnectivityViaApi
                Description = "Default to streamlined connectivity when onboarding devices in Intune and Defender for Cloud"
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "MicrosoftIntuneConnection"
                Value       = $IntuneConnection.IntuneConnectionStatus
                Description = "Connects to Microsoft Intune to enable sharing of device information and enhanced policy enforcement."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "PreviewFeatures"
                Value       = $PreviewFeatures.IsOptIn
                Description = "Allow access to preview features. Turn on to be among the first to try upcoming features."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "PurviewSharing"
                Value       = $PurviewSharing
                Description = "Forwards endpoint security alerts and their triage status to Microsoft Compliance Center, allowing you to enhance your organization's data governance and compliance capabilities by leveraging Purview's alert management features."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "LiveResponse"
                Value       = $LiveResponse.AutomatedIrLiveResponse
                Description = "Allows users with appropriate RBAC permissions to investigate devices that they are authorized to access, using a remote shell connection."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "LiveResponseForServers"
                Value       = $LiveResponse.LiveResponseForServers
                Description = "Allows users with Live Response privileges to connect remotely to servers (Windows Server or Linux devices) that they are authorized to access."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "LiveResponseUnsignedScriptExecution"
                Value       = $LiveResponse.AutomatedIrUnsignedScripts
                Description = "Enables using unsigned PowerShell scripts in Live Response."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "AlwaysRemediatePUA"
                Value       = $PotentiallyUnwantedApplications.AutomatedIrPuaAsSuspicious
                Description = "When turned on, potentially unwanted applications (PUA) are remediated on all devices in your tenant."
                ConfigurableInPortal = $true
            }
            [PSCustomObject]@{
                Name        = "EnableAutomaticAttackDisruption"
                Value       = $PotentiallyUnwantedApplications.IsAutomatedIrContainDeviceEnabled
                Description = "Microsoft Defender XDR correlates millions of individual signals to identify active ransomware campaigns or other sophisticated attacks in the environment with high confidence. While an attack is in progress, Defender XDR disrupts the attack by automatically containing compromised assets that the attacker is using through automatic attack disruption."
                ConfigurableInPortal = $false
            }
            [PSCustomObject]@{
                Name        = "AuthenticatedTelemetry"
                Value       = $AuthenticatedTelemetry
                Description = "Keep authenticated telemetry turned on to prevent spoofing telemetry into your dashboard."
                ConfigurableInPortal = $true
            }
        )
        # Remove unlicensed features
        if (-not $BasicAdvancedFeatures.LicenseEnabled) {
            $AdvancedSettings = $AdvancedSettings | Where-Object {
                $_.Name -notin @("SkypeForBusinessIntegration", "ShowUserDetails", "MicrosoftIntuneConnection")
            }
        }
        return $AdvancedSettings
    }

    end {
    }
}