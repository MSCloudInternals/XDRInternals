![](./images/xdrinternals-banner.jpg "XDRInternals")

# XDRInternals

Welcome to XDRInternals, the unofficial PowerShell module to interact with the Microsoft Defender XDR portal. For a short introduction on how to install the module and authenticate to the portal, please watch the video below :)

https://github.com/user-attachments/assets/e5ccd2fa-4af1-4b0f-b1ff-8870cb077a79

## Description

XDRInternals is a PowerShell module that provides direct access to the Microsoft Defender XDR portal APIs. It enables automation and scripting capabilities for managing and querying XDR resources including endpoints, identities, configurations, and advanced hunting queries.

## Disclaimer

This is an unofficial, community-driven project and is not affiliated with, endorsed by, or supported by Microsoft. This module interacts with undocumented APIs that may change without notice.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

USE AT YOUR OWN RISK. The authors and contributors are not responsible for any issues, data loss, or security implications that may arise from using this module.

## Key Features

### Caching Functionality

Many cmdlets in this module implement intelligent caching to improve performance and reduce API calls:

- Cached data is stored in memory with configurable Time-To-Live (TTL) values
- Default cache duration varies by cmdlet (typically 10-30 minutes)
- Use the `-Force` parameter on supported cmdlets to bypass cache and retrieve fresh data
- Cache keys are automatically generated based on query parameters to ensure accurate results

Example:
```powershell
# First call retrieves from API and caches the result
Get-XdrTenantContext

# Second call uses cached data (if within TTL)
Get-XdrTenantContext

# Force fresh retrieval
Get-XdrTenantContext -Force
```

## Available Cmdlets

| Cmdlet | Description |
| --- | --- |
| Connect-XdrByBrowser | Authenticate or connect to Defender XDR |
| Connect-XdrByCredential | Authenticate or connect to Defender XDR |
| Connect-XdrByEstsCookie | Authenticate or connect to Defender XDR |
| Connect-XdrByPhoneSignIn | Authenticate or connect to Defender XDR |
| Connect-XdrBySoftwarePasskey | Authenticate or connect to Defender XDR |
| Connect-XdrBySSO | Authenticate or connect to Defender XDR |
| Connect-XdrByTemporaryAccessPass | Authenticate or connect to Defender XDR |
| Connect-XdrEndpointDeviceLiveResponse | Authenticate or connect to Defender XDR |
| ConvertTo-XdrEncodedAdvancedHuntingQuery | Defender XDR helper command |
| Disconnect-XdrEndpointDeviceLiveResponse | Defender XDR helper command |
| Export-XdrToSentinel | Defender XDR helper command |
| Get-XdrActionsCenterHistory | Retrieve Defender XDR data |
| Get-XdrActionsCenterPending | Retrieve Defender XDR data |
| Get-XdrAdvancedHuntingFunction | Retrieve Defender XDR data |
| Get-XdrAdvancedHuntingTableSchema | Retrieve Defender XDR data |
| Get-XdrAdvancedHuntingUnifiedDetectionRules | Retrieve Defender XDR data |
| Get-XdrAdvancedHuntingUserHistory | Retrieve Defender XDR data |
| Get-XdrAlert | Retrieve Defender XDR data |
| Get-XdrCloudAppsActivityTimeline | Retrieve Cloud Apps activity timeline data |
| Get-XdrCloudAppsApp | Retrieve live-validated Cloud Apps app, OAuth, catalog, service, tag, and file data |
| Get-XdrCloudAppsConfiguration | Retrieve grouped Cloud Apps configuration data |
| Get-XdrCloudAppsDiscovery | Retrieve Cloud Discovery data |
| Get-XdrCloudAppsGovernance | Retrieve Cloud Apps governance and App Governance data |
| Get-XdrCloudAppsPolicy | Retrieve Cloud Apps policies, policy metadata, actions, and limits |
| Get-XdrConfigurationAlertServiceSetting | Retrieve Defender XDR data |
| Get-XdrConfigurationAlertTuning | Retrieve Defender XDR data |
| Get-XdrConfigurationAssetRuleManagement | Retrieve Defender XDR data |
| Get-XdrConfigurationCriticalAssetManagementClassification | Retrieve Defender XDR data |
| Get-XdrConfigurationCriticalAssetManagementClassificationSchema | Retrieve Defender XDR data |
| Get-XdrConfigurationPreviewFeatures | Retrieve Defender XDR data |
| Get-XdrConfigurationServiceAccountClassification | Retrieve Defender XDR data |
| Get-XdrConfigurationUnifiedRBACWorkload | Retrieve Defender XDR data |
| Get-XdrDatalakeDatabase | Retrieve Defender XDR data |
| Get-XdrDatalakeTableSchema | Retrieve Defender XDR data |
| Get-XdrEndpointAdvancedFeatures | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationAdvancedFeatures | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationAuthenticatedTelemetry | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationCustomCollectionRule | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationIntuneConnection | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationLiveResponse | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationPotentiallyUnwantedApplications | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationPreviewFeature | Retrieve Defender XDR data |
| Get-XdrEndpointConfigurationPurviewSharing | Retrieve Defender XDR data |
| Get-XdrEndpointDevice | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceActionResult | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceLiveResponseLibrary | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceLiveResponseLibraryFile | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceModel | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceOsVersionFriendlyName | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceRbacGroup | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceRbacGroupScope | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceTag | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceTimeline | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceTotals | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceVendor | Retrieve Defender XDR data |
| Get-XdrEndpointDeviceWindowsReleaseVersion | Retrieve Defender XDR data |
| Get-XdrEndpointLicenseReport | Retrieve Defender XDR data |
| Get-XdrExposureManagementRecommendations | Retrieve Defender XDR data |
| Get-XdrIdentityAlertThreshold | Retrieve Defender XDR data |
| Get-XdrIdentityConfigurationDirectoryServiceAccount | Retrieve Defender XDR data |
| Get-XdrIdentityConfigurationRemediationActionAccount | Retrieve Defender XDR data |
| Get-XdrIdentityDomainControllerCoverage | Retrieve Defender XDR data |
| Get-XdrIdentityIdentity | Retrieve Defender XDR data |
| Get-XdrIdentityOnboardingStatus | Retrieve Defender XDR data |
| Get-XdrIdentityServiceAccount | Retrieve Defender XDR data |
| Get-XdrIdentityStatistic | Retrieve Defender XDR data |
| Get-XdrIdentityUser | Retrieve Defender XDR data |
| Get-XdrIdentityUserTimeline | Retrieve Defender XDR data |
| Get-XdrIncident | Retrieve Defender XDR data |
| Get-XdrIncidentAssociatedAlert | Retrieve Defender XDR data |
| Get-XdrMtoTenantList | Retrieve Defender XDR data |
| Get-XdrStreamingApiConfiguration | Retrieve Defender XDR data |
| Get-XdrSuppressionRule | Retrieve Defender XDR data |
| Get-XdrTenantContext | Retrieve Defender XDR data |
| Get-XdrTenantWorkloadStatus | Retrieve Defender XDR data |
| Get-XdrThreatAnalyticsOutbreaks | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementAdvisories | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementBaseline | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementCertificates | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementChangeEvents | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementDashboard | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementExtensions | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementProducts | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementRemediationTasks | Retrieve Defender XDR data |
| Get-XdrVulnerabilityManagementVulnerabilities | Retrieve Defender XDR data |
| Get-XdrXspmAttackPath | Retrieve Defender XDR data |
| Get-XdrXspmChokePoint | Retrieve Defender XDR data |
| Get-XdrXspmTopEntryPoint | Retrieve Defender XDR data |
| Get-XdrXspmTopTarget | Retrieve Defender XDR data |
| Invoke-XdrEndpointDeviceAction | Invoke Defender XDR operations |
| Invoke-XdrEndpointDeviceAutomatedInvestigation | Invoke Defender XDR operations |
| Invoke-XdrEndpointDeviceLiveResponseCommand | Invoke Defender XDR operations |
| Invoke-XdrEndpointDevicePolicySync | Invoke Defender XDR operations |
| Invoke-XdrHuntingQueryValidation | Invoke Defender XDR operations |
| Invoke-XdrMtoAdvancedHunting | Invoke Defender XDR operations |
| Invoke-XdrRestMethod | Invoke Defender XDR operations |
| Invoke-XdrXspmHuntingQuery | Invoke Defender XDR operations |
| Merge-XdrIncident | Defender XDR helper command |
| Move-XdrAlertToIncident | Defender XDR helper command |
| New-XdrAdvancedHuntingFunction | Create Defender XDR resources |
| New-XdrConfigurationCriticalAssetManagementClassification | Create Defender XDR resources |
| New-XdrEndpointConfigurationCustomCollectionRule | Create Defender XDR resources |
| New-XdrEndpointDeviceLiveResponseLibraryFile | Create Defender XDR resources |
| New-XdrEndpointDeviceRbacGroup | Create Defender XDR resources |
| New-XdrIdentityConfigurationRemediationActionAccount | Create Defender XDR resources |
| Remove-XdrAdvancedHuntingFunction | Remove Defender XDR resources |
| Remove-XdrConfigurationCriticalAssetManagementClassification | Remove Defender XDR resources |
| Remove-XdrEndpointDeviceLiveResponseLibraryFile | Remove Defender XDR resources |
| Remove-XdrIdentityConfigurationRemediationActionAccount | Remove Defender XDR resources |
| Set-XdrAdvancedHuntingFunction | Update Defender XDR configuration or state |
| Set-XdrCloudAppsDiscoveredApp | Update a discovered app note |
| Set-XdrConfigurationCriticalAssetManagementClassification | Update Defender XDR configuration or state |
| Set-XdrConfigurationPreviewFeatures | Update Defender XDR configuration or state |
| Set-XdrConnectionSettings | Update Defender XDR configuration or state |
| Set-XdrEndpointAdvancedFeatures | Update Defender XDR configuration or state |
| Set-XdrEndpointConfigurationCustomCollectionRule | Update Defender XDR configuration or state |
| Set-XdrEndpointDeviceAssetValue | Update Defender XDR configuration or state |
| Set-XdrEndpointDeviceCriticalityLevel | Update Defender XDR configuration or state |
| Set-XdrEndpointDeviceExclusionState | Update Defender XDR configuration or state |
| Set-XdrEndpointDeviceRbacGroup | Update Defender XDR configuration or state |
| Set-XdrEndpointDeviceTag | Update Defender XDR configuration or state |
| Set-XdrIdentityConfigurationRemediationActionAccount | Update Defender XDR configuration or state |
| Set-XdrSentinelConnection | Update Defender XDR configuration or state |
| Stop-XdrEndpointDeviceAction | Defender XDR helper command |
| Update-XdrConnectionSettings | Defender XDR helper command |

## Installation

### From the PowerShell Gallery

```powershell
# Install the module from the PowerShell Gallery
Install-Module XDRInternals

# Import the module
Import-Module XDRInternals
```

### From GitHub

```powershell
# Clone the repository
git clone https://github.com/MSCloudInternals/XDRInternals.git

# Import the module
Import-Module .\XDRInternals\XDRInternals.psd1
```

## Usage

### Connect to Microsoft Defender XDR

```powershell
# Connect to Microsoft Defender XDR using ESTSAUTH cookie
Connect-XdrByEstsCookie
```

```powershell
# Connect to Microsoft Defender XDR using an interactive browser sign-in
# Uses a dedicated secondary browser profile by default
# Useful for passkey/FIDO2 or Temporary Access Pass flows
Connect-XdrByBrowser -Username 'admin@contoso.com'
```

`Connect-XdrByBrowser` uses Chromium-compatible browser automation and cookie capture. On macOS, Microsoft Edge, Google Chrome, Brave, and Chromium are the supported browsers today. Safari is not currently supported by this flow.

On macOS and Linux, `Connect-XdrByBrowser` is still an interactive flow. Complete any prompts until Defender XDR finishes loading so the cmdlet can capture the final session cookies.

```powershell
# Connect to Microsoft Defender XDR using Windows/browser single sign-on
Connect-XdrBySSO
```

`Connect-XdrBySSO` is still a Windows-first flow, but it can also reuse existing Chromium browser session state on macOS and Linux when a supported browser profile already has the required sign-in state.

`Connect-XdrBySSO -Visible` is useful for validating or troubleshooting the flow because it lets you confirm the browser reached Defender XDR before the cmdlet captures the session cookies.

```powershell
# Connect to Microsoft Defender XDR using a Temporary Access Pass
$tap = ConvertTo-SecureString '+&YZuead' -AsPlainText -Force
Connect-XdrByTemporaryAccessPass -Username 'admin@contoso.com' -TemporaryAccessPass $tap -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'
```

```powershell
# Connect to Microsoft Defender XDR using Microsoft Authenticator phone sign-in
Connect-XdrByPhoneSignIn -Username 'admin@contoso.com'
```

Phone sign-in starts the Defender portal flow directly and shows the number returned by Entra ID when the service exposes it through the resume URL. Some tenants or accounts currently land in a `login.microsoft.com` passkey/native-bridge interstitial instead of inline `PhoneAppNotification`; in that case the cmdlet fails fast and `Connect-XdrByBrowser` remains the supported fallback.

Or alternatively:

```powershell
# Configure connection settings with SCC auth (XSRF token is obtained automatically)
Set-XdrConnectionSettings -SccAuth $sccauth
```

### Examples

```powershell
# Get tenant context
Get-XdrTenantContext

# Retrieve incidents
Get-XdrIncident -Status Active

# Get alerts associated with an incident
Get-XdrIncidentAssociatedAlert -IncidentId 12345

# Retrieve endpoint devices
Get-XdrEndpointDevice -PageSize 50

# Get all identities with automatic pagination
Get-XdrIdentityIdentity -All

# Get custom collection rules
Get-XdrEndpointConfigurationCustomCollectionRule

# Export custom collection rules to YAML
Get-XdrEndpointConfigurationCustomCollectionRule -Output YAML | Out-File "rules.yaml"

# Create a new custom collection rule from YAML
New-XdrEndpointConfigurationCustomCollectionRule -FilePath "C:\Rules\FileMonitoring.yaml"

# Update an existing rule from YAML
Set-XdrEndpointConfigurationCustomCollectionRule -FilePath "C:\Rules\UpdatedRule.yaml" -RuleId "guid"

# Update a rule using PSObject
$rule = Get-XdrEndpointConfigurationCustomCollectionRule | Where-Object { $_.ruleName -eq "My Rule" }
$rule.isEnabled = $false
Set-XdrEndpointConfigurationCustomCollectionRule -InputObject $rule

# Move alerts to an existing incident
Move-XdrAlertToIncident -AlertIds "alert1", "alert2" -TargetIncidentId 12345

# Move alerts to a new incident
Move-XdrAlertToIncident -AlertIds "alert1"

# Get attack paths from XSPM
Get-XdrXspmAttackPath -Top 50

# Retrieve all attack paths with automatic pagination
Get-XdrXspmAttackPath -All

# Get choke points (critical nodes in multiple attack paths)
Get-XdrXspmChokePoint

# Get top entry points and targets
Get-XdrXspmTopEntryPoint
Get-XdrXspmTopTarget

# Execute custom XSPM hunting queries
Invoke-XdrXspmHuntingQuery -Query "AttackPathsV2 | where RiskLevel == 'High'" -ScenarioName "CustomQuery"
```

#### Cloud Apps

```powershell
# Get recent Cloud Apps activity with admin-friendly output
Get-XdrCloudAppsActivityTimeline -LastNDays 1

# Push harder for time-sensitive incident response while preserving completeness checks
Get-XdrCloudAppsActivityTimeline -LastNDays 7 -Aggressive -ExportPath ".\cloud-apps-activity.ndjson" -ExportFormat Ndjson

# Explore grouped app and discovery surfaces
Get-XdrCloudAppsApp -Type Discovered -Limit 50
Get-XdrCloudAppsDiscovery -ListStreams
Get-XdrCloudAppsConfiguration -Type DiscoveryStream

# Review governance and policy data
Get-XdrCloudAppsGovernance
Get-XdrCloudAppsPolicy -Type OAuth -Metadata
```

#### Live Response

```powershell
# Open an interactive Live Response shell
Connect-XdrEndpointDeviceLiveResponse -DeviceId $deviceId

# Create one or more non-interactive sessions for automation
$sessions = Get-XdrEndpointDevice -MachineSearchPrefix sml |
	Select-Object -First 2 |
	Connect-XdrEndpointDeviceLiveResponse -NonInteractive

# Run a command and get PowerShell-native row output for common table responses
$sessions |
	Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -ExpandTableOutput |
	Select-Object DeviceName, Name, Pid, MemoryKB

# Keep the original API wrapper object instead of expanding table rows
$sessions[0] |
	Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'drivers -name cdd.dll' -RawCommandResult

# Disconnect sessions through the pipeline
$sessions | Disconnect-XdrEndpointDeviceLiveResponse
```

Notes:

- `Connect-XdrEndpointDeviceLiveResponse -NonInteractive` accepts pipeline input from `Get-XdrEndpointDevice` and supports `-NoStatusTable` when connecting to multiple devices.
- `Invoke-XdrEndpointDeviceLiveResponseCommand` expands common table outputs such as `processes`, `services`, `drivers`, `connections`, `dir`, and `persistence` into typed row objects by default. Use `-RawCommandResult` to keep the original API response shape, or `-IncludeCommandResult` together with `-ExpandTableOutput` to emit both forms.
- `Disconnect-XdrEndpointDeviceLiveResponse` accepts session objects or raw session IDs from the pipeline.

## License

See LICENSE file for details.
