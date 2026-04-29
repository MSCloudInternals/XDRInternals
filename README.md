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

| Cmdlet                                                          | Description                                                         |
| --------------------------------------------------------------- | ------------------------------------------------------------------- |
| Connect-XdrByBrowser                                            | Authenticates to Microsoft Defender XDR using an interactive browser sign-in. |
| Connect-XdrByCredential                                         | Authenticates to Microsoft Defender XDR using username, password, and optional TOTP MFA. |
| Connect-XdrByEstsCookie                                         | Establishes an authenticated session to the Microsoft Defender XDR portal. |
| Connect-XdrByPhoneSignIn                                        | Authenticates to Microsoft Defender XDR using Microsoft Authenticator phone sign-in. |
| Connect-XdrBySoftwarePasskey                                    | Authenticates to Microsoft Defender XDR using a software passkey. |
| Connect-XdrBySSO                                                | Authenticates to Microsoft Defender XDR using browser-based single sign-on. |
| Connect-XdrByTemporaryAccessPass                                | Authenticates to Microsoft Defender XDR using a Temporary Access Pass (TAP). |
| Connect-XdrEndpointDeviceLiveResponse                           | Opens a Live Response session to an endpoint device in Microsoft Defender XDR. |
| ConvertTo-XdrEncodedAdvancedHuntingQuery                        | Encodes an Advanced Hunting query for use in Microsoft Defender XDR. |
| Disconnect-XdrEndpointDeviceLiveResponse                        | Closes an active Live Response session in Microsoft Defender XDR. |
| Export-XdrToSentinel                                            | Exports XDR data to a Microsoft Sentinel (Log Analytics) custom table. |
| Get-XdrActionsCenterHistory                                     | Retrieves historical actions from the Microsoft Defender XDR Action Center. |
| Get-XdrActionsCenterPending                                     | Retrieves pending actions from the Microsoft Defender XDR Action Center. |
| Get-XdrAdvancedHuntingFunction                                  | Retrieves Advanced Hunting functions from Microsoft Defender XDR. |
| Get-XdrAdvancedHuntingTableSchema                               | Retrieves the Advanced Hunting table schema from Microsoft Defender XDR. |
| Get-XdrAdvancedHuntingUnifiedDetectionRules                     | Retrieves the Unified Detection Rules from Advanced Hunting. |
| Get-XdrAdvancedHuntingUserHistory                               | Retrieves Advanced Hunting user history from Microsoft Defender XDR. |
| Get-XdrAlert                                                    | Retrieves alerts from Microsoft Defender XDR. |
| Get-XdrCloudAppsGeneralSetting                                  | Retrieves general settings from Microsoft Defender for Cloud Apps (Cloud Apps). |
| Get-XdrConfigurationAlertServiceSetting                         | Retrieves alert service settings from Microsoft Defender XDR. |
| Get-XdrConfigurationAlertTuning                                 | Retrieves alert tuning configuration from Microsoft Defender XDR. |
| Get-XdrConfigurationAssetRuleManagement                         | Retrieves asset rule management configuration from Microsoft Defender XDR. |
| Get-XdrConfigurationCriticalAssetManagementClassification       | Retrieves critical asset management classification rules from Microsoft Defender XDR. |
| Get-XdrConfigurationCriticalAssetManagementClassificationSchema | Retrieves the schema for Critical Asset Management rules from Microsoft Defender XDR. |
| Get-XdrConfigurationPreviewFeatures                             | Retrieves the configuration for Defender XDR Preview features. |
| Get-XdrConfigurationServiceAccountClassification                | Retrieves service account classification rules from Microsoft Defender XDR. |
| Get-XdrConfigurationUnifiedRBACWorkload                         | Retrieves Unified RBAC workload configuration from Microsoft Defender XDR. |
| Get-XdrDatalakeDatabase                                         | Retrieves databases from Microsoft Defender XDR datalake. |
| Get-XdrDatalakeTableSchema                                      | Retrieves database entities schema from Microsoft Defender XDR datalake. |
| Get-XdrEndpointAdvancedFeatures                                 | Retrieves comprehensive advanced features configuration for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationAdvancedFeatures                    | Retrieves the advanced features configuration settings for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationAuthenticatedTelemetry              | Retrieves the Authenticated Telemetry status for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationCustomCollectionRule                | Retrieves custom collection rules for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationIntuneConnection                    | Retrieves the Intune connection status for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationLiveResponse                        | Retrieves the Live Response configuration settings for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationPotentiallyUnwantedApplications     | Retrieves the potentially unwanted applications (PUA) configuration for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationPreviewFeature                      | Retrieves the preview features configuration for Microsoft Defender for Endpoint. |
| Get-XdrEndpointConfigurationPurviewSharing                      | Retrieves the Purview alert sharing configuration for Microsoft Defender for Endpoint. |
| Get-XdrEndpointDevice                                           | Retrieves endpoint devices from Microsoft Defender XDR. |
| Get-XdrEndpointDeviceActionResult                               | Gets device action results and download URIs from Microsoft Defender XDR. |
| Get-XdrEndpointDeviceLiveResponseLibrary                        | Retrieves the Live Response library files from Microsoft Defender XDR. |
| Get-XdrEndpointDeviceLiveResponseLibraryFile                    | Downloads a script file from the Live Response library. |
| Get-XdrEndpointDeviceModel                                      | Retrieves all device models from Microsoft Defender for Endpoint. |
| Get-XdrEndpointDeviceOsVersionFriendlyName                      | Retrieves all OS version friendly names from Microsoft Defender for Endpoint. |
| Get-XdrEndpointDeviceRbacGroup                                  | Retrieves device groups for Defender for Endpoint. |
| Get-XdrEndpointDeviceRbacGroupScope                             | Retrieves all RBAC groups from Microsoft Defender for Endpoint. |
| Get-XdrEndpointDeviceTag                                        | Retrieves all device tags from Microsoft Defender for Endpoint. |
| Get-XdrEndpointDeviceTimeline                                   | Retrieves the timeline of events for a specific device from Microsoft Defender XDR. |
| Get-XdrEndpointDeviceTotals                                     | Retrieves the device totals from Microsoft Defender XDR. |
| Get-XdrEndpointDeviceVendor                                     | Retrieves all device vendors from Microsoft Defender for Endpoint. |
| Get-XdrEndpointDeviceWindowsReleaseVersion                      | Retrieves all Windows release versions from Microsoft Defender for Endpoint. |
| Get-XdrEndpointLicenseReport                                    | Retrieves license usage report for Microsoft Defender for Endpoint. |
| Get-XdrExposureManagementRecommendations                        | Retrieves recommendations from Exposure Management. |
| Get-XdrIdentityAlertThreshold                                   | Retrieves alert threshold configuration for Microsoft Defender for Identity. |
| Get-XdrIdentityConfigurationDirectoryServiceAccount             | Retrieves directory service accounts for Microsoft Defender for Identity. |
| Get-XdrIdentityConfigurationRemediationActionAccount            | Retrieves the remediation action account configuration for Microsoft Defender for Identity. |
| Get-XdrIdentityDomainControllerCoverage                         | Retrieves domain controller coverage from Microsoft Defender for Identity. |
| Get-XdrIdentityIdentity                                         | Retrieves identities from Microsoft Defender for Identity. |
| Get-XdrIdentityOnboardingStatus                                 | Retrieves the onboarding status of Microsoft Defender for Identity. |
| Get-XdrIdentityServiceAccount                                   | Retrieves service accounts from Microsoft Defender for Identity. |
| Get-XdrIdentityStatistic                                        | Retrieves aggregated identity statistics from Microsoft Defender for Identity. |
| Get-XdrIdentityUser                                             | Retrieves detailed user identity information from Microsoft Defender for Identity. |
| Get-XdrIdentityUserTimeline                                     | Retrieves the timeline of events for a specific user from Microsoft Defender for Identity. |
| Get-XdrIncident                                                 | Retrieves incidents from Microsoft Defender XDR. |
| Get-XdrIncidentAssociatedAlert                                  | Retrieves alerts associated with a specific incident from Microsoft Defender XDR. |
| Get-XdrMtoTenantList                                            | Retrieves the list of accessible tenants from Microsoft Defender XDR. |
| Get-XdrStreamingApiConfiguration                                | Retrieves Streaming API configuration from Microsoft Defender XDR. |
| Get-XdrSuppressionRule                                          | Retrieves alert suppression rules from Microsoft Defender XDR. |
| Get-XdrTenantContext                                            | Retrieves the tenant context information from Microsoft Defender XDR. |
| Get-XdrTenantWorkloadStatus                                     | Retrieves and evaluates the workload status from Microsoft Defender XDR tenant context. |
| Get-XdrThreatAnalyticsOutbreaks                                 | Retrieves threat analytics outbreaks from Microsoft Defender XDR. |
| Get-XdrVulnerabilityManagementAdvisories                        | Retrieves security advisories from Vulnerability Management. |
| Get-XdrVulnerabilityManagementBaseline                          | Retrieves security baseline assessment data from Microsoft Defender XDR. |
| Get-XdrVulnerabilityManagementCertificates                      | Retrieves certificates from Vulnerability Management. |
| Get-XdrVulnerabilityManagementChangeEvents                      | Retrieves change events from Vulnerability Management. |
| Get-XdrVulnerabilityManagementDashboard                         | Retrieves Microsoft Defender Vulnerability Management dashboard analytics data. |
| Get-XdrVulnerabilityManagementExtensions                        | Retrieves browser extensions from Vulnerability Management. |
| Get-XdrVulnerabilityManagementProducts                          | Retrieves products from Vulnerability Management. |
| Get-XdrVulnerabilityManagementRemediationTasks                  | Retrieves remediation tasks from Vulnerability Management. |
| Get-XdrVulnerabilityManagementVulnerabilities                   | Retrieves vulnerabilities from Vulnerability Management. |
| Get-XdrXspmAttackPath                                           | Retrieves attack path data from Microsoft Defender XDR XSPM. |
| Get-XdrXspmChokePoint                                           | Retrieves choke point data from Microsoft Defender XDR XSPM. |
| Get-XdrXspmTopEntryPoint                                        | Retrieves top entry points from Microsoft Defender XDR XSPM attack paths. |
| Get-XdrXspmTopTarget                                            | Retrieves top targets from Microsoft Defender XDR XSPM attack paths. |
| Invoke-XdrEndpointDeviceAction                                  | Invokes response actions on an endpoint device in Microsoft Defender XDR. |
| Invoke-XdrEndpointDeviceAutomatedInvestigation                  | Starts an automated investigation on an endpoint device in Microsoft Defender XDR. |
| Invoke-XdrEndpointDeviceLiveResponseCommand                     | Sends a command to an active Live Response session in Microsoft Defender XDR. |
| Invoke-XdrEndpointDevicePolicySync                              | Forces a policy sync on an endpoint device in Microsoft Defender XDR. |
| Invoke-XdrHuntingQueryValidation                                | Validates an Advanced Hunting query for custom detection rules in Microsoft Defender XDR. |
| Invoke-XdrMtoAdvancedHunting                                    | Executes an Advanced Hunting query across multiple tenants in MTO (Multi-Tenant Organization). |
| Invoke-XdrRestMethod                                            | Invokes a REST API call to Microsoft Defender XDR with authenticated session. |
| Invoke-XdrXspmHuntingQuery                                      | Executes a hunting query against the Microsoft Defender XDR XSPM attack surface API. |
| Merge-XdrIncident                                               | Merges multiple incidents into a single incident in Microsoft Defender XDR. |
| Move-XdrAlertToIncident                                         | Moves alerts to a specific incident or creates a new one. |
| New-XdrAdvancedHuntingFunction                                  | Creates a new Advanced Hunting function in Microsoft Defender XDR. |
| New-XdrConfigurationCriticalAssetManagementClassification       | Creates a new Critical Asset Management classification rule in Microsoft Defender XDR. |
| New-XdrEndpointConfigurationCustomCollectionRule                | Creates a new custom collection rule for Microsoft Defender for Endpoint from a YAML file. |
| New-XdrEndpointDeviceLiveResponseLibraryFile                    | Uploads a script file to the Live Response library. |
| New-XdrEndpointDeviceRbacGroup                                  | Creates a device group in Defender for Endpoint used for RBAC and policies. |
| New-XdrIdentityConfigurationRemediationActionAccount            | Registers a new remediation action account for Microsoft Defender for Identity. |
| Remove-XdrAdvancedHuntingFunction                               | Removes an Advanced Hunting function from Microsoft Defender XDR. |
| Remove-XdrConfigurationCriticalAssetManagementClassification    | Removes a Critical Asset Management classification rule from Microsoft Defender XDR. |
| Remove-XdrEndpointDeviceLiveResponseLibraryFile                 | Deletes a file from the Live Response library. |
| Remove-XdrIdentityConfigurationRemediationActionAccount         | Removes a remediation action account from Microsoft Defender for Identity. |
| Set-XdrAdvancedHuntingFunction                                  | Updates an existing Advanced Hunting function in Microsoft Defender XDR. |
| Set-XdrConfigurationCriticalAssetManagementClassification       | Updates critical asset management classification rule metadata in Microsoft Defender XDR. |
| Set-XdrConfigurationPreviewFeatures                             | Sets the configuration for Defender XDR Preview features. |
| Set-XdrConnectionSettings                                       | Creates XDR connection settings using authentication cookies. |
| Set-XdrEndpointAdvancedFeatures                                 | Configures advanced features settings for Microsoft Defender for Endpoint. |
| Set-XdrEndpointConfigurationCustomCollectionRule                | Updates an existing custom collection rule for Microsoft Defender for Endpoint. |
| Set-XdrEndpointDeviceAssetValue                                 | Sets the asset value on endpoint devices in Microsoft Defender XDR. |
| Set-XdrEndpointDeviceCriticalityLevel                           | Sets the criticality level on endpoint devices in Microsoft Defender XDR. |
| Set-XdrEndpointDeviceExclusionState                             | Sets the exclusion state on endpoint devices in Microsoft Defender XDR. |
| Set-XdrEndpointDeviceRbacGroup                                  | Updates Defender for Endpoint device groups. |
| Set-XdrEndpointDeviceTag                                        | Sets, adds, or removes user-defined tags on endpoint devices in Microsoft Defender XDR. |
| Set-XdrIdentityConfigurationRemediationActionAccount            | Configures the remediation action account type for Microsoft Defender for Identity. |
| Set-XdrSentinelConnection                                       | Configures the Sentinel (Log Analytics) workspace connection for data export. |
| Stop-XdrEndpointDeviceAction                                    | Cancels a pending device action in Microsoft Defender XDR. |
| Update-XdrConnectionSettings                                    | Updates XDR connection session cookies and authentication tokens. |
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
