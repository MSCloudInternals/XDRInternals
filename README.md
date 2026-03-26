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
| Connect-XdrByEstsCookie                                         | Authenticate to Microsoft Defender XDR using ESTS cookie            |
| Connect-XdrEndpointDeviceLiveResponse                           | Start interactive or non-interactive Live Response sessions         |
| Connect-XdrBySoftwarePasskey                                    | Authenticate to Microsoft Defender XDR using a software FIDO2 passkey (local or Azure Key Vault) |
| ConvertTo-XdrEncodedAdvancedHuntingQuery                        | Encode Advanced Hunting queries for URL/API usage                   |
| Disconnect-XdrEndpointDeviceLiveResponse                        | Close one or more active Live Response sessions                     |
| Get-XdrActionsCenterHistory                                     | Retrieve historical actions from the Action Center                  |
| Get-XdrActionsCenterPending                                     | Retrieve pending actions from the Action Center                     |
| Get-XdrAdvancedHuntingFunction                                  | Get saved Advanced Hunting functions                                |
| Get-XdrAdvancedHuntingTableSchema                               | Get the schema for Advanced Hunting tables                          |
| Get-XdrAdvancedHuntingUnifiedDetectionRules                     | Get unified detection rules from Advanced Hunting                   |
| Get-XdrAdvancedHuntingUserHistory                               | Retrieve user's Advanced Hunting query history                      |
| Get-XdrAlert                                                    | Retrieve alerts with filtering and pagination                       |
| Get-XdrCloudAppsGeneralSetting                                  | Get Cloud Apps general settings                                     |
| Get-XdrConfigurationAlertServiceSetting                         | Get alert service configuration settings                            |
| Get-XdrConfigurationAlertTuning                                 | Retrieve alert tuning and suppression rules                         |
| Get-XdrConfigurationAssetRuleManagement                         | Get asset rule management configuration                             |
| Get-XdrConfigurationCriticalAssetManagement                     | Retrieve critical asset management settings                         |
| Get-XdrConfigurationCriticalAssetManagementClassification       | Retrieve critical asset management classification rules             |
| Get-XdrConfigurationCriticalAssetManagementClassificationSchema | Get available properties for classification rules                   |
| Get-XdrConfigurationPreviewFeatures                             | Get and manage XDR preview features                                 |
| Get-XdrConfigurationServiceAccountClassification                | Get service account classification configuration                    |
| Get-XdrConfigurationUnifiedRBACWorkload                         | Retrieve Unified RBAC workload configuration                        |
| Get-XdrDatalakeDatabase                                         | Get available datalake databases                                    |
| Get-XdrDatalakeTableSchema                                      | Retrieve schema for datalake tables                                 |
| Get-XdrEndpointAdvancedFeatures                                 | Get endpoint advanced features settings                             |
| Get-XdrEndpointConfigurationAdvancedFeatures                    | Retrieve endpoint advanced features configuration                   |
| Get-XdrEndpointConfigurationAuthenticatedTelemetry              | Get authenticated telemetry configuration                           |
| Get-XdrEndpointConfigurationCustomCollectionRule                | Get custom collection rules for MDE                                 |
| Get-XdrEndpointConfigurationIntuneConnection                    | Retrieve Intune connection configuration                            |
| Get-XdrEndpointConfigurationLiveResponse                        | Get Live Response configuration settings                            |
| Get-XdrEndpointConfigurationPotentiallyUnwantedApplications     | Retrieve PUA configuration                                          |
| Get-XdrEndpointConfigurationPreviewFeature                      | Get preview feature configuration                                   |
| Get-XdrEndpointConfigurationPurviewSharing                      | Retrieve Purview data sharing configuration                         |
| Get-XdrEndpointDevice                                           | Get endpoint devices with filtering and pagination                  |
| Get-XdrEndpointDeviceActionResult                               | Get device action results, status, and download URIs                |
| Get-XdrEndpointDeviceModel                                      | Retrieve device models                                              |
| Get-XdrEndpointDeviceOsVersionFriendlyName                      | Get friendly names for OS versions                                  |
| Get-XdrEndpointDeviceLiveResponseLibrary                        | List files in the Live Response library                             |
| Get-XdrEndpointDeviceLiveResponseLibraryFile                    | Download a script file from the Live Response library               |
| Get-XdrEndpointDeviceRbacGroup                                  | Retrieve RBAC groups for devices                                    |
| Get-XdrEndpointDeviceRbacGroupScope                             | Retrieve RBAC groups scope for devices                              |
| Get-XdrEndpointDeviceTag                                        | Get device tags                                                     |
| Get-XdrEndpointDeviceTimeline                                   | Retrieve timeline events for a specific device                      |
| Get-XdrEndpointDeviceTotals                                     | Get total counts of endpoint devices                                |
| Get-XdrEndpointDeviceVendor                                     | Retrieve device vendor information                                  |
| Get-XdrEndpointDeviceWindowsReleaseVersion                      | Get Windows release version information                             |
| Get-XdrEndpointLicenseReport                                    | Retrieve endpoint license report                                    |
| Get-XdrExposureManagementRecommendations                        | Get security recommendations from Exposure Management               |
| Get-XdrIdentityAlertThreshold                                   | Get alert threshold configuration for Defender for Identity         |
| Get-XdrIdentityConfigurationDirectoryServiceAccount             | Retrieve directory service account configuration                    |
| Get-XdrIdentityConfigurationRemediationActionAccount            | Get remediation action account configuration                        |
| Get-XdrIdentityDomainControllerCoverage                         | Retrieve domain controller coverage information                     |
| Get-XdrIdentityIdentity                                         | Get identities from Microsoft Defender for Identity                 |
| Get-XdrIdentityOnboardingStatus                                 | Get onboarding status for Defender for Identity                     |
| Get-XdrIdentityServiceAccount                                   | Retrieve service account information                                |
| Get-XdrIdentityStatistic                                        | Get identity statistics                                             |
| Get-XdrIncident                                                 | Retrieve incidents with filtering and pagination                    |
| Get-XdrIncidentAssociatedAlert                                  | Retrieve alerts associated with a specific incident                 |
| Get-XdrMtoTenantList                                            | Get list of tenants in MTO multi-tenant view                        |
| Get-XdrStreamingApiConfiguration                                | Get Streaming API configuration                                     |
| Get-XdrSuppressionRule                                          | Retrieve alert suppression rules                                    |
| Get-XdrTenantContext                                            | Retrieve tenant context information                                 |
| Get-XdrTenantWorkloadStatus                                     | Get workload status for the tenant                                  |
| Get-XdrThreatAnalyticsOutbreaks                                 | Retrieve threat analytics outbreak data (-ChangeCount, -TopThreats) |
| Get-XdrUserPreference                                           | Get user preferences from Microsoft Defender XDR                    |
| Get-XdrVulnerabilityManagementAdvisories                        | Retrieve security advisories from TVM                               |
| Get-XdrVulnerabilityManagementBaseline                          | Get security baseline assessment data from TVM                      |
| Get-XdrVulnerabilityManagementCertificates                      | Retrieve certificate inventory from TVM                             |
| Get-XdrVulnerabilityManagementChangeEvents                      | Get change events from TVM                                          |
| Get-XdrVulnerabilityManagementDashboard                         | Retrieve TVM dashboard data                                         |
| Get-XdrVulnerabilityManagementExtensions                        | Get browser extension inventory from TVM                            |
| Get-XdrVulnerabilityManagementProducts                          | Retrieve product information from TVM                               |
| Get-XdrVulnerabilityManagementRemediationTasks                  | Get remediation tasks and exceptions from TVM                       |
| Get-XdrVulnerabilityManagementVulnerabilities                   | Retrieve vulnerabilities from TVM (-Summary for stats)              |
| Get-XdrXspmAttackPath                                           | Retrieve attack path data from XSPM                                 |
| Get-XdrXspmChokePoint                                           | Get choke points in attack paths                                    |
| Get-XdrXspmTopEntryPoint                                        | Retrieve top entry points from attack paths                         |
| Get-XdrXspmTopTarget                                            | Get top targets from attack paths                                   |
| Invoke-XdrEndpointDeviceAction                                  | Unified cmdlet for all endpoint device actions                      |
| Invoke-XdrEndpointDeviceAutomatedInvestigation                  | Start an automated investigation on a device                        |
| Invoke-XdrEndpointDeviceLiveResponseCommand                     | Execute Live Response commands programmatically with optional row expansion |
| Invoke-XdrEndpointDevicePolicySync                              | Force a policy sync on a device                                     |
| Invoke-XdrHuntingQueryValidation                                | Validate an Advanced Hunting query for custom detection rules       |
| Invoke-XdrMtoAdvancedHunting                                    | Execute Advanced Hunting queries across multiple tenants            |
| Invoke-XdrRestMethod                                            | Invoke REST API calls to XDR endpoints                              |
| Invoke-XdrXspmHuntingQuery                                      | Execute hunting queries against XSPM attack surface API             |
| Merge-XdrIncident                                               | Merge multiple incidents into a single incident                     |
| Move-XdrAlertToIncident                                         | Move alerts to a specific incident or create a new one              |
| New-XdrAdvancedHuntingFunction                                  | Create new Advanced Hunting functions                               |
| New-XdrConfigurationCriticalAssetManagementClassification       | Create critical asset management classification rules               |
| New-XdrEndpointConfigurationCustomCollectionRule                | Create custom collection rules from YAML files                      |
| New-XdrEndpointDeviceLiveResponseLibraryFile                    | Upload a script file to the Live Response library                   |
| New-XdrEndpointDeviceRbacGroup                                  | Create new endpoint device groups                                   |
| New-XdrIdentityConfigurationRemediationActionAccount            | Create new remediation action account configuration                 |
| Remove-XdrAdvancedHuntingFunction                               | Remove Advanced Hunting functions                                   |
| Remove-XdrConfigurationCriticalAssetManagementClassification    | Remove critical asset management classification rules               |
| Remove-XdrEndpointDeviceLiveResponseLibraryFile                 | Delete a file from the Live Response library                        |
| Remove-XdrIdentityConfigurationRemediationActionAccount         | Remove remediation action account configuration                     |
| Set-XdrAdvancedHuntingFunction                                  | Update existing Advanced Hunting functions                          |
| Set-XdrConfigurationCriticalAssetManagementClassification       | Enable or disable classification rules                              |
| Set-XdrConfigurationPreviewFeatures                             | Enable or disable XDR preview features                              |
| Set-XdrConnectionSettings                                       | Configure connection settings for XDR                               |
| Set-XdrEndpointAdvancedFeatures                                 | Set endpoint advanced features configuration                        |
| Set-XdrEndpointConfigurationCustomCollectionRule                | Update existing custom collection rules                             |
| Set-XdrEndpointDeviceAssetValue                                 | Set the asset value for one or more devices                         |
| Set-XdrEndpointDeviceCriticalityLevel                           | Set the criticality level for one or more devices                   |
| Set-XdrEndpointDeviceExclusionState                             | Set device exclusion state (Excluded/Included)                      |
| Set-XdrEndpointDeviceRbacGroup                                  | Update endpoint device groups                                       |
| Set-XdrEndpointDeviceTag                                        | Set user-defined tags on one or more devices                        |
| Set-XdrIdentityConfigurationRemediationActionAccount            | Update remediation action account configuration                     |
| Stop-XdrEndpointDeviceAction                                    | Cancel a pending device action by request GUID                      |
| Update-XdrConnectionSettings                                    | Update and refresh connection settings                              |

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
