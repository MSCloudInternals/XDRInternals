![](./images/xdrinternals-banner.jpg "XDRInternals")

# XDRInternals

The unofficial API cmdlet to interact with the Microsoft Defender XDR portal

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

| Cmdlet                                                      | Description                                                   |
| ----------------------------------------------------------- | ------------------------------------------------------------- |
| Connect-XdrByEstsCookie                                     | Authenticate to Microsoft Defender XDR using ESTS cookie      |
| Get-XdrActionsCenterHistory                                 | Retrieve historical actions from the Action Center            |
| Get-XdrActionsCenterPending                                 | Retrieve pending actions from the Action Center               |
| Get-XdrAdvancedHuntingFunction                              | Get saved Advanced Hunting functions                          |
| Get-XdrAdvancedHuntingTableSchema                           | Get the schema for Advanced Hunting tables                    |
| Get-XdrAdvancedHuntingUserHistory                           | Retrieve user's Advanced Hunting query history                |
| Get-XdrAlert                                                | Retrieve alerts with filtering and pagination                 |
| Get-XdrConfigurationAlertServiceSetting                     | Get alert service configuration settings                      |
| Get-XdrConfigurationAlertTuning                             | Retrieve alert tuning and suppression rules                   |
| Get-XdrConfigurationAssetRuleManagement                     | Get asset rule management configuration                       |
| Get-XdrConfigurationCriticalAssetManagement                 | Retrieve critical asset management settings                   |
| Get-XdrConfigurationServiceAccountClassification            | Get service account classification configuration              |
| Get-XdrConfigurationUnifiedRBACWorkload                     | Retrieve Unified RBAC workload configuration                  |
| Get-XdrDatalakeDatabase                                     | Get available datalake databases                              |
| Get-XdrDatalakeTableSchema                                  | Retrieve schema for datalake tables                           |
| Get-XdrEndpointAdvancedFeatures                             | Get endpoint advanced features settings                       |
| Get-XdrEndpointConfigurationAdvancedFeatures                | Retrieve endpoint advanced features configuration             |
| Get-XdrEndpointConfigurationAuthenticatedTelemetry          | Get authenticated telemetry configuration                     |
| Get-XdrEndpointConfigurationCustomCollectionRule            | Get custom collection rules for MDE                           |
| Get-XdrEndpointConfigurationIntuneConnection                | Retrieve Intune connection configuration                      |
| Get-XdrEndpointConfigurationLiveResponse                    | Get Live Response configuration settings                      |
| Get-XdrEndpointConfigurationPotentiallyUnwantedApplications | Retrieve PUA configuration                                    |
| Get-XdrEndpointConfigurationPreviewFeature                  | Get preview feature configuration                             |
| Get-XdrEndpointConfigurationPurviewSharing                  | Retrieve Purview data sharing configuration                   |
| Get-XdrEndpointCustomDataCollectionRules                    | Get custom data collection rules                              |
| Get-XdrEndpointDevice                                       | Get endpoint devices with filtering and pagination            |
| Get-XdrEndpointDeviceModel                                  | Retrieve device models                                        |
| Get-XdrEndpointDeviceOsVersionFriendlyName                  | Get friendly names for OS versions                            |
| Get-XdrEndpointDeviceRbacGroup                              | Retrieve RBAC groups for devices                              |
| Get-XdrEndpointDeviceTag                                    | Get device tags                                               |
| Get-XdrEndpointDeviceTimeline                               | Retrieve timeline events for a specific device                |
| Get-XdrEndpointDeviceTotals                                 | Get total counts of endpoint devices                          |
| Get-XdrEndpointDeviceVendor                                 | Retrieve device vendor information                            |
| Get-XdrEndpointDeviceWindowsReleaseVersion                  | Get Windows release version information                       |
| Get-XdrEndpointLicenseReport                                | Retrieve endpoint license report                              |
| Get-XdrIdentityAlertThreshold                               | Get alert threshold configuration for Defender for Identity   |
| Get-XdrIdentityConfigurationDirectoryServiceAccount         | Retrieve directory service account configuration              |
| Get-XdrIdentityConfigurationRemediationActionAccount        | Get remediation action account configuration                  |
| Get-XdrIdentityDomainControllerCoverage                     | Retrieve domain controller coverage information               |
| Get-XdrIdentityIdentity                                     | Get identities from Microsoft Defender for Identity           |
| Get-XdrIdentityOnboardingStatus                             | Get onboarding status for Defender for Identity               |
| Get-XdrIdentityServiceAccount                               | Retrieve service account information                          |
| Get-XdrIdentityStatistic                                    | Get identity statistics                                       |
| Get-XdrIncident                                             | Retrieve incidents with filtering and pagination              |
| Get-XdrServiceInfo                                          | Retrieve XDR service information                              |
| Get-XdrStreamingApiConfiguration                            | Get Streaming API configuration                               |
| Get-XdrSuppressionRule                                      | Retrieve alert suppression rules                              |
| Get-XdrTenantContext                                        | Retrieve tenant context information                           |
| Get-XdrTenants                                              | Retrieve list of accessible tenants                           |
| Get-XdrTenantWorkloadStatus                                 | Get workload status for the tenant                            |
| Get-XdrUnifiedPortalIsOnboarded                             | Check if unified portal is onboarded                          |
| Get-XdrUnifiedPortalOnboardedWorkspace                      | Get onboarded workspace information                           |
| Get-XdrXspmAttackPath                                       | Retrieve attack path data from XSPM                           |
| Get-XdrXspmChokePoint                                       | Get choke points in attack paths                              |
| Get-XdrXspmTopEntryPoint                                    | Retrieve top entry points from attack paths                   |
| Get-XdrXspmTopTarget                                        | Get top targets from attack paths                             |
| Invoke-XdrHuntingQueryValidation                            | Validate an Advanced Hunting query for custom detection rules |
| Invoke-XdrRestMethod                                        | Invoke REST API calls to XDR endpoints                        |
| Invoke-XdrXspmHuntingQuery                                  | Execute hunting queries against XSPM attack surface API       |
| Merge-XdrIncident                                           | Merge multiple incidents into a single incident               |
| New-XdrAdvancedHuntingFunction                              | Create new Advanced Hunting functions                         |
| New-XdrEndpointConfigurationCustomCollectionRule            | Create custom collection rules from YAML files                |
| New-XdrIdentityConfigurationRemediationActionAccount        | Create new remediation action account configuration           |
| Remove-XdrAdvancedHuntingFunction                           | Remove Advanced Hunting functions                             |
| Remove-XdrIdentityConfigurationRemediationActionAccount     | Remove remediation action account configuration               |
| Set-XdrAdvancedHuntingFunction                              | Update existing Advanced Hunting functions                    |
| Set-XdrConnectionSettings                                   | Configure connection settings for XDR                         |
| Set-XdrEndpointAdvancedFeatures                             | Set endpoint advanced features configuration                  |
| Set-XdrEndpointConfigurationCustomCollectionRule            | Update existing custom collection rules                       |
| Set-XdrIdentityConfigurationRemediationActionAccount        | Update remediation action account configuration               |
| Update-XdrConnectionSettings                                | Update and refresh connection settings                        |

## Installation

```powershell
# Clone the repository
git clone https://github.com/MSCloudInternals/XDRInternals.git

# Import the module
Import-Module .\XDRInternals\XDRInternals.psd1
```

## Usage

```powershell
# Connect to Microsoft Defender XDR
Connect-XdrByEstsCookie

# Get tenant context
Get-XdrTenantContext

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

## License

See LICENSE file for details.
