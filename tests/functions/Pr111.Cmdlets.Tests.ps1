$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

Describe 'PR 111 cmdlet behavior' -Tag 'Functions', 'PR111' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals

        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
    }

    It 'documents and refreshes the device group cache when creating RBAC groups' {
        Mock Get-XdrEndpointDeviceRbacGroup {
            @(
                [pscustomobject]@{ Name = 'Tier 0'; Priority = 0 }
                [pscustomobject]@{ Name = 'All devices'; Priority = 999 }
            )
        } -ModuleName XDRInternals
        Mock Set-XdrEndpointDeviceRbacGroup {
            param($GroupObject)
            @($GroupObject)
        } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals

        $groupObject = [pscustomobject]@{
            id           = ''
            name         = 'Pester Smoke Device Group'
            description  = 'Validation group'
            machinesRule = @()
        }

        $result = @(New-XdrEndpointDeviceRbacGroup -GroupObject $groupObject -Confirm:$false)
        $helpText = Get-Help New-XdrEndpointDeviceRbacGroup -Full | Out-String
        $outputTypes = (Get-Command New-XdrEndpointDeviceRbacGroup).OutputType.Type.FullName

        $groupObject.Priority | Should -Be 1
        $result | Should -HaveCount 3
        $helpText | Should -Not -Match 'includes caching support'
        $helpText | Should -Match '(?is)GroupObject.*required'
        $outputTypes | Should -Contain 'System.Object[]'
        Should -Invoke Set-XdrEndpointDeviceRbacGroup -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            @($GroupObject).Count -eq 3 -and
            $GroupObject[-1].name -eq 'Pester Smoke Device Group' -and
            $GroupObject[-1].Priority -eq 1
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'GetXdrEndpointDeviceRbacGroup' -and
            $TTLMinutes -eq 30 -and
            @($Value).Count -eq 3
        }
    }

    It 'still throws a clear error when GroupObject is omitted' {
        { New-XdrEndpointDeviceRbacGroup -Confirm:$false } |
            Should -Throw -ExpectedMessage '*GroupObject is required*'
    }

    It 'returns the created Advanced Hunting function to the pipeline' {
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                Id   = 42
                Name = 'PesterSmokeFunction'
            }
        } -ModuleName XDRInternals

        $result = New-XdrAdvancedHuntingFunction -Name 'PesterSmokeFunction' -KQLQuery 'DeviceInfo | take 1' -Confirm:$false

        $result.Id | Should -Be 42
        $result.Name | Should -Be 'PesterSmokeFunction'
    }

    It 'returns the updated Advanced Hunting function to the pipeline' {
        Mock Get-XdrAdvancedHuntingFunction {
            [pscustomobject]@{
                Id              = 42
                Name            = 'ExistingFunction'
                Body            = 'DeviceInfo | take 1'
                Description     = 'Existing description'
                IsShared        = $false
                Path            = ''
                InputParameters = @()
            }
        } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                Id   = 42
                Name = 'UpdatedFunction'
            }
        } -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals

        $result = Set-XdrAdvancedHuntingFunction -Id 42 -Name 'UpdatedFunction' -Confirm:$false

        $result.Name | Should -Be 'UpdatedFunction'
        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'XdrAdvancedHuntingFunction'
        }
    }

    It 'returns created custom collection rules to the pipeline' {
        $rulePath = Join-Path $TestDrive 'custom-collection-rule.yaml'
        @'
name: Pester Smoke Rule
description: Validation rule
platform: Windows
scope: Organization
table: DeviceEvents
actionType: RegistryValueSet
filters:
  conditionType: Operational
  logicalOperator: AND
  conditions: []
'@ | Set-Content -Path $rulePath -Encoding UTF8

        Mock Get-XdrTenantContext {
            [pscustomobject]@{
                AuthInfo = [pscustomobject]@{
                    UserName = 'pester@contoso.com'
                }
            }
        } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationCustomCollectionRule { @() } -ModuleName XDRInternals
        Mock ConvertTo-ApiFilterFormat { @{ parsed = $true } } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                ruleId   = '11111111-1111-1111-1111-111111111111'
                ruleName = 'Pester Smoke Rule'
            }
        } -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals

        $result = New-XdrEndpointConfigurationCustomCollectionRule -FilePath $rulePath -Enabled:$true -Confirm:$false

        $result.ruleId | Should -Be '11111111-1111-1111-1111-111111111111'
        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'XdrEndpointConfigurationCustomCollectionRule'
        }
    }

    It 'returns updated custom collection rules to the pipeline' {
        $existingRule = [pscustomobject]@{
            ruleId              = '22222222-2222-2222-2222-222222222222'
            ruleName            = 'Existing Rule'
            ruleDescription     = 'Existing description'
            isEnabled           = $true
            platform            = 'Windows'
            scope               = 'Organization'
            table               = 'DeviceEvents'
            actionType          = 'RegistryValueSet'
            filters             = @{}
            tags                = @()
            createdBy           = 'pester@contoso.com'
            creationDateTimeUtc = '2026-01-01T00:00:00Z'
            version             = 3
            updateKey           = 'update-key'
        }
        Mock Get-XdrTenantContext {
            [pscustomobject]@{
                AuthInfo = [pscustomobject]@{
                    UserName = 'pester@contoso.com'
                }
            }
        } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationCustomCollectionRule { @($existingRule) } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                ruleId   = '22222222-2222-2222-2222-222222222222'
                ruleName = 'Updated Rule'
            }
        } -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals

        $inputRule = [pscustomobject]@{
            ruleId          = '22222222-2222-2222-2222-222222222222'
            ruleName        = 'Updated Rule'
            ruleDescription = 'Updated description'
            isEnabled       = $false
            platform        = 'Windows'
            scope           = 'Organization'
            table           = 'DeviceEvents'
            actionType      = 'RegistryValueSet'
            filters         = @{}
            tags            = @()
        }

        $result = Set-XdrEndpointConfigurationCustomCollectionRule -InputObject $inputRule -Confirm:$false

        $result.ruleName | Should -Be 'Updated Rule'
        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'XdrEndpointConfigurationCustomCollectionRule'
        }
    }

    It 'uses stable cache keys for paged incident retrieval' {
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock ConvertFrom-XdrDetectionSourceId { 'Email' } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            $request = $Body | ConvertFrom-Json
            switch ($request.pageIndex) {
                1 {
                    @(
                        [pscustomobject]@{ Severity = 128; DetectionSources = @(1) }
                        [pscustomobject]@{ Severity = 64; DetectionSources = @() }
                    )
                }
                2 {
                    @(
                        [pscustomobject]@{ Severity = 32; DetectionSources = @() }
                    )
                }
                default { @() }
            }
        } -ModuleName XDRInternals

        $result = @(Get-XdrIncident -TitleSearchTerms 'malware', 'phishing' -LookBackInDays 7 -SortByField CreatedDate -SortOrder Ascending -PageSize 2 -All)

        $result | Should -HaveCount 3
        $result[0].SeverityName | Should -Be 'Medium'
        @($result[0].DetectionSourceNames) | Should -Contain 'Email'
        Should -Invoke Get-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'XdrIncidents_LookBackInDays=7;SortByField=CreatedDate;SortOrder=Ascending;PageSize=2;PageIndex=1;DefenderExpertsLicensed=False;TitleSearchTerms=malware,phishing'
        }
        Should -Invoke Get-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'XdrIncidents_LookBackInDays=7;SortByField=CreatedDate;SortOrder=Ascending;PageSize=2;PageIndex=2;DefenderExpertsLicensed=False;TitleSearchTerms=malware,phishing'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'XdrIncidents_LookBackInDays=7;SortByField=CreatedDate;SortOrder=Ascending;PageSize=2;PageIndex=1;DefenderExpertsLicensed=False;TitleSearchTerms=malware,phishing'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $CacheKey -eq 'XdrIncidents_LookBackInDays=7;SortByField=CreatedDate;SortOrder=Ascending;PageSize=2;PageIndex=2;DefenderExpertsLicensed=False;TitleSearchTerms=malware,phishing'
        }
    }

    It 'returns flattened unified RBAC workload settings plus cloud scoping status' {
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                workloads = [pscustomobject]@{
                    Aad = [pscustomobject]@{
                        isWorkloadEligible                = $true
                        isWorkloadProvisioned             = $true
                        isUrbacEnabled                    = $true
                        migrationInfo                     = [pscustomobject]@{
                            lastImportedDate = '2026-01-01T00:00:00Z'
                            hasRoles         = $true
                        }
                        userAccessLevel                   = 'Admin'
                        maxAccessLevelForAllUnifiedScopes = 'Admin'
                        maxAccessLevelIgnoreScopes        = 'Reader'
                        hasEnablementToggle               = $true
                        uiTextKey                         = 'aad'
                    }
                    Mdo = [pscustomobject]@{
                        isWorkloadEligible                = $true
                        isWorkloadProvisioned             = $true
                        isUrbacEnabled                    = $false
                        migrationInfo                     = [pscustomobject]@{
                            lastImportedDate = $null
                            hasRoles         = $false
                        }
                        userAccessLevel                   = 'Reader'
                        maxAccessLevelForAllUnifiedScopes = 'Reader'
                        maxAccessLevelIgnoreScopes        = 'Reader'
                        hasEnablementToggle               = $false
                        uiTextKey                         = 'mdo'
                        isExoEnabled                      = $true
                    }
                }
                cloudScopingActivationStatus = 'Enabled'
            }
        } -ModuleName XDRInternals

        $result = @(Get-XdrConfigurationUnifiedRBACWorkload)
        $cloudScoping = $result | Where-Object Workload -eq 'CloudScopingActivationStatus'
        $mdo = $result | Where-Object Workload -eq 'DefenderForOffice365'

        $result | Should -HaveCount 3
        ($result | Where-Object Workload -eq 'EntraID').IsUrbacEnabled | Should -BeTrue
        $mdo.IsExoEnabled | Should -BeTrue
        $cloudScoping.CloudScopingActivationStatus | Should -Be 'Enabled'
    }

    It 'returns normalized alert service settings as objects' {
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                Mdc = [pscustomobject]@{
                    reasons         = @()
                    feedback        = 'feedback'
                    disabledTime    = '2026-01-02T00:00:00Z'
                    disablementType = 'Manual'
                }
                Aad = [pscustomobject]@{
                    reasons         = @('TenantDisabled')
                    feedback        = $null
                    disabledTime    = $null
                    disablementType = 'Inherited'
                }
            }
        } -ModuleName XDRInternals

        $result = @(Get-XdrConfigurationAlertServiceSetting)
        $outputTypes = (Get-Command Get-XdrConfigurationAlertServiceSetting).OutputType.Type.FullName

        $result | Should -HaveCount 2
        ($result | Where-Object Service -eq 'DefenderForCloud').AlertSetting | Should -Be 'MonitorAllAlerts'
        ($result | Where-Object Service -eq 'EntraID').AlertSetting | Should -Be 'TenantDisabled'
        $outputTypes | Should -Contain 'System.Object[]'
    }
}
