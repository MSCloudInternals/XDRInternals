$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

Describe 'Endpoint advanced features' -Tag 'Functions', 'Endpoint', 'ReviewRegression' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationAdvancedFeatures {
            [pscustomobject]@{
                LicenseEnabled                             = $true
                EnableCustomAsrAdvancedProcessTermination = $true
                EnableHVAOnboardingOptions                 = $false
            }
        } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationIntuneConnection { 1 } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationLiveResponse { [pscustomobject]@{} } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationPotentiallyUnwantedApplications { [pscustomobject]@{} } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationPreviewFeature { [pscustomobject]@{} } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationPurviewSharing { $false } -ModuleName XDRInternals
        Mock Get-XdrEndpointConfigurationAuthenticatedTelemetry { $false } -ModuleName XDRInternals
    }

    It 'includes both optional feature toggles missing from the consolidated getter' {
        $features = @(Get-XdrEndpointAdvancedFeatures)

        $customAsr = $features | Where-Object Name -EQ 'CustomASRRulesAdvancedProcessTermination'
        $restrictedOnboarding = $features | Where-Object Name -EQ 'AllowRestrictedSecurityOperationsDuringOnboarding'

        $customAsr.Value | Should -BeTrue
        $customAsr.Description | Should -Be 'Enable or disable the ability to kill parent processes.'
        $customAsr.ConfigurableInPortal | Should -BeFalse
        $restrictedOnboarding.Value | Should -BeFalse
        $restrictedOnboarding.Description | Should -Match '^Provides the option to restrict security operations'
        $restrictedOnboarding.ConfigurableInPortal | Should -BeTrue
    }

    It 'exports the portal-aligned optional features alias' {
        $alias = Get-Alias Get-XdrEndpointConfigurationOptionalFeatures

        $alias.Definition | Should -Be 'Get-XdrEndpointConfigurationAdvancedFeatures'
        (Get-Command Get-XdrEndpointConfigurationOptionalFeatures).CommandType | Should -Be 'Alias'
    }
}

Describe 'Endpoint automated attack disruption exclusions' -Tag 'Functions', 'Endpoint' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{ ExclusionType = 'DeviceTag'; DefaultIdentifiers = @() }
        } -ModuleName XDRInternals
    }

    It 'routes each supported device exclusion type to its captured endpoint' -ForEach @(
        @{ Type = 'IP'; Path = 'IP' }
        @{ Type = 'DeviceTag'; Path = 'DeviceTag' }
        @{ Type = 'DefaultDeviceTag'; Path = 'deviceTag/default' }
    ) {
        $result = Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type $Type

        $result.ExclusionType | Should -Be 'DeviceTag'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq "https://security.microsoft.com/apiproxy/mtp/disrupt/api/exclusions/$Path"
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -eq "GetXdrEndpointConfigurationAttackDisruptionExclusion$Type" -and $TTLMinutes -eq 30
        }
    }

    It 'uses the canonical route and cache key for a case-insensitive type' {
        Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type devicetag | Out-Null

        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Uri -eq 'https://security.microsoft.com/apiproxy/mtp/disrupt/api/exclusions/DeviceTag'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -eq 'GetXdrEndpointConfigurationAttackDisruptionExclusionDeviceTag'
        }
    }

    It 'returns a valid cached exclusion response without a request' {
        Mock Get-XdrCache {
            [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(5); Value = [pscustomobject]@{ ExclusionType = 'IP' } }
        } -ModuleName XDRInternals

        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP).ExclusionType | Should -Be 'IP'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0
    }
}

Describe 'Endpoint custom data collection model' -Tag 'Functions', 'Endpoint' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{ platforms = @([pscustomobject]@{ platform = 'Windows'; tables = @() }) }
        } -ModuleName XDRInternals
    }

    It 'retrieves the platform and table model and caches its raw response' {
        $model = Get-XdrEndpointConfigurationCustomCollectionModel -Force

        $model.platforms[0].platform | Should -Be 'Windows'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/mtp/mdeCustomCollection/model'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -eq 'GetXdrEndpointConfigurationCustomCollectionModel' -and $TTLMinutes -eq 30
        }
        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 1
    }
}

Describe 'Endpoint automated investigation advanced settings' -Tag 'Functions', 'Endpoint' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{ data = [pscustomobject]@{
                cloud_upload = $true
                upload_memory_content = $false
                computer_file_extension = 'exe'
            } }
        } -ModuleName XDRInternals
    }

    It 'retrieves the advanced AutoIR settings and preserves the API response' {
        $settings = Get-XdrEndpointConfigurationAutomatedInvestigation -Force

        $settings.data.cloud_upload | Should -BeTrue
        $settings.data.upload_memory_content | Should -BeFalse
        $settings.data.computer_file_extension | Should -Be 'exe'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Exactly -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/mtp/autoIr/ui/admin/advanced'
        }
    }
}

Describe 'Endpoint isolation allow rules' -Tag 'Functions', 'Endpoint' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { @([pscustomobject]@{ name = 'example' }) } -ModuleName XDRInternals
    }

    It 'requests rules for <OsPlatform> with a platform-specific cache key' -ForEach @(
        @{ OsPlatform = 'Windows' }
        @{ OsPlatform = 'MacOs' }
    ) {
        @(Get-XdrEndpointConfigurationIsolationAllowRule -OsPlatform $OsPlatform).Count | Should -Be 1
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq "https://security.microsoft.com/apiproxy/mtp/customizationApi/?customizationType=IsolationAllowRules&osPlatform=$OsPlatform"
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -eq "GetXdrEndpointConfigurationIsolationAllowRule$OsPlatform" -and $TTLMinutes -eq 30
        }
    }
}

Describe 'Endpoint automated investigation exclusions' -Tag 'Functions', 'Endpoint' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ count = 0; results = @() } } -ModuleName XDRInternals
    }

    It 'retrieves <Type> exclusions from the captured API route' -ForEach @(
        @{ Type = 'MemoryContent'; Path = 'acl/all?type=memory_content' }
        @{ Type = 'Folder'; Path = 'folder_exclusion/all?page_size=99999&type=folder' }
    ) {
        $result = Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Type

        $result.count | Should -Be 0
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq "https://security.microsoft.com/apiproxy/mtp/autoIr/$Path"
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -eq "GetXdrEndpointConfigurationAutomatedInvestigationExclusion$Type" -and $TTLMinutes -eq 30
        }
    }

    It 'returns and caches all pages of memory-content exclusions' {
        Mock Invoke-RestMethod {
            if ($Uri -like '*page=2') {
                return [pscustomobject]@{ count = 2; next = $null; results = @([pscustomobject]@{ id = 'second' }) }
            }
            [pscustomobject]@{
                count = 2
                next = 'https://security.microsoft.com/apiproxy/mtp/autoIr/acl/all?type=memory_content&page=2'
                results = @([pscustomobject]@{ id = 'first' })
            }
        } -ModuleName XDRInternals

        $result = Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type MemoryContent

        @($result.results.id) | Should -Be @('first', 'second')
        $result.next | Should -BeNullOrEmpty
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Exactly -Times 2
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Exactly -Times 1 -ParameterFilter {
            $Value.results.Count -eq 2 -and $null -eq $Value.next
        }
    }
}
