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
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            if ($Uri -like '*/IP') {
                [pscustomobject]@{ ExclusionType = 'IP'; Exclusions = @() }
            } elseif ($Uri -like '*/deviceTag/default') {
                [pscustomobject]@{ ExclusionType = 'DeviceTag'; DefaultIdentifiers = @() }
            } else {
                [pscustomobject]@{ ExclusionType = 'DeviceTag'; Exclusions = @() }
            }
        } -ModuleName XDRInternals
    }

    It 'routes each supported device exclusion type to its captured endpoint' -ForEach @(
        @{ Type = 'IP'; Path = 'IP'; ResponseType = 'IP'; Collection = 'Exclusions' }
        @{ Type = 'DeviceTag'; Path = 'DeviceTag'; ResponseType = 'DeviceTag'; Collection = 'Exclusions' }
        @{ Type = 'DefaultDeviceTag'; Path = 'deviceTag/default'; ResponseType = 'DeviceTag'; Collection = 'DefaultIdentifiers' }
    ) {
        $result = Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type $Type

        $result.ExclusionType | Should -Be $ResponseType
        $result.PSObject.Properties.Name | Should -Contain $Collection
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

    It 'bypasses a valid exclusion cache entry with Force' {
        Mock Get-XdrCache {
            [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(5); Value = [pscustomobject]@{ ExclusionType = 'IP' } }
        } -ModuleName XDRInternals

        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type DeviceTag -Force).ExclusionType | Should -Be 'DeviceTag'
        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -eq 'GetXdrEndpointConfigurationAttackDisruptionExclusionDeviceTag'
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1
    }

    It 'does not cache a failed exclusion request' {
        Mock Invoke-RestMethod { throw 'Request failed' } -ModuleName XDRInternals

        { Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP -ErrorAction Stop } | Should -Throw
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
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

    It 'returns a valid cached model without a request' {
        Mock Get-XdrCache {
            [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(5); Value = [pscustomobject]@{ platforms = @() } }
        } -ModuleName XDRInternals

        (Get-XdrEndpointConfigurationCustomCollectionModel).PSObject.Properties.Name | Should -Contain 'platforms'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0
    }

    It 'does not cache a failed model request' {
        Mock Invoke-RestMethod { throw 'Request failed' } -ModuleName XDRInternals

        { Get-XdrEndpointConfigurationCustomCollectionModel -ErrorAction Stop } | Should -Throw
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }
}
