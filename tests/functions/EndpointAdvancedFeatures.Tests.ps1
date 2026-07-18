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
