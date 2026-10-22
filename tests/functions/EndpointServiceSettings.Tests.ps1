$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

Describe 'Additional Endpoint service settings' -Tag 'Functions', 'Endpoint' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
    }

    It 'retrieves web content filtering policies' {
        Mock Invoke-RestMethod {
            @([pscustomobject]@{ PolicyName = 'policy'; BlockedCategoryIds = @(1); AuditCategoryIds = @(2) })
        } -ModuleName XDRInternals

        $policies = @(Get-XdrEndpointWebContentFilteringPolicy -Force)

        $policies.Count | Should -Be 1
        $policies[0].BlockedCategoryIds | Should -Contain 1
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/mtp/userRequests/webcategory/policies'
        }
    }

    It 'retrieves onboarding status without changing field names' {
        Mock Invoke-RestMethod {
            [pscustomobject]@{ MachineOnboarded = $true; RanTestAlert = $false; StatusHasChanged = $false }
        } -ModuleName XDRInternals

        $status = Get-XdrEndpointOnboardingStatus -Force

        $status.MachineOnboarded | Should -BeTrue
        $status.RanTestAlert | Should -BeFalse
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/mtp/settings/EndpointOnboardingStatus'
        }
    }

    It 'lists <List> onboarding activators with a separate cache' -ForEach @(
        @{ List = 'List'; Hidden = $false }
        @{ List = 'ListHidden'; Hidden = $true }
    ) {
        Mock Invoke-RestMethod { @([pscustomobject]@{ RequestId = 'request'; Name = 'sample' }) } -ModuleName XDRInternals

        $activators = @(Get-XdrEndpointOnboardingActivator -Hidden:$Hidden)

        $activators.Count | Should -Be 1
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq "https://security.microsoft.com/apiproxy/mtp/packages/DownloadOnboardingWindowsActivator/$List"
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -eq "GetXdrEndpointOnboardingActivator$List" -and $TTLMinutes -eq 30
        }
    }
}