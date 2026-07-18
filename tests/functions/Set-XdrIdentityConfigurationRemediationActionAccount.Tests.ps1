$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

Describe 'Set-XdrIdentityConfigurationRemediationActionAccount' -Tag 'Functions', 'Identity' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ ok = $true } } -ModuleName XDRInternals
    }

    It 'uses Local System by default when the parameter is omitted' {
        Set-XdrIdentityConfigurationRemediationActionAccount -Confirm:$false | Out-Null

        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $payload = $Body | ConvertFrom-Json
            $Uri -eq 'https://security.microsoft.com/apiproxy/aatp/api/remediationActions/configuration' -and
            $Method -eq 'Post' -and
            $payload.IsRemediationWithLocalSystemEnabled -eq $true
        }
    }

    It 'allows switching to a dedicated account explicitly' {
        Set-XdrIdentityConfigurationRemediationActionAccount -UseLocalSystem:$false -Confirm:$false | Out-Null

        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $payload = $Body | ConvertFrom-Json
            $payload.IsRemediationWithLocalSystemEnabled -eq $false
        }
    }

    It 'does not call the API when WhatIf is specified' {
        Set-XdrIdentityConfigurationRemediationActionAccount -WhatIf | Out-Null

        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0 -Exactly
        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'documents both examples with explicit boolean values' {
        $help = Get-Help Set-XdrIdentityConfigurationRemediationActionAccount
        $exampleOneCode = ($help.Examples.Example[0].Code -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })[0].Trim()
        $exampleTwoCode = ($help.Examples.Example[1].Code -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })[0].Trim()

        $help.Parameters.Parameter |
            Where-Object Name -eq 'UseLocalSystem' |
            Select-Object -ExpandProperty Description |
            Select-Object -ExpandProperty Text |
            Should -Match 'Defaults to \$true'

        $exampleOneCode | Should -Be 'Set-XdrIdentityConfigurationRemediationActionAccount -UseLocalSystem:$true'
        $exampleTwoCode | Should -Be 'Set-XdrIdentityConfigurationRemediationActionAccount -UseLocalSystem:$false'
    }
}
