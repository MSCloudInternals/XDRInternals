Describe 'Identity resolve-only lookup' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrCache { throw 'Resolve-only must not use the enriched cache' } -ModuleName XDRInternals
        Mock Set-XdrCache { throw 'Resolve-only must not cache incomplete user data' } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            if ($Uri -notlike '*/user/resolve') { throw 'Unexpected enrichment API call' }
            [pscustomobject]@{ results = [pscustomobject]@{ displayName = 'Analyst'; ids = [pscustomobject]@{ aad = 'object-id' } }; errors = @(); workloads = @() }
        } -ModuleName XDRInternals
    }

    It 'resolves a <Parameter> with one API call and no enrichment' -TestCases @(
        @{ Parameter = 'Upn'; Identifier = 'analyst@example.test'; Field = 'upn' }
        @{ Parameter = 'AadId'; Identifier = '12345678-1234-1234-1234-123456789abc'; Field = 'aad' }
        @{ Parameter = 'Sid'; Identifier = 'S-1-5-21-111-222-333-1001'; Field = 'sid' }
    ) {
        param($Parameter, $Identifier, $Field)
        $arguments = @{ $Parameter = $Identifier }
        $user = Get-XdrIdentityUser @arguments -ResolveOnly

        $user.displayName | Should -Be 'Analyst'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Uri -like '*/user/resolve' -and ($Body | ConvertFrom-Json).userIdentifiers.$Field -eq $Identifier
        }
        Should -Invoke Get-XdrCache -ModuleName XDRInternals -Times 0
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }
}