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

    It 'resolves a UPN with one API call and no enrichment' {
        $user = Get-XdrIdentityUser -Upn 'analyst@example.test' -ResolveOnly

        $user.displayName | Should -Be 'Analyst'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Uri -like '*/user/resolve' -and ($Body | ConvertFrom-Json).userIdentifiers.upn -eq 'analyst@example.test'
        }
        Should -Invoke Get-XdrCache -ModuleName XDRInternals -Times 0
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }
}