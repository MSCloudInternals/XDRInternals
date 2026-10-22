Describe 'Automated investigation exclusion continuation origin' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:ContinuationCalls = [System.Collections.Generic.List[string]]::new()
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
    }

    It 'validates <Type> continuation <Link>' -ForEach @(
        foreach ($type in @('Folder', 'MemoryContent')) {
            foreach ($link in @('https', 'relative', 'query', 'explicit443', 'networkRelative', 'http', 'port', 'userinfo', 'host', 'path', 'repeat')) {
                @{ Type = $type; Link = $link }
            }
        }
    ) {
        $path = if ($Type -eq 'Folder') { '/apiproxy/mtp/autoIr/folder_exclusion/all' } else { '/apiproxy/mtp/autoIr/acl/all' }
        $next = switch ($Link) {
            https { "https://security.microsoft.com${path}?scroll=synthetic" }
            relative { "${path}?scroll=synthetic" }
            query { '?scroll=synthetic' }
            explicit443 { "https://security.microsoft.com:443${path}?scroll=synthetic" }
            networkRelative { "//security.microsoft.com${path}?scroll=synthetic" }
            http { "http://security.microsoft.com${path}?scroll=synthetic" }
            port { "https://security.microsoft.com:8443${path}?scroll=synthetic" }
            userinfo { "https://synthetic@security.microsoft.com${path}?scroll=synthetic" }
            host { "https://example.invalid${path}?scroll=synthetic" }
            path { 'https://security.microsoft.com/other?scroll=synthetic' }
            repeat { "${path}?scroll=synthetic" }
        }
        InModuleScope XDRInternals -Parameters @{ Next = $next; Repeat = ($Link -eq 'repeat') } {
            param($Next, $Repeat)
            $script:NextFixture = $Next
            $script:RepeatFixture = $Repeat
        }
        Mock Invoke-RestMethod {
            param($Uri)
            InModuleScope XDRInternals -Parameters @{ Uri = [string]$Uri } {
                param($Uri)
                $script:ContinuationCalls.Add($Uri)
                if ($script:ContinuationCalls.Count -gt 2) { throw 'Unexpected third transport call' }
                [pscustomobject]@{
                    count = $(if ($script:ContinuationCalls.Count -eq 1) { 9001 } else { 9002 })
                    results = $(if ($script:ContinuationCalls.Count -eq 1) { @() } else { @([pscustomobject]@{ id = 'second' }) })
                    next = $(if ($script:ContinuationCalls.Count -eq 1 -or $script:RepeatFixture) { $script:NextFixture } else { $null })
                }
            }
        } -ModuleName XDRInternals

        if ($Link -in @('http', 'port', 'userinfo', 'host', 'path', 'repeat')) {
            { Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Type -Force -ErrorAction Stop } |
                Should -Throw '*Invalid automated investigation exclusion continuation link*'
            $expectedCalls = if ($Link -eq 'repeat') { 2 } else { 1 }
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times $expectedCalls -Exactly
            Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0 -Exactly
        } else {
            $result = Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Type -Force -ErrorAction Stop
            $result.results | Should -HaveCount 1
            $result.results[0].id | Should -Be 'second'
            $result.count | Should -Be 9001
            $result.next | Should -BeNullOrEmpty
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
            Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -Exactly
        }
    }
    It 'rejects a redirect on the <Stage> request for <Type> without caching partial results' -ForEach @(
        foreach ($type in @('Folder', 'MemoryContent')) {
            foreach ($stage in @('initial', 'continuation')) {
                @{ Type = $type; Stage = $stage }
            }
        }
    ) {
        $script:RedirectCalls = 0
        Mock Invoke-RestMethod {
            param($ErrorAction)
            $script:RedirectCalls++
            if ($Stage -eq 'initial' -or $script:RedirectCalls -eq 2) {
                Write-Error -Message 'Synthetic redirect rejected' -ErrorAction $ErrorAction
            }
            [pscustomobject]@{ count = 1; results = @([pscustomobject]@{ id = 'first' }); next = '?scroll=synthetic' }
        } -ModuleName XDRInternals

        $capturedErrors = @()
        $result = @(Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Type -Force -ErrorAction SilentlyContinue -ErrorVariable +capturedErrors)
        $result | Should -HaveCount 0
        $capturedErrors | Should -Not -BeNullOrEmpty
        ($capturedErrors | Out-String) | Should -BeLike '*Synthetic redirect rejected*'
        $expectedCalls = if ($Stage -eq 'initial') { 1 } else { 2 }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times $expectedCalls -Exactly
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times $expectedCalls -Exactly -ParameterFilter {
            $PesterBoundParameters.ContainsKey('MaximumRedirection') -and $MaximumRedirection -eq 0 -and $ErrorAction -eq 'Stop'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0 -Exactly
    }

}
