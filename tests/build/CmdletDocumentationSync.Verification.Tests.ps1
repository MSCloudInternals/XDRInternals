Describe 'Documentation fixed point verification' {
    BeforeAll {
        $sourceRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        function Invoke-FixtureScript {
            param([string]$Name = 'Sync-CmdletDocumentation.ps1')
            $result = & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -File (Join-Path $fixture "build/$Name") 2>&1
            $script:fixtureExit = $LASTEXITCODE
            return ($result | Out-String)
        }
        function Save-Fixture {
            & git -C $fixture add -A
            & git -C $fixture -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm fixture
            if ($LASTEXITCODE) { throw 'Fixture commit failed.' }
        }
        function Get-OutputHashes {
            return @($outputs | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path $fixture $_)).Hash }) -join ','
        }
    }
    BeforeEach {
        $fixture = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $outputs = @('README.md', 'XDRInternals/XDRInternals.psd1', 'XDRay/CmdletApiMapping.json', 'XDRay Firefox/CmdletApiMapping.json')
        foreach ($directory in @('build', 'XDRInternals/functions', 'XDRInternals/internal', 'XDRay', 'XDRay Firefox')) {
            $null = New-Item -ItemType Directory -Path (Join-Path $fixture $directory) -Force
        }
        Copy-Item "$sourceRoot/build/*CmdletDocumentation*.ps1" (Join-Path $fixture 'build')
        Set-Content (Join-Path $fixture 'README.md') @'
Authored before $5.
## Available Cmdlets

| Cmdlet | Description |
|--------|-------------|
| Placeholder | Placeholder |

## Next Section
Authored after $1.
'@ -Encoding utf8BOM
        Set-Content (Join-Path $fixture $outputs[1]) '@{ ModuleVersion = ''9.8.7''; FunctionsToExport = @(''Placeholder'') }' -Encoding utf8BOM
        foreach ($path in $outputs[2..3]) { Set-Content (Join-Path $fixture $path) '[]' -Encoding utf8BOM }
        Set-Content (Join-Path $fixture 'XDRInternals/functions/Get-Widget.ps1') @'
<#
.SYNOPSIS
Gets widgets for $5.
#>
function Get-Widget {
    param([string]$Id)
    $Uri = "https://security.microsoft.com/widgets/$Id"
}
'@ -Encoding utf8BOM
        & git -C $fixture init -q
        Invoke-FixtureScript | Out-Null
        $fixtureExit | Should -Be 0
        Save-Fixture
    }
    It 'passes clean committed outputs and is byte idempotent' {
        $before = Get-OutputHashes
        Invoke-FixtureScript 'Test-CmdletDocumentationSync.ps1' | Should -Match 'All four'
        $fixtureExit | Should -Be 0
        Invoke-FixtureScript | Out-Null
        $fixtureExit | Should -Be 0
        Get-OutputHashes | Should -Be $before
        (Get-Content (Join-Path $fixture 'README.md') -Raw) | Should -Match 'Authored after \$1\.'
        (Import-PowerShellDataFile (Join-Path $fixture $outputs[1])).ModuleVersion | Should -Be '9.8.7'
    }
    It 'preserves CRLF and LF inputs and UTF8 BOM' -ForEach @(@{Newline="`n"}, @{Newline="`r`n"}) {
        foreach ($output in $outputs) {
            $path = Join-Path $fixture $output
            [IO.File]::WriteAllText($path, ([IO.File]::ReadAllText($path) -replace '\r?\n', $Newline), [Text.UTF8Encoding]::new($true))
        }
        $before = Get-OutputHashes
        Invoke-FixtureScript | Out-Null
        $fixtureExit | Should -Be 0
        Get-OutputHashes | Should -Be $before
    }
    It 'detects changed public function input without altering outputs' {
        Add-Content (Join-Path $fixture 'XDRInternals/functions/Get-Widget.ps1') "`n# harmless internal edit"
        Copy-Item (Join-Path $fixture 'XDRInternals/functions/Get-Widget.ps1') (Join-Path $fixture 'XDRInternals/functions/Get-NewWidget.ps1')
        $path = Join-Path $fixture 'XDRInternals/functions/Get-NewWidget.ps1'
        (Get-Content $path -Raw).Replace('Get-Widget', 'Get-NewWidget') | Set-Content $path -Encoding utf8BOM
        $before = Get-OutputHashes
        Invoke-FixtureScript 'Test-CmdletDocumentationSync.ps1' | Should -Match 'stale'
        $fixtureExit | Should -Not -Be 0
        Get-OutputHashes | Should -Be $before
    }
    It 'rejects dirty, deleted and untracked output <Output> (<Kind>)' -ForEach @(
        foreach ($output in @('README.md', 'XDRInternals/XDRInternals.psd1', 'XDRay/CmdletApiMapping.json', 'XDRay Firefox/CmdletApiMapping.json')) {
            foreach ($kind in @('dirty', 'deleted', 'untracked')) { @{Output=$output; Kind=$kind} }
        }
    ) {
        $path = Join-Path $fixture $Output
        switch ($Kind) {
            dirty { Add-Content $path 'contributor change' }
            deleted { Remove-Item -LiteralPath $path }
            untracked { & git -C $fixture rm --cached -- $Output | Out-Null }
        }
        $before = if (Test-Path $path) { [IO.File]::ReadAllBytes($path) }
        Invoke-FixtureScript 'Test-CmdletDocumentationSync.ps1' | Out-Null
        $fixtureExit | Should -Not -Be 0
        if ($before) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) | Should -Be ([Convert]::ToBase64String($before)) }
        else { Test-Path $path | Should -BeFalse }
    }
    It 'detects committed stale output <Output>' -ForEach @(
        @{Output='README.md'}, @{Output='XDRInternals/XDRInternals.psd1'},
        @{Output='XDRay/CmdletApiMapping.json'}, @{Output='XDRay Firefox/CmdletApiMapping.json'}
    ) {
        $path = Join-Path $fixture $Output
        $content = Get-Content $path -Raw
        if ($Output -like '*.json') { $content = $content.Replace('https://security.microsoft.com/widgets/{Id}', 'https://security.microsoft.com/stale') }
        else { $content = $content.Replace('Get-Widget', 'Get-StaleWidget') }
        Set-Content $path $content -Encoding utf8BOM -NoNewline
        Save-Fixture
        Invoke-FixtureScript 'Test-CmdletDocumentationSync.ps1' | Out-Null
        $fixtureExit | Should -Not -Be 0
    }
    It 'fails closed before writes for <Kind>' -ForEach @(
        @{Kind='malformed primary JSON'}, @{Kind='malformed Firefox JSON'}, @{Kind='non-array JSON'},
        @{Kind='missing README section'}, @{Kind='duplicate README section'},
        @{Kind='missing manifest target'}, @{Kind='duplicate manifest target'},
        @{Kind='manifest parse error'}, @{Kind='function parse error'}, @{Kind='wrong function name'}, @{Kind='no functions'}
    ) {
        switch ($Kind) {
            'malformed primary JSON' { Set-Content (Join-Path $fixture $outputs[2]) '[' }
            'malformed Firefox JSON' { Set-Content (Join-Path $fixture $outputs[3]) '[' }
            'non-array JSON' { Set-Content (Join-Path $fixture $outputs[2]) '{}' }
            'missing README section' { Set-Content (Join-Path $fixture 'README.md') 'prose' }
            'duplicate README section' { Add-Content (Join-Path $fixture 'README.md') "`n## Available Cmdlets" }
            'missing manifest target' { Set-Content (Join-Path $fixture $outputs[1]) '@{ ModuleVersion = ''9.8.7'' }' }
            'duplicate manifest target' { Set-Content (Join-Path $fixture $outputs[1]) '@{ FunctionsToExport = @(); Nested = @{ FunctionsToExport = @() } }' }
            'manifest parse error' { Add-Content (Join-Path $fixture $outputs[1]) '{' }
            'function parse error' { Add-Content (Join-Path $fixture 'XDRInternals/functions/Get-Widget.ps1') '{' }
            'wrong function name' { Set-Content (Join-Path $fixture 'XDRInternals/functions/Get-Widget.ps1') 'function Get-Other {}' }
            'no functions' { Remove-Item (Join-Path $fixture 'XDRInternals/functions/Get-Widget.ps1') }
        }
        $before = Get-OutputHashes
        Invoke-FixtureScript | Out-Null
        $fixtureExit | Should -Not -Be 0
        Get-OutputHashes | Should -Be $before
    }
    It 'propagates generator failure even when it leaves all outputs intact' {
        Set-Content (Join-Path $fixture 'build/Sync-CmdletDocumentation.ps1') 'exit 23'
        Invoke-FixtureScript 'Test-CmdletDocumentationSync.ps1' | Should -Match 'exit 23'
        $fixtureExit | Should -Not -Be 0
    }
    It 'rejects a successful generator that omits an output' {
        Add-Content (Join-Path $fixture 'build/Sync-CmdletDocumentation.ps1') "`nRemove-Item -LiteralPath (Join-Path `$repoRoot 'XDRay/CmdletApiMapping.json')"
        Invoke-FixtureScript 'Test-CmdletDocumentationSync.ps1' | Should -Match 'omitted output'
        $fixtureExit | Should -Not -Be 0
    }
    It 'copies internal catalog inputs into the verification fixture' {
        Set-Content (Join-Path $fixture 'XDRInternals/internal/catalog.txt') 'catalog input'
        Add-Content (Join-Path $fixture 'build/Sync-CmdletDocumentation.ps1') @'

if ([IO.File]::ReadAllText((Join-Path $repoRoot 'XDRInternals/internal/catalog.txt')).Trim() -ne 'catalog input') { throw 'Catalog missing' }
'@
        Invoke-FixtureScript 'Test-CmdletDocumentationSync.ps1' | Should -Match 'All four'
        $fixtureExit | Should -Be 0
    }
    It 'keeps retained intentional URIs and discriminator fields in both copies' {
        $mappings = @(
            @{Cmdlet='Get-Widget'; ApiUri='https://security.microsoft.com/intentional{Uri}'; Method='POST'; Discriminator=@{Report='catalog'}},
            @{Cmdlet='Get-Widget'; ApiUri='https://security.microsoft.com/widgets/{Id}'; Parameters=@{Name='fixed:one'}; Method='GET'; QueryMatch=@{reportId=1}; BodyMatch=@{}; ReportQueryKeys=@('reportId'); ReportBinary=$false},
            @{Cmdlet='Get-Widget'; ApiUri='https://security.microsoft.com/widgets/{Id}'; Parameters=@{Name='fixed:two'}; Method='POST'; QueryMatch=@{}; BodyMatch=@{schemaId=2}; ReportQueryKeys=@(); ReportBinary=$true}
        ) | ConvertTo-Json -Depth 10
        foreach ($output in $outputs[2..3]) { Set-Content (Join-Path $fixture $output) $mappings -Encoding utf8BOM }
        Invoke-FixtureScript | Out-Null
        $fixtureExit | Should -Be 0
        $actual = @(Get-Content (Join-Path $fixture $outputs[2]) -Raw | ConvertFrom-Json)
        $actual.Count | Should -Be 3
        ($actual | Where-Object Method -eq POST | Where-Object Discriminator).Discriminator.Report | Should -Be 'catalog'
        (Get-FileHash (Join-Path $fixture $outputs[2])).Hash | Should -Be (Get-FileHash (Join-Path $fixture $outputs[3])).Hash
        $before = Get-OutputHashes
        Invoke-FixtureScript | Out-Null
        Get-OutputHashes | Should -Be $before
    }
}
