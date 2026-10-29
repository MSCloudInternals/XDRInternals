Describe 'Kustainer local example exposure' {
    BeforeAll {
        $script:ExportGuide = Get-Content (Join-Path $PSScriptRoot '../../docs/export-functions.md') -Raw
    }
    It 'binds every documented local Docker example to loopback' {
        $commands = @($script:ExportGuide -split "`n" | Where-Object { $_ -match '^docker run .*kustainer' })
        $commands | Should -HaveCount 1
        foreach ($command in $commands) {
            $command | Should -Match '(?:^|\s)-p\s+127\.0\.0\.1:8080:8080(?:\s|$)'
            $command | Should -Not -Match '(?:^|\s)-p\s+8080:8080(?:\s|$)'
        }
    }
    It 'states that remote access needs access control and TLS is not authentication' {
        $script:ExportGuide | Should -Match 'does not authenticate'
        $script:ExportGuide | Should -Match 'access-controlled proxy'
        $script:ExportGuide | Should -Match 'TLS alone does not authenticate'
    }
}
