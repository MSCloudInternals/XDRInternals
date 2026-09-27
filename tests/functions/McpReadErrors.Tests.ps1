Describe 'MCP read error boundaries' {
    BeforeAll {
        $hostPath = Join-Path $PSScriptRoot '../../mcp/bridge/ReadOnlyHost.ps1'
        $hostAst = [System.Management.Automation.Language.Parser]::ParseFile($hostPath, [ref]$null, [ref]$null)
        $classifier = $hostAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-UpstreamErrorCode'
            }, $false)
        . ([scriptblock]::Create($classifier.Extent.Text))
    }

    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache { throw 'Failed reads must not populate the cache' } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$global:__pester_data.McpHttpStatus)
            $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Request for incident 401 failed.', $response)
            $failure = [System.Management.Automation.ErrorRecord]::new($exception, 'SyntheticHttpFailure', 'InvalidOperation', $null)
            $failure.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":"Access denied"}')
            throw $failure
        } -ModuleName XDRInternals
    }

    It 'preserves HTTP status through the real <Name> read' -TestCases @(
        @{ Name = 'incident list'; Command = 'Get-XdrIncident'; Arguments = @{ LookBackInDays = 7; PageIndex = 1; PageSize = 1 } }
        @{ Name = 'incident detail'; Command = 'Get-XdrIncident'; Arguments = @{ IncidentId = 401 } }
        @{ Name = 'incident alerts'; Command = 'Get-XdrIncidentAssociatedAlert'; Arguments = @{ IncidentId = 401; PageIndex = 1; PageSize = 1 } }
        @{ Name = 'alert list'; Command = 'Get-XdrAlert'; Arguments = @{ DaysAgo = 7; PageNumber = 1; PageSize = 1 } }
        @{ Name = 'device list'; Command = 'Get-XdrEndpointDevice'; Arguments = @{ PageIndex = 1; PageSize = 1 } }
        @{ Name = 'device detail'; Command = 'Get-XdrEndpointDevice'; Arguments = @{ DeviceId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } }
        @{ Name = 'identity list'; Command = 'Get-XdrIdentityIdentity'; Arguments = @{ PageSize = 1; Skip = 0 } }
        @{ Name = 'identity detail'; Command = 'Get-XdrIdentityUser'; Arguments = @{ Upn = 'analyst@example.test'; ResolveOnly = $true } }
        @{ Name = 'pending actions'; Command = 'Get-XdrActionsCenterPending'; Arguments = @{ PageIndex = 1; PageSize = 1 } }
        @{ Name = 'action history'; Command = 'Get-XdrActionsCenterHistory'; Arguments = @{ Months = 1; PageIndex = 1; PageSize = 1 } }
        @{ Name = 'cloud policies'; Command = 'Get-XdrCloudAppsPolicy'; Arguments = @{ Limit = 1; Skip = 0 } }
    ) {
        param($Name, $Command, $Arguments)

        foreach ($statusCode in @(401, 403, 404, 500)) {
            $global:__pester_data.McpHttpStatus = $statusCode
            $failure = $null
            try { & $Command @Arguments -ErrorAction Stop } catch { $failure = $_ }

            $failure | Should -Not -BeNullOrEmpty
            $expected = switch ($statusCode) {
                401 { 'not_connected' }
                403 { 'not_connected' }
                404 { 'not_found' }
                500 { 'upstream_failed' }
            }
            Get-UpstreamErrorCode $failure | Should -Be $expected
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }

    It 'maps an empty identity resolve result to not_found' {
        Mock Invoke-RestMethod { [pscustomobject]@{ results = $null } } -ModuleName XDRInternals
        $failure = $null
        try { Get-XdrIdentityUser -Upn 'missing@example.test' -ResolveOnly -ErrorAction Stop } catch { $failure = $_ }

        $failure | Should -Not -BeNullOrEmpty
        Get-UpstreamErrorCode $failure | Should -Be 'not_found'
    }
}