Describe 'Passkey retained provider state' {
    InModuleScope XDRInternals {
        BeforeEach {
            $script:providerCode = $null
            $script:interrupt = $false
            $script:issueCookie = $false
            Mock Test-Path { $true } -ParameterFilter { $Path -eq '/synthetic/passkey.json' }
            Mock Get-Content { '{"username":"test@example.invalid","userHandle":"dGVzdA","credentialId":"dGVzdA","privateKey":"synthetic-key"}' } -ParameterFilter { $Path -eq '/synthetic/passkey.json' }
            Mock New-XdrPasskeySignature { @{ Signature = [byte[]]@(1,2); ClientData = [byte[]]@(3,4) } }
            Mock Start-Sleep {}
            Mock Invoke-RestMethod { throw 'Unexpected REST request' }
            Mock Invoke-WebRequest {
                if ($Uri -like '*/organizations/oauth2/v2.0/authorize*') {
                    return [pscustomobject]@{ StatusCode = 200; Content = '{"sFidoChallenge":"challenge","oGetCredTypeResult":{"FlowToken":"synthetic-flow","Credentials":{"HasFido":true,"FidoParams":{"AllowList":["test"]}}}}' }
                }
                if ($Uri -eq 'https://login.microsoft.com/common/fido/get?uiflavor=Web') {
                    return [pscustomobject]@{ StatusCode = 200; Content = '{"sFT":"synthetic-flow"}' }
                }
                if ($Uri -eq 'https://login.microsoftonline.com/common/login') {
                    return [pscustomobject]@{ StatusCode = 200; Content = '' }
                }
                if ($Uri -eq 'https://login.microsoftonline.com/common/login?sso_reload=true' -or $Uri -eq 'https://login.microsoftonline.com/kmsi') {
                    if ($script:issueCookie) {
                        $WebSession.Cookies.Add([uri]'https://login.microsoftonline.com', [System.Net.Cookie]::new('ESTSAUTH', 'synthetic-success-cookie'))
                    }
                    $state = @{ sErrorCode = $script:providerCode; sFT = 'secret-flow'; sCtx = 'secret-context'; sErrTxt = 'unsafe-provider-text'; correlationId = '11111111-1111-1111-1111-111111111111' }
                    if ($script:interrupt) { $state.pgid = 'KmsiInterrupt' }
                    return [pscustomobject]@{ StatusCode = 200; Content = ($state | ConvertTo-Json -Compress) }
                }
                throw "Unexpected synthetic request: $Uri"
            }
        }

        It 'preserves exact <ProviderCode> at <Stage>' -ForEach @(
            @{ ProviderCode = '53003'; Scenario = 'PolicyBlocked'; Action = 'reported Conditional Access requirements'; Interrupt = $false; Stage = 'ArtifactCapture' }
            @{ ProviderCode = '53000'; Scenario = 'DeviceNotCompliant'; Action = 'device marked compliant'; Interrupt = $false; Stage = 'ArtifactCapture' }
            @{ ProviderCode = '53003'; Scenario = 'PolicyBlocked'; Action = 'reported Conditional Access requirements'; Interrupt = $true; Stage = 'AssertionValidation' }
            @{ ProviderCode = '53000'; Scenario = 'DeviceNotCompliant'; Action = 'device marked compliant'; Interrupt = $true; Stage = 'AssertionValidation' }
        ) {
            $script:providerCode = $ProviderCode
            $script:interrupt = $Interrupt
            $caught = try { Invoke-XdrPasskeyAuthentication -KeyFilePath '/synthetic/passkey.json' } catch { $_ }
            $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.ConditionalAccess*'
            $metadata = $caught.Exception.Data['XdrAuthenticationFailure']
            $metadata.ProviderCode | Should -Be $ProviderCode
            $metadata.AuthenticationMethod | Should -Be 'SoftwarePasskey'
            $metadata.Stage | Should -Be $Stage
            $metadata.StatusCode | Should -Be 200
            $metadata.ConditionalAccessScenario | Should -Be $Scenario
            $metadata.Retryable | Should -BeFalse
            $metadata.CorrelationId | Should -Be '11111111-1111-1111-1111-111111111111'
            $caught.ErrorDetails.RecommendedAction | Should -Match $Action
            ($caught.ErrorDetails.Message, $caught.ErrorDetails.RecommendedAction, ($metadata | ConvertTo-Json -Depth 8)) -join "`n" | Should -Not -Match 'secret-flow|secret-context|unsafe-provider-text|synthetic-key'
            Should -Invoke Invoke-WebRequest -Times $(if ($Interrupt) { 5 } else { 4 }) -Exactly
            Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        }

        It 'retains local fallback when exact provider state is unavailable: <Code>' -ForEach @(
            @{ Interrupt = $false; Code = 'NoAuthenticationArtifact'; Retryable = $true }
            @{ Interrupt = $true; Code = 'PasskeyAssertionFailed'; Retryable = $false }
        ) {
            $script:interrupt = $Interrupt
            $caught = try { Invoke-XdrPasskeyAuthentication -KeyFilePath '/synthetic/passkey.json' } catch { $_ }
            $caught.FullyQualifiedErrorId | Should -BeLike "XdrAuthentication.$Code*"
            $caught.Exception.Data['XdrAuthenticationFailure'].Retryable | Should -Be $Retryable
        }

        It 'still returns a successful ESTS cookie' {
            $script:issueCookie = $true
            Invoke-XdrPasskeyAuthentication -KeyFilePath '/synthetic/passkey.json' | Should -Be 'synthetic-success-cookie'
        }
    }
}
