Describe 'Direct ESTS cookie final bootstrap errors' {
    InModuleScope XDRInternals {
        BeforeEach {
            Mock Write-Host {}
            Mock Clear-XdrCache {}
            Mock Invoke-WebRequest {
                if ($Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/') {
                    return [pscustomobject]@{ InputFields = @('code','id_token','state','session_state','correlation_id') | ForEach-Object { [pscustomobject]@{ name = $_; value = 'synthetic-exchange-value' } }; Content = ''; StatusCode = 200 }
                }
                return [pscustomobject]@{ StatusCode = 200 }
            }
            Mock Invoke-RestMethod { throw 'Unexpected REST request' }
        }

        It 'normalizes session setup HTTP <Status> after successful code exchange' -ForEach @(
            @{ Status = 401; Code = 'ProviderRejected'; Retryable = $false; Category = 'AuthenticationError' }
            @{ Status = 403; Code = 'ProviderRejected'; Retryable = $false; Category = 'AuthenticationError' }
            @{ Status = 503; Code = 'ProviderUnavailable'; Retryable = $true; Category = 'ResourceUnavailable' }
        ) {
            $script:native = [System.Exception]::new('unsafe-native-message cookie=secret-cookie')
            $script:native | Add-Member NoteProperty Response ([pscustomobject]@{ StatusCode = $Status })
            Mock Set-XdrConnectionSettings { throw $script:native }
            $caught = try { Connect-XdrByEstsCookie -EstsAuthCookieValue 'synthetic-cookie' } catch { $_ }
            $caught.FullyQualifiedErrorId | Should -BeLike "XdrAuthentication.$Code*"
            $caught.CategoryInfo.Category | Should -Be $Category
            [object]::ReferenceEquals($caught.Exception.InnerException, $script:native) | Should -BeTrue
            $metadata = $caught.Exception.Data['XdrAuthenticationFailure']
            $metadata.Code | Should -Be $Code
            $metadata.Stage | Should -Be 'PortalBootstrap'
            $metadata.AuthenticationMethod | Should -Be 'EstsCookie'
            $metadata.Retryable | Should -Be $Retryable
            $metadata.StatusCode | Should -Be $Status
            $caught.ErrorDetails.RecommendedAction | Should -Not -BeNullOrEmpty
            ($caught.ErrorDetails.Message, $caught.ErrorDetails.RecommendedAction, ($metadata | ConvertTo-Json -Depth 8)) -join "`n" | Should -Not -Match 'unsafe-native-message|secret-cookie|synthetic-exchange-value'
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'Post' -and $Body.code -eq 'synthetic-exchange-value' }
            Should -Invoke Set-XdrConnectionSettings -Times 1 -Exactly
            Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        }

        It 'preserves an already normalized session setup error' {
            $failure = Get-XdrAuthenticationFailure -AuthState ([pscustomobject]@{ sErrorCode = '53000' }) -AuthenticationMethod EstsCookie -Stage TenantContext
            $script:normalized = New-XdrAuthenticationErrorRecord -Failure $failure
            Mock Set-XdrConnectionSettings { throw $script:normalized }
            $caught = try { Connect-XdrByEstsCookie -EstsAuthCookieValue 'synthetic-cookie' } catch { $_ }
            [object]::ReferenceEquals($caught.Exception, $script:normalized.Exception) | Should -BeTrue
            $caught.ErrorDetails.Message | Should -Be $script:normalized.ErrorDetails.Message
            $caught.ErrorDetails.RecommendedAction | Should -Be $script:normalized.ErrorDetails.RecommendedAction
            $caught.Exception.Data['XdrAuthenticationFailure'].Stage | Should -Be 'TenantContext'
            $caught.Exception.Data['XdrAuthenticationFailure'].ConditionalAccessScenario | Should -Be 'DeviceNotCompliant'
            $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.ConditionalAccess*'
        }
    }
}
