Describe 'Disconnect-Xdr' {
    BeforeEach {
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{ 'X-XSRF-TOKEN' = 'xsrf-secret' }
            $script:XdrCacheStore = @{ cached = 'tenant-data' }
            $script:AzureDataExplorerConnection = [pscustomobject]@{ AccessToken = 'adx-secret' }
            $script:SentinelWorkspaceId = 'workspace-id'
            $script:SentinelSharedKey = 'sentinel-secret'
            $script:SentinelDceEndpoint = 'https://unused.example'
            $script:LiveResponseSession = [pscustomobject]@{ SessionId = 'CLR-test' }
            $script:XdrBaseUrl = 'https://security.microsoft.com'
            $script:responseMetadata = @{ total = 1 }
        }
    }

    It 'clears authentication credentials and related module state' {
        Disconnect-Xdr -Confirm:$false

        InModuleScope XDRInternals {
            $script:session | Should -BeNullOrEmpty
            $script:headers | Should -BeNullOrEmpty
            $script:XdrCacheStore | Should -BeNullOrEmpty
            $script:AzureDataExplorerConnection | Should -BeNullOrEmpty
            $script:SentinelWorkspaceId | Should -BeNullOrEmpty
            $script:SentinelSharedKey | Should -BeNullOrEmpty
            $script:SentinelDceEndpoint | Should -BeNullOrEmpty
            $script:LiveResponseSession | Should -BeNullOrEmpty
            $script:XdrBaseUrl | Should -BeNullOrEmpty
            $script:responseMetadata | Should -BeNullOrEmpty
        }
    }

    It 'honors WhatIf without clearing the session' {
        Disconnect-Xdr -WhatIf

        InModuleScope XDRInternals {
            Test-Path variable:script:session | Should -BeTrue
            $script:headers['X-XSRF-TOKEN'] | Should -Be 'xsrf-secret'
            $script:SentinelSharedKey | Should -Be 'sentinel-secret'
            $script:AzureDataExplorerConnection.AccessToken | Should -Be 'adx-secret'
        }
    }
}

Describe 'Connection credential lifecycle helpers' {
    It 'converts an Az SecureString token for immediate use' {
        Mock Get-AzAccessToken {
            $secureToken = [System.Security.SecureString]::new()
            foreach ($character in 'az-token-value'.ToCharArray()) {
                $secureToken.AppendChar($character)
            }
            $secureToken.MakeReadOnly()

            [pscustomobject]@{
                Token = $secureToken
            }
        } -ModuleName XDRInternals

        InModuleScope XDRInternals {
            Invoke-XdrAzAccessTokenRequest -Resource 'https://management.azure.com/' | Should -Be 'az-token-value'
        }
    }

    It 'rejects the unimplemented Sentinel DCE option without changing connection state' {
        InModuleScope XDRInternals {
            $script:SentinelWorkspaceId = 'existing-workspace'
            $script:SentinelSharedKey = 'existing-key'
            $script:SentinelDceEndpoint = $null

            {
                Set-XdrSentinelConnection -WorkspaceId 'replacement-workspace' -SharedKey 'replacement-key' -DceEndpoint 'https://example.ingest.monitor.azure.com' -Confirm:$false
            } | Should -Throw '*DCE ingestion is not implemented*'

            $script:SentinelWorkspaceId | Should -Be 'existing-workspace'
            $script:SentinelSharedKey | Should -Be 'existing-key'
            $script:SentinelDceEndpoint | Should -BeNullOrEmpty
        }
    }
}
