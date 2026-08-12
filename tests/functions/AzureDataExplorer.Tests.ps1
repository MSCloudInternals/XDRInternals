Describe 'Azure Data Explorer export' {
    BeforeAll {
        Import-Module "$global:testroot\..\XDRInternals\XDRInternals.psd1" -Force
    }

    Describe 'Set-XdrAzureDataExplorerConnection' {
        It 'derives the ingestion endpoint from the cluster URI' {
            InModuleScope XDRInternals {
                Set-XdrAzureDataExplorerConnection -ClusterUri 'https://contoso.westeurope.kusto.windows.net' -Database 'Investigations'

                $connection = Get-XdrAzureDataExplorerConnection
                $connection.ClusterUri.AbsoluteUri | Should -Be 'https://contoso.westeurope.kusto.windows.net/'
                $connection.IngestionUri.AbsoluteUri | Should -Be 'https://ingest-contoso.westeurope.kusto.windows.net/'
                $connection.Database | Should -Be 'Investigations'
            }
        }

        It 'rejects non-HTTPS Azure Data Explorer endpoints before storing credentials' {
            InModuleScope XDRInternals {
                {
                    Set-XdrAzureDataExplorerConnection -ClusterUri 'http://contoso.westeurope.kusto.windows.net' -Database 'Investigations' -Confirm:$false
                } | Should -Throw '*must use HTTPS*'
            }
        }

        It 'rejects non-Azure Data Explorer hosts before storing credentials' {
            InModuleScope XDRInternals {
                {
                    Set-XdrAzureDataExplorerConnection -ClusterUri 'https://attacker.example' -Database 'Investigations' -AccessToken 'token' -Confirm:$false
                } | Should -Throw '*trusted Azure Data Explorer service host*'
            }
        }

        It 'discovers clusters and prompts for cluster selection when multiple matches are available' {
            $script:adxSelections = @('2')
            $script:adxSelectionIndex = 0

            Mock Write-Information {} -ModuleName XDRInternals
            Mock Read-Host {
                $response = $script:adxSelections[$script:adxSelectionIndex]
                $script:adxSelectionIndex++
                return $response
            } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'nm-test-cluster'
                        ClusterUri        = 'https://nm-test-cluster.westus2.kusto.windows.net'
                        IngestionUri      = 'https://ingest-nm-test-cluster.westus2.kusto.windows.net'
                        SubscriptionId    = 'sub-1'
                        SubscriptionName  = 'Lab Subscription'
                        Location          = 'westus2'
                        SkuTier           = 'Basic'
                        ProvisioningState = 'Succeeded'
                        State             = 'Running'
                        Databases         = @(
                            [pscustomobject]@{
                                DatabaseName = 'Investigations'
                                Kind         = 'ReadWrite'
                            }
                        )
                    },
                    [pscustomobject]@{
                        ClusterName       = 'MyFreeCluster'
                        ClusterUri        = 'https://kvc-2fjns59p9bjfxt1f1f.southcentralus.kusto.windows.net'
                        IngestionUri      = 'https://ingest-kvc-2fjns59p9bjfxt1f1f.southcentralus.kusto.windows.net'
                        TenantId          = 'tenant-free'
                        SubscriptionId    = $null
                        SubscriptionName  = $null
                        Location          = 'southcentralus'
                        SkuTier           = 'Free'
                        ProvisioningState = 'Running'
                        State             = 'Running'
                        Databases         = @(
                            [pscustomobject]@{
                                DatabaseName = 'MyDatabase'
                                Kind         = 'ReadWrite'
                            }
                        )
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Set-XdrAzureDataExplorerConnection

                $connection = Get-XdrAzureDataExplorerConnection
                $connection.ClusterUri.AbsoluteUri | Should -Be 'https://kvc-2fjns59p9bjfxt1f1f.southcentralus.kusto.windows.net/'
                $connection.IngestionUri.AbsoluteUri | Should -Be 'https://ingest-kvc-2fjns59p9bjfxt1f1f.southcentralus.kusto.windows.net/'
                $connection.Database | Should -Be 'MyDatabase'
                $connection.TenantId | Should -Be 'tenant-free'
            }

            Should -Invoke Get-XdrAzureDataExplorerCluster -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $IncludeDatabases -eq $true
            }

            Should -Invoke Read-Host -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Prompt -eq 'Select cluster [1-2]'
            }
        }

        It 'prompts for database selection when the chosen cluster has multiple databases' {
            Mock Write-Information {} -ModuleName XDRInternals
            Mock Read-Host { '2' } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'nm-test-cluster'
                        ClusterUri        = 'https://nm-test-cluster.westus2.kusto.windows.net'
                        IngestionUri      = 'https://ingest-nm-test-cluster.westus2.kusto.windows.net'
                        SubscriptionId    = 'sub-1'
                        SubscriptionName  = 'Lab Subscription'
                        Location          = 'westus2'
                        SkuTier           = 'Basic'
                        ProvisioningState = 'Succeeded'
                        State             = 'Running'
                        Databases         = @(
                            [pscustomobject]@{
                                DatabaseName = 'Investigations'
                                Kind         = 'ReadWrite'
                            },
                            [pscustomobject]@{
                                DatabaseName = 'Sandbox'
                                Kind         = 'ReadWrite'
                            }
                        )
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Set-XdrAzureDataExplorerConnection

                $connection = Get-XdrAzureDataExplorerConnection
                $connection.ClusterUri.AbsoluteUri | Should -Be 'https://nm-test-cluster.westus2.kusto.windows.net/'
                $connection.Database | Should -Be 'Sandbox'
            }

            Should -Invoke Read-Host -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Prompt -eq 'Select database [1-2]'
            }
        }

        It 'throws in non-interactive mode when multiple clusters match discovery' {
            Mock Write-Information {} -ModuleName XDRInternals
            Mock Read-Host { throw 'Read-Host should not be called in non-interactive mode.' } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'nm-test-cluster'
                        ClusterUri        = 'https://nm-test-cluster.westus2.kusto.windows.net'
                        IngestionUri      = 'https://ingest-nm-test-cluster.westus2.kusto.windows.net'
                        SubscriptionId    = 'sub-1'
                        SubscriptionName  = 'Lab Subscription'
                        Location          = 'westus2'
                        SkuTier           = 'Basic'
                        ProvisioningState = 'Succeeded'
                        State             = 'Running'
                        Databases         = @(
                            [pscustomobject]@{
                                DatabaseName = 'Investigations'
                                Kind         = 'ReadWrite'
                            }
                        )
                    },
                    [pscustomobject]@{
                        ClusterName       = 'MyFreeCluster'
                        ClusterUri        = 'https://kvc-2fjns59p9bjfxt1f1f.southcentralus.kusto.windows.net'
                        IngestionUri      = 'https://ingest-kvc-2fjns59p9bjfxt1f1f.southcentralus.kusto.windows.net'
                        SubscriptionId    = $null
                        SubscriptionName  = $null
                        Location          = 'southcentralus'
                        SkuTier           = 'Free'
                        ProvisioningState = 'Running'
                        State             = 'Running'
                        Databases         = @(
                            [pscustomobject]@{
                                DatabaseName = 'MyDatabase'
                                Kind         = 'ReadWrite'
                            }
                        )
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                {
                    Set-XdrAzureDataExplorerConnection -NonInteractive
                } | Should -Throw '*Multiple Azure Data Explorer clusters matched the requested discovery criteria in non-interactive mode*'
            }

            Should -Invoke Read-Host -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'throws in non-interactive mode when multiple databases are discovered for one cluster' {
            Mock Write-Information {} -ModuleName XDRInternals
            Mock Read-Host { throw 'Read-Host should not be called in non-interactive mode.' } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'nm-test-cluster'
                        ClusterUri        = 'https://nm-test-cluster.westus2.kusto.windows.net'
                        IngestionUri      = 'https://ingest-nm-test-cluster.westus2.kusto.windows.net'
                        SubscriptionId    = 'sub-1'
                        SubscriptionName  = 'Lab Subscription'
                        Location          = 'westus2'
                        SkuTier           = 'Basic'
                        ProvisioningState = 'Succeeded'
                        State             = 'Running'
                        Databases         = @(
                            [pscustomobject]@{
                                DatabaseName = 'Investigations'
                                Kind         = 'ReadWrite'
                            },
                            [pscustomobject]@{
                                DatabaseName = 'Sandbox'
                                Kind         = 'ReadWrite'
                            }
                        )
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                {
                    Set-XdrAzureDataExplorerConnection -NonInteractive
                } | Should -Throw '*Multiple databases were discovered for cluster ''nm-test-cluster'' in non-interactive mode*'
            }

            Should -Invoke Read-Host -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'does not prompt in non-interactive mode when discovery resolves to one cluster and one database' {
            Mock Write-Information {} -ModuleName XDRInternals
            Mock Read-Host { throw 'Read-Host should not be called in non-interactive mode.' } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'nm-test-cluster'
                        ClusterUri        = 'https://nm-test-cluster.westus2.kusto.windows.net'
                        IngestionUri      = 'https://ingest-nm-test-cluster.westus2.kusto.windows.net'
                        TenantId          = 'tenant-selected'
                        SubscriptionId    = 'sub-1'
                        SubscriptionName  = 'Lab Subscription'
                        Location          = 'westus2'
                        SkuTier           = 'Basic'
                        ProvisioningState = 'Succeeded'
                        State             = 'Running'
                        Databases         = @(
                            [pscustomobject]@{
                                DatabaseName = 'Investigations'
                                Kind         = 'ReadWrite'
                            }
                        )
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Set-XdrAzureDataExplorerConnection -NonInteractive

                $connection = Get-XdrAzureDataExplorerConnection
                $connection.ClusterUri.AbsoluteUri | Should -Be 'https://nm-test-cluster.westus2.kusto.windows.net/'
                $connection.Database | Should -Be 'Investigations'
                $connection.TenantId | Should -Be 'tenant-selected'
            }

            Should -Invoke Read-Host -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'does not allow discovery mode to reuse the explicit data-plane access token parameter' {
            {
                Set-XdrAzureDataExplorerConnection -ClusterName 'nm-test-cluster' -AccessToken 'token'
            } | Should -Throw '*Parameter set cannot be resolved*'
        }

        It 'throws when the selected cluster has no discovered databases' {
            Mock Write-Information {} -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'nm-test-cluster'
                        ClusterUri        = 'https://nm-test-cluster.westus2.kusto.windows.net'
                        IngestionUri      = 'https://ingest-nm-test-cluster.westus2.kusto.windows.net'
                        SubscriptionId    = 'sub-1'
                        SubscriptionName  = 'Lab Subscription'
                        Location          = 'westus2'
                        SkuTier           = 'Basic'
                        ProvisioningState = 'Creating'
                        State             = 'Running'
                        Databases         = @()
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                {
                    Set-XdrAzureDataExplorerConnection
                } | Should -Throw '*No databases were discovered for cluster ''nm-test-cluster''*ProvisioningState=Creating*'
            }
        }

        It 'fails closed when automatic discovery is incomplete' {
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'MyFreeCluster'
                        ClusterUri        = 'https://free.kusto.windows.net'
                        IngestionUri      = 'https://ingest-free.kusto.windows.net'
                        ProvisioningState = 'Running'
                        State             = 'Running'
                        Databases         = @([pscustomobject]@{ DatabaseName = 'MyDatabase'; Kind = 'ReadWrite' })
                        DiscoveryStatus   = [pscustomobject]@{
                            IsComplete = $false
                            Failures   = @([pscustomobject]@{
                                    Provider = 'AzureResourceManager'
                                    Scope    = 'Subscription discovery'
                                    Message  = 'ARM unavailable'
                                })
                        }
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                {
                    Set-XdrAzureDataExplorerConnection -NonInteractive
                } | Should -Throw '*connection discovery was incomplete*ARM unavailable*AllowPartialDiscovery*'
            }
        }

        It 'allows explicit opt-in to select from partial discovery results' {
            Mock Get-XdrAzureDataExplorerCluster {
                @(
                    [pscustomobject]@{
                        ClusterName       = 'MyFreeCluster'
                        ClusterUri        = 'https://free.kusto.windows.net'
                        IngestionUri      = 'https://ingest-free.kusto.windows.net'
                        TenantId          = 'tenant-free'
                        ProvisioningState = 'Running'
                        State             = 'Running'
                        Databases         = @([pscustomobject]@{ DatabaseName = 'MyDatabase'; Kind = 'ReadWrite' })
                        DiscoveryStatus   = [pscustomobject]@{
                            IsComplete = $false
                            Failures   = @([pscustomobject]@{
                                    Provider = 'AzureResourceManager'
                                    Scope    = 'Subscription discovery'
                                    Message  = 'ARM unavailable'
                                })
                        }
                    }
                )
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Set-XdrAzureDataExplorerConnection -NonInteractive -AllowPartialDiscovery

                $connection = Get-XdrAzureDataExplorerConnection
                $connection.ClusterUri.AbsoluteUri | Should -Be 'https://free.kusto.windows.net/'
                $connection.Database | Should -Be 'MyDatabase'
            }
        }

        It 'does not perform discovery when WhatIf is used in discover mode' {
            Mock Resolve-XdrAzureDataExplorerDiscoveredConnection {
                throw 'Discovery should not run under WhatIf'
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Set-XdrAzureDataExplorerConnection -WhatIf
            }

            Should -Invoke Resolve-XdrAzureDataExplorerDiscoveredConnection -ModuleName XDRInternals -Times 0 -Exactly
        }
    }

    Describe 'Get-XdrAzureDataExplorerCluster' {
        It 'enumerates subscriptions, clusters, and databases through Azure Resource Manager' {
            Mock Get-XdrAzureAccessToken { 'arm-token' } -ModuleName XDRInternals
            Mock Invoke-XdrAzureDataExplorerRestRequest { @() } -ModuleName XDRInternals
            Mock Get-XdrAzureResourceManagerCollection {
                switch ($Path) {
                    '/subscriptions?api-version=2022-12-01' {
                        @(
                            [pscustomobject]@{
                                subscriptionId = 'sub-1'
                                displayName    = 'Lab Subscription'
                                tenantId       = 'tenant-1'
                            }
                        )
                    }
                    '/subscriptions/sub-1/providers/Microsoft.Kusto/clusters?api-version=2024-04-13' {
                        @(
                            [pscustomobject]@{
                                id         = '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/labcluster'
                                name       = 'labcluster'
                                location   = 'southcentralus'
                                sku        = [pscustomobject]@{
                                    name = 'Dev(No SLA)_Standard_D11_v2'
                                    tier = 'Standard'
                                }
                                properties = [pscustomobject]@{
                                    uri               = 'https://labcluster.southcentralus.kusto.windows.net'
                                    dataIngestionUri  = 'https://ingest-labcluster.southcentralus.kusto.windows.net'
                                    state             = 'Running'
                                    provisioningState = 'Succeeded'
                                }
                            }
                        )
                    }
                    '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/labcluster/databases?api-version=2024-04-13' {
                        @(
                            [pscustomobject]@{
                                id         = '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/labcluster/databases/Investigations'
                                name       = 'labcluster/Investigations'
                                kind       = 'ReadWrite'
                                location   = 'southcentralus'
                                properties = [pscustomobject]@{
                                    provisioningState = 'Succeeded'
                                    softDeletePeriod  = 'P365D'
                                    hotCachePeriod    = 'P31D'
                                }
                            }
                        )
                    }
                    default {
                        throw "Unexpected ARM collection path: $Path"
                    }
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = @(Get-XdrAzureDataExplorerCluster -IncludeDatabases -RequestTimeout 123 -WarningVariable discoveryWarnings)

                $result.Count | Should -Be 1
                $result[0].ClusterName | Should -Be 'labcluster'
                $result[0].SubscriptionName | Should -Be 'Lab Subscription'
                $result[0].IngestionUri | Should -Be 'https://ingest-labcluster.southcentralus.kusto.windows.net'
                @($result[0].Databases).Count | Should -Be 1
                $result[0].Databases[0].DatabaseName | Should -Be 'Investigations'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://management.azure.com/' -and
                $TenantId -eq 'tenant-1'
            }
        }

        It 'acquires tenant-specific ARM tokens for discovered subscriptions in other tenants' {
            Mock Get-XdrCache {
                [pscustomobject]@{
                    Value = 'tenant-home'
                }
            } -ModuleName XDRInternals -ParameterFilter {
                $CacheKey -eq 'XdrTenantId'
            }
            Mock Get-XdrAzureAccessToken { 'arm-token' } -ModuleName XDRInternals
            Mock Invoke-XdrAzureDataExplorerRestRequest { @() } -ModuleName XDRInternals
            Mock Get-XdrAzureResourceManagerCollection {
                switch ($Path) {
                    '/subscriptions?api-version=2022-12-01' {
                        @(
                            [pscustomobject]@{
                                subscriptionId = 'sub-guest'
                                displayName    = 'Guest Subscription'
                                tenantId       = 'tenant-guest'
                            }
                        )
                    }
                    '/subscriptions/sub-guest/providers/Microsoft.Kusto/clusters?api-version=2024-04-13' {
                        @(
                            [pscustomobject]@{
                                id         = '/subscriptions/sub-guest/resourceGroups/rg-guest/providers/Microsoft.Kusto/clusters/guestcluster'
                                name       = 'guestcluster'
                                location   = 'eastus2'
                                sku        = [pscustomobject]@{
                                    name = 'Standard'
                                    tier = 'Standard'
                                }
                                properties = [pscustomobject]@{
                                    uri               = 'https://guestcluster.eastus2.kusto.windows.net'
                                    dataIngestionUri  = 'https://ingest-guestcluster.eastus2.kusto.windows.net'
                                    state             = 'Running'
                                    provisioningState = 'Succeeded'
                                }
                            }
                        )
                    }
                    default {
                        throw "Unexpected ARM collection path: $Path"
                    }
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = @(Get-XdrAzureDataExplorerCluster)

                $result.Count | Should -Be 1
                $result[0].SubscriptionId | Should -Be 'sub-guest'
                $result[0].TenantId | Should -Be 'tenant-guest'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://management.azure.com/' -and
                $TenantId -eq 'tenant-home'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://management.azure.com/' -and
                $TenantId -eq 'tenant-guest'
            }
        }

        It 'can query an explicit subscription list without calling the subscription discovery endpoint' {
            Mock Get-XdrAzureAccessToken { 'arm-token' } -ModuleName XDRInternals
            Mock Get-XdrCache {
                [pscustomobject]@{
                    Value = 'tenant-from-cache'
                }
            } -ModuleName XDRInternals -ParameterFilter {
                $CacheKey -eq 'XdrTenantId'
            }
            Mock Invoke-XdrAzureDataExplorerRestRequest { @() } -ModuleName XDRInternals
            Mock Invoke-XdrAzureResourceManagerRequest {
                [pscustomobject]@{
                    subscriptionId = 'sub-2'
                    displayName    = 'App Subscription'
                    tenantId       = 'tenant-2'
                    state          = 'Enabled'
                }
            } -ModuleName XDRInternals
            Mock Get-XdrAzureResourceManagerCollection {
                switch ($Path) {
                    '/subscriptions/sub-2/providers/Microsoft.Kusto/clusters?api-version=2024-04-13' {
                        @(
                            [pscustomobject]@{
                                id         = '/subscriptions/sub-2/resourceGroups/rg-app/providers/Microsoft.Kusto/clusters/appcluster'
                                name       = 'appcluster'
                                location   = 'eastus'
                                sku        = [pscustomobject]@{
                                    name = 'Standard'
                                    tier = 'Standard'
                                }
                                properties = [pscustomobject]@{
                                    uri               = 'https://appcluster.eastus.kusto.windows.net'
                                    dataIngestionUri  = 'https://ingest-appcluster.eastus.kusto.windows.net'
                                    state             = 'Running'
                                    provisioningState = 'Succeeded'
                                }
                            }
                        )
                    }
                    default {
                        throw "Unexpected ARM collection path: $Path"
                    }
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = @(Get-XdrAzureDataExplorerCluster -SubscriptionId 'sub-2')

                $result.Count | Should -Be 1
                $result[0].SubscriptionId | Should -Be 'sub-2'
                $result[0].ClusterName | Should -Be 'appcluster'
                $result[0].TenantId | Should -Be 'tenant-2'
                $result[0].DiscoveryStatus.IsComplete | Should -BeTrue
                $result[0].DiscoveryStatus.Failures | Should -BeNullOrEmpty
            }

            Should -Invoke Get-XdrAzureResourceManagerCollection -ModuleName XDRInternals -Times 0 -Exactly -ParameterFilter {
                $Path -eq '/subscriptions?api-version=2022-12-01'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://management.azure.com/' -and
                $TenantId -eq 'tenant-from-cache'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://management.azure.com/' -and
                $TenantId -eq 'tenant-2'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 0 -Exactly -ParameterFilter {
                $Resource -eq 'https://help.kusto.windows.net'
            }
        }

        It 'filters databases by name and skips clusters without matches' {
            Mock Get-XdrAzureAccessToken { 'arm-token' } -ModuleName XDRInternals
            Mock Invoke-XdrAzureDataExplorerRestRequest { @() } -ModuleName XDRInternals
            Mock Get-XdrAzureResourceManagerCollection {
                switch ($Path) {
                    '/subscriptions?api-version=2022-12-01' {
                        @(
                            [pscustomobject]@{
                                subscriptionId = 'sub-1'
                                displayName    = 'Lab Subscription'
                                tenantId       = 'tenant-1'
                            }
                        )
                    }
                    '/subscriptions/sub-1/providers/Microsoft.Kusto/clusters?api-version=2024-04-13' {
                        @(
                            [pscustomobject]@{
                                id         = '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/labcluster'
                                name       = 'labcluster'
                                location   = 'southcentralus'
                                sku        = [pscustomobject]@{
                                    name = 'Standard'
                                    tier = 'Standard'
                                }
                                properties = [pscustomobject]@{
                                    uri               = 'https://labcluster.southcentralus.kusto.windows.net'
                                    dataIngestionUri  = 'https://ingest-labcluster.southcentralus.kusto.windows.net'
                                    state             = 'Running'
                                    provisioningState = 'Succeeded'
                                }
                            }
                        )
                    }
                    '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/labcluster/databases?api-version=2024-04-13' {
                        @(
                            [pscustomobject]@{
                                id         = '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/labcluster/databases/Scratch'
                                name       = 'Scratch'
                                kind       = 'ReadWrite'
                                location   = 'southcentralus'
                                properties = [pscustomobject]@{
                                    provisioningState = 'Succeeded'
                                    softDeletePeriod  = 'P365D'
                                    hotCachePeriod    = 'P31D'
                                }
                            }
                        )
                    }
                    default {
                        throw "Unexpected ARM collection path: $Path"
                    }
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = @(Get-XdrAzureDataExplorerCluster -DatabaseName 'Investigations')
                $result | Should -BeNullOrEmpty
            }
        }

        It 'includes free clusters even when Azure Resource Manager discovery is unavailable' {
            Mock Get-XdrAzureAccessToken {
                switch ($Resource) {
                    'https://management.azure.com/' {
                        throw 'ARM auth unavailable'
                    }
                    'https://help.kusto.windows.net' {
                        'free-cluster-token'
                    }
                    'https://kusto.kusto.windows.net' {
                        'free-cluster-data-token'
                    }
                    default {
                        throw "Unexpected token resource: $Resource"
                    }
                }
            } -ModuleName XDRInternals
            Mock Get-XdrCache {
                [pscustomobject]@{
                    Value = 'tenant-from-cache'
                }
            } -ModuleName XDRInternals -ParameterFilter {
                $CacheKey -eq 'XdrTenantId'
            }

            Mock Invoke-XdrAzureDataExplorerRestRequest {
                if ($BaseUri.AbsoluteUri -eq 'https://saasrp.kusto.windows.net/' -and $Path -eq '/v1/rest/SaasRp/clusters') {
                    return @(
                        [pscustomobject]@{
                            id                 = 'kvc-f1csubt6echz7s8ark'
                            engineUrl          = 'https://kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net'
                            dmUrl              = 'https://ingest-kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net'
                            state              = 'Running'
                            region             = 'southcentralus'
                            defaultDisplayName = 'MyFreeCluster'
                            databaseCount      = 1
                            graduation         = $null
                        }
                    )
                }

                if ($BaseUri.AbsoluteUri -eq 'https://kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net/' -and $Path -eq '/v1/rest/mgmt') {
                    return [pscustomobject]@{
                        Tables = @(
                            [pscustomobject]@{
                                TableName = 'Table_0'
                                Columns   = @(
                                    [pscustomobject]@{ ColumnName = 'DatabaseName' },
                                    [pscustomobject]@{ ColumnName = 'DatabaseAccessMode' }
                                )
                                Rows      = @(
                                    , @('MyDatabase', 'ReadWrite')
                                )
                            }
                        )
                    }
                }

                throw "Unexpected Azure Data Explorer REST request: $($BaseUri.AbsoluteUri)$Path"
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = @(Get-XdrAzureDataExplorerCluster -IncludeDatabases -RequestTimeout 123 -WarningVariable discoveryWarnings)

                $result.Count | Should -Be 1
                $result[0].ClusterName | Should -Be 'MyFreeCluster'
                $result[0].ClusterUri | Should -Be 'https://kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net'
                $result[0].IngestionUri | Should -Be 'https://ingest-kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net'
                $result[0].Location | Should -Be 'southcentralus'
                $result[0].TenantId | Should -Be 'tenant-from-cache'
                @($result[0].Databases).Count | Should -Be 1
                $result[0].Databases[0].DatabaseName | Should -Be 'MyDatabase'
                $result[0].Databases[0].Kind | Should -Be 'ReadWrite'
                $result[0].DiscoveryStatus.IsComplete | Should -BeFalse
                $result[0].DiscoveryStatus.Failures | Should -HaveCount 1
                $result[0].DiscoveryStatus.Failures[0].Provider | Should -Be 'AzureResourceManager'
                @($discoveryWarnings) | Should -HaveCount 1
                @($discoveryWarnings)[0].Message | Should -BeLike '*discovery returned partial results*ARM auth unavailable*'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://help.kusto.windows.net' -and
                $TenantId -eq 'tenant-from-cache'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://kusto.kusto.windows.net' -and
                $TenantId -eq 'tenant-from-cache'
            }

            Should -Invoke Invoke-XdrAzureDataExplorerRestRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $BaseUri.AbsoluteUri -eq 'https://saasrp.kusto.windows.net/' -and
                $Path -eq '/v1/rest/SaasRp/clusters' -and
                $TimeoutSec -eq 123
            }

            Should -Invoke Invoke-XdrAzureDataExplorerRestRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $BaseUri.AbsoluteUri -eq 'https://kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net/' -and
                $Path -eq '/v1/rest/mgmt' -and
                $TimeoutSec -eq 123
            }
        }

        It 'returns other clusters when database enumeration fails for a creating Azure cluster' {
            Mock Get-XdrAzureAccessToken {
                switch ($Resource) {
                    'https://management.azure.com/' {
                        'arm-token'
                    }
                    'https://help.kusto.windows.net' {
                        'free-cluster-token'
                    }
                    'https://kusto.kusto.windows.net' {
                        'free-cluster-data-token'
                    }
                    default {
                        throw "Unexpected token resource: $Resource"
                    }
                }
            } -ModuleName XDRInternals

            Mock Get-XdrAzureResourceManagerCollection {
                switch ($Path) {
                    '/subscriptions?api-version=2022-12-01' {
                        @(
                            [pscustomobject]@{
                                subscriptionId = 'sub-1'
                                displayName    = 'Lab Subscription'
                                tenantId       = 'tenant-1'
                            }
                        )
                    }
                    '/subscriptions/sub-1/providers/Microsoft.Kusto/clusters?api-version=2024-04-13' {
                        @(
                            [pscustomobject]@{
                                id         = '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/nm-test-cluster'
                                name       = 'nm-test-cluster'
                                location   = 'westus2'
                                sku        = [pscustomobject]@{
                                    name = 'Basic'
                                    tier = 'Basic'
                                }
                                properties = [pscustomobject]@{
                                    uri               = 'https://nm-test-cluster.westus2.kusto.windows.net'
                                    dataIngestionUri  = 'https://ingest-nm-test-cluster.westus2.kusto.windows.net'
                                    state             = 'Running'
                                    provisioningState = 'Creating'
                                }
                            }
                        )
                    }
                    '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.Kusto/clusters/nm-test-cluster/databases?api-version=2024-04-13' {
                        throw 'Cannot fetch databases while resource is in state ''Creating''.'
                    }
                    default {
                        throw "Unexpected ARM collection path: $Path"
                    }
                }
            } -ModuleName XDRInternals

            Mock Invoke-XdrAzureDataExplorerRestRequest {
                if ($BaseUri.AbsoluteUri -eq 'https://saasrp.kusto.windows.net/' -and $Path -eq '/v1/rest/SaasRp/clusters') {
                    return @(
                        [pscustomobject]@{
                            id                 = 'kvc-f1csubt6echz7s8ark'
                            engineUrl          = 'https://kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net'
                            dmUrl              = 'https://ingest-kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net'
                            state              = 'Running'
                            region             = 'southcentralus'
                            defaultDisplayName = 'MyFreeCluster'
                            databaseCount      = 1
                            graduation         = $null
                        }
                    )
                }

                if ($BaseUri.AbsoluteUri -eq 'https://kvc-f1csubt6echz7s8ark.southcentralus.kusto.windows.net/' -and $Path -eq '/v1/rest/mgmt') {
                    return [pscustomobject]@{
                        Tables = @(
                            [pscustomobject]@{
                                TableName = 'Table_0'
                                Columns   = @(
                                    [pscustomobject]@{ ColumnName = 'DatabaseName' },
                                    [pscustomobject]@{ ColumnName = 'DatabaseAccessMode' }
                                )
                                Rows      = @(
                                    , @('MyDatabase', 'ReadWrite')
                                )
                            }
                        )
                    }
                }

                throw "Unexpected Azure Data Explorer REST request: $($BaseUri.AbsoluteUri)$Path"
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = @(Get-XdrAzureDataExplorerCluster -IncludeDatabases -WarningVariable discoveryWarnings)

                $result.Count | Should -Be 2
                $result[0].ClusterName | Should -Be 'nm-test-cluster'
                @($result[0].Databases).Count | Should -Be 0
                $result[1].ClusterName | Should -Be 'MyFreeCluster'
                @($result[1].Databases).Count | Should -Be 1
                $result[1].Databases[0].DatabaseName | Should -Be 'MyDatabase'
                $result[0].DiscoveryStatus.IsComplete | Should -BeFalse
                $result[0].DiscoveryStatus.Failures | Should -HaveCount 1
                $result[0].DiscoveryStatus.Failures[0].Provider | Should -Be 'AzureResourceManager'
                $result[0].DiscoveryStatus.Failures[0].Scope | Should -Be 'Cluster nm-test-cluster database enumeration'
                [object]::ReferenceEquals($result[1].DiscoveryStatus, $result[0].DiscoveryStatus) | Should -BeTrue
                @($discoveryWarnings) | Should -HaveCount 1
                @($discoveryWarnings)[0].Message | Should -BeLike '*discovery returned partial results*Cannot fetch databases*'
            }
        }
    }

    Describe 'Get-XdrAzureResourceManagerCollection' {
        It 'preserves api-version when ARM nextLink omits it' {
            $script:armRequestUris = @()

            Mock Invoke-XdrAzureResourceManagerRequest {
                $script:armRequestUris += $Uri.AbsoluteUri

                if ($script:armRequestUris.Count -eq 1) {
                    return [pscustomobject]@{
                        value    = @([pscustomobject]@{ name = 'first' })
                        nextLink = 'https://management.azure.com/subscriptions/nextPageToken'
                    }
                }

                return [pscustomobject]@{
                    value = @([pscustomobject]@{ name = 'second' })
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = @(Get-XdrAzureResourceManagerCollection -Path '/subscriptions?api-version=2022-12-01' -Token 'arm-token')

                $result.Count | Should -Be 2
                $result[0].name | Should -Be 'first'
                $result[1].name | Should -Be 'second'
            }

            $script:armRequestUris[1] | Should -Be 'https://management.azure.com/subscriptions/nextPageToken?api-version=2022-12-01'
        }
    }

    Describe 'Test-XdrAzureDataExplorerNotFound' {
        It 'treats Kusto entity-not-found responses as bootstrapable misses' {
            InModuleScope XDRInternals {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('Request is invalid and cannot be executed.'),
                    'BadRequest_EntityNotFound',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $null
                )
                $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                    '{"error":{"code":"BadRequest_EntityNotFound","@type":"Kusto.Data.Exceptions.EntityNotFoundException","@message":"Entity ID ''DeviceTimelineCliBridgeSmoke'' of kind ''Table'' was not found."}}'
                )

                (Test-XdrAzureDataExplorerNotFound -ErrorRecord $errorRecord) | Should -BeTrue
            }
        }
    }

    Describe 'Invoke-XdrAzureDataExplorerRestRequest' {
        It 'does not attach bearer tokens to untrusted hosts' {
            Mock Invoke-RestMethod { throw 'must not be called' } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                {
                    Invoke-XdrAzureDataExplorerRestRequest -BaseUri 'https://attacker.example' -Path '/v2/rest/query' -Token 'token'
                } | Should -Throw '*Refusing to send an Azure Data Explorer bearer token*'
            }
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'retries transient transport EOF failures' {
            $script:restAttempts = 0

            Mock Start-Sleep {} -ModuleName XDRInternals
            Mock Invoke-RestMethod {
                $script:restAttempts++
                if ($script:restAttempts -eq 1) {
                    throw [System.IO.IOException]::new('Received an unexpected EOF or 0 bytes from the transport stream.')
                }

                [pscustomobject]@{ ok = $true }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = Invoke-XdrAzureDataExplorerRestRequest `
                    -BaseUri 'https://contoso.westeurope.kusto.windows.net' `
                    -Path '/v1/rest/query' `
                    -Token 'token' `
                    -RetryCount 2

                $result.ok | Should -BeTrue
            }

            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
            Should -Invoke Start-Sleep -ModuleName XDRInternals -Times 1 -Exactly
        }
    }

    Describe 'Invoke-XdrAzureResourceManagerRequest' {
        It 'does not attach ARM bearer tokens to untrusted hosts' {
            Mock Invoke-RestMethod { throw 'must not be called' } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                {
                    Invoke-XdrAzureResourceManagerRequest -Uri 'https://attacker.example/subscriptions' -Token 'token'
                } | Should -Throw '*Refusing to send an Azure Resource Manager bearer token*'
            }
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'retries transient transport EOF failures' {
            $script:armRestAttempts = 0

            Mock Start-Sleep {} -ModuleName XDRInternals
            Mock Invoke-RestMethod {
                $script:armRestAttempts++
                if ($script:armRestAttempts -eq 1) {
                    throw [System.IO.IOException]::new('Received an unexpected EOF or 0 bytes from the transport stream.')
                }

                [pscustomobject]@{ ok = $true }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = Invoke-XdrAzureResourceManagerRequest `
                    -Path '/subscriptions?api-version=2022-12-01' `
                    -Token 'token' `
                    -RetryCount 2

                $result.ok | Should -BeTrue
            }

            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
            Should -Invoke Start-Sleep -ModuleName XDRInternals -Times 1 -Exactly
        }
    }

    Describe 'Test-XdrAzureDataExplorerTable' {
        It 'returns true when the filtered table list contains a matching row' {
            Mock Invoke-XdrAzureDataExplorerManagementCommand {
                [pscustomobject]@{
                    Tables = @(
                        [pscustomobject]@{
                            Columns = @(
                                [pscustomobject]@{ ColumnName = 'TableName' }
                            )
                            Rows    = @(
                                @('DeviceTimeline')
                            )
                        }
                    )
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                (Test-XdrAzureDataExplorerTable -ClusterUri 'https://contoso.westeurope.kusto.windows.net' -Database 'Investigations' -TableName 'DeviceTimeline' -Token 'token') | Should -BeTrue
            }
        }

        It 'returns false when the filtered table list is empty' {
            Mock Invoke-XdrAzureDataExplorerManagementCommand {
                [pscustomobject]@{
                    Tables = @(
                        [pscustomobject]@{
                            Columns = @(
                                [pscustomobject]@{ ColumnName = 'TableName' }
                            )
                            Rows    = @()
                        }
                    )
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                (Test-XdrAzureDataExplorerTable -ClusterUri 'https://contoso.westeurope.kusto.windows.net' -Database 'Investigations' -TableName 'DeviceTimeline' -Token 'token') | Should -BeFalse
            }
        }
    }

    Describe 'Initialize-XdrAzureDataExplorerTable' {
        BeforeEach {
            Mock Invoke-XdrAzureDataExplorerManagementCommand {} -ModuleName XDRInternals
        }

        It 'creates a missing table and module-owned mapping with convergent commands' {
            Mock Get-XdrAzureDataExplorerTableSchema { $null } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerMapping { $null } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Initialize-XdrAzureDataExplorerTable `
                    -ClusterUri 'https://contoso.westeurope.kusto.windows.net' `
                    -Database 'Investigations' `
                    -TableName 'DeviceTimeline' `
                    -MappingName 'DeviceTimeline_EventMapping' `
                    -Token 'token'
            }

            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Command -eq '.create-merge tables DeviceTimeline (Event:dynamic)'
            }
            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Command.StartsWith(".create-or-alter table DeviceTimeline ingestion json mapping 'DeviceTimeline_EventMapping' '[")
            }
        }

        It 'does not mutate a current table or mapping' {
            Mock Get-XdrAzureDataExplorerTableSchema { @{ Event = 'dynamic' } } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerMapping {
                [pscustomobject]@{
                    Name    = 'DeviceTimeline_EventMapping'
                    Mapping = '[{"column":"Event","Properties":{"path":"$"}}]'
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Initialize-XdrAzureDataExplorerTable `
                    -ClusterUri 'https://contoso.westeurope.kusto.windows.net' `
                    -Database 'Investigations' `
                    -TableName 'DeviceTimeline' `
                    -MappingName 'DeviceTimeline_EventMapping' `
                    -Token 'token'
            }

            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'adds missing typed columns and replaces a stale module-owned mapping' {
            Mock Get-XdrAzureDataExplorerTableSchema { @{ ActionTime = 'datetime' } } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerMapping {
                [pscustomobject]@{
                    Name    = 'XDRTest_EventMapping'
                    Mapping = '[{"column":"ActionTime","Properties":{"path":"$.OldTime"}}]'
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $profile = @{
                    Columns        = @(
                        @{ Name = 'ActionTime'; Type = 'datetime' },
                        @{ Name = 'Event'; Type = 'dynamic' }
                    )
                    ColumnMappings = @(
                        @{ Column = 'ActionTime'; Properties = @{ Path = '$.ActionTime' } },
                        @{ Column = 'Event'; Properties = @{ Path = '$' } }
                    )
                }

                Initialize-XdrAzureDataExplorerTable `
                    -ClusterUri 'https://contoso.westeurope.kusto.windows.net' `
                    -Database 'Investigations' `
                    -TableName 'XDRTest' `
                    -MappingName 'XDRTest_EventMapping' `
                    -Token 'token' `
                    -TableProfile $profile
            }

            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Command -eq '.create-merge tables XDRTest (ActionTime:datetime, Event:dynamic)'
            }
            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Command -like ".create-or-alter table XDRTest ingestion json mapping 'XDRTest_EventMapping' *"
            }
        }

        It 'fails before mutation when a typed column is incompatible' {
            Mock Get-XdrAzureDataExplorerTableSchema { @{ ActionTime = 'string'; Event = 'dynamic' } } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerMapping {
                [pscustomobject]@{ Name = 'XDRTest_EventMapping'; Mapping = '[]' }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $profile = @{
                    Columns        = @(
                        @{ Name = 'ActionTime'; Type = 'datetime' },
                        @{ Name = 'Event'; Type = 'dynamic' }
                    )
                    ColumnMappings = @(
                        @{ Column = 'ActionTime'; Properties = @{ Path = '$.ActionTime' } },
                        @{ Column = 'Event'; Properties = @{ Path = '$' } }
                    )
                }

                {
                    Initialize-XdrAzureDataExplorerTable `
                        -ClusterUri 'https://contoso.westeurope.kusto.windows.net' `
                        -Database 'Investigations' `
                        -TableName 'XDRTest' `
                        -MappingName 'XDRTest_EventMapping' `
                        -Token 'token' `
                        -TableProfile $profile
                } | Should -Throw '*ActionTime (expected datetime, found string)*No schema or mapping changes were applied*'
            }

            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'preserves an existing explicitly named manual mapping' {
            Mock Get-XdrAzureDataExplorerTableSchema { @{ Event = 'dynamic' } } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerMapping {
                [pscustomobject]@{
                    Name    = 'CallerMapping'
                    Mapping = '[{"column":"CustomColumn","Properties":{"path":"$.Custom"}}]'
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                Initialize-XdrAzureDataExplorerTable `
                    -ClusterUri 'https://contoso.westeurope.kusto.windows.net' `
                    -Database 'Investigations' `
                    -TableName 'DeviceTimeline' `
                    -MappingName 'CallerMapping' `
                    -Token 'token' `
                    -PreserveExistingMapping
            }

            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'uses idempotent management commands when initializers race on a missing table' {
            Mock Get-XdrAzureDataExplorerTableSchema { $null } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerMapping { $null } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                1..2 | ForEach-Object {
                    Initialize-XdrAzureDataExplorerTable `
                        -ClusterUri 'https://contoso.westeurope.kusto.windows.net' `
                        -Database 'Investigations' `
                        -TableName 'ConcurrentTable' `
                        -MappingName 'ConcurrentTable_EventMapping' `
                        -Token 'token'
                }
            }

            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 2 -Exactly -ParameterFilter {
                $Command -eq '.create-merge tables ConcurrentTable (Event:dynamic)'
            }
            Should -Invoke Invoke-XdrAzureDataExplorerManagementCommand -ModuleName XDRInternals -Times 2 -Exactly -ParameterFilter {
                $Command -like ".create-or-alter table ConcurrentTable ingestion json mapping 'ConcurrentTable_EventMapping' *"
            }
        }
    }

    Describe 'Get-XdrAzureAccessToken' {
        BeforeEach {
            InModuleScope XDRInternals {
                $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                $script:session.Cookies.Add('https://login.microsoftonline.com/', [System.Net.Cookie]::new('ESTSAUTH', 'ests-cookie-value'))
            }
        }

        It 'uses the direct ESTS session flow for non-ADX resources before falling back to local tools' {
            Mock Invoke-WebRequest {
                [pscustomobject]@{
                    Headers      = @{ Location = 'msauth.com.msauth.unsignedapp://auth?code=auth-code' }
                    BaseResponse = [pscustomobject]@{
                        ResponseUri = [uri]'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize'
                        Headers     = @{ Location = 'msauth.com.msauth.unsignedapp://auth?code=auth-code' }
                    }
                }
            } -ModuleName XDRInternals

            Mock Invoke-RestMethod {
                [pscustomobject]@{
                    access_token = 'ests-session-token'
                }
            } -ModuleName XDRInternals -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/token'
            }

            Mock Invoke-XdrAzAccessTokenRequest {
                throw 'Az.Accounts should not be used when the ESTS session succeeds.'
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $token = Get-XdrAzureAccessToken -Resource 'https://graph.microsoft.com' `
                    -Scope 'https://graph.microsoft.com/.default' `
                    -ResourceDisplayName 'Microsoft Graph'

                $token | Should -Be 'ests-session-token'
            }

            Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/authorize*' -and
                $WebSession -ne $null
            }

            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/token' -and
                $Body.scope -eq 'https://graph.microsoft.com/.default'
            }

            Should -Invoke Invoke-XdrAzAccessTokenRequest -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'prefers the XDR web session bridge for Azure Data Explorer before local Azure auth' {
            Mock Invoke-XdrLocalAzureAccessTokenRequest {
                throw 'Local Azure auth should not be used when the ESTS bridge succeeds.'
            } -ModuleName XDRInternals

            Mock Invoke-WebRequest {
                return [pscustomobject]@{
                    Headers      = @{ Location = 'https://login.microsoftonline.com/common/oauth2/nativeclient?code=bridge-auth-code' }
                    BaseResponse = [pscustomobject]@{
                        ResponseUri = [uri]'https://login.microsoftonline.com/organizations/oauth2/authorize'
                        Headers     = @{ Location = 'https://login.microsoftonline.com/common/oauth2/nativeclient?code=bridge-auth-code' }
                    }
                }
            } -ModuleName XDRInternals

            Mock Invoke-RestMethod {
                if ($Body.grant_type -eq 'authorization_code') {
                    return [pscustomobject]@{
                        access_token  = 'bridge-arm-token'
                        refresh_token = 'bridge-refresh-token'
                    }
                }

                return [pscustomobject]@{
                    access_token = 'bridge-adx-token'
                }
            } -ModuleName XDRInternals -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/token'
            }

            InModuleScope XDRInternals {
                $token = Get-XdrAzureAccessToken -Resource 'https://api.kusto.windows.net' `
                    -Scope 'https://contoso.westeurope.kusto.windows.net/.default' `
                    -ResourceDisplayName 'Azure Data Explorer'

                $token | Should -Be 'bridge-adx-token'
            }

            Should -Invoke Invoke-XdrLocalAzureAccessTokenRequest -ModuleName XDRInternals -Times 0 -Exactly

            Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/authorize*' -and
                $Uri -notlike 'https://login.microsoftonline.com/*/oauth2/v2.0/authorize*'
            }

            Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 0 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/authorize*'
            }

            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/token' -and
                $Body.grant_type -eq 'authorization_code' -and
                $Body.resource -eq 'https://management.core.windows.net/'
            }

            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/token' -and
                $Body.grant_type -eq 'refresh_token' -and
                $Body.resource -eq 'https://api.kusto.windows.net'
            }
        }

        It 'falls back to local Azure auth for Azure Data Explorer when the XDR web session bridge is unavailable' {
            Mock Invoke-XdrLocalAzureAccessTokenRequest {
                'local-adx-token'
            } -ModuleName XDRInternals

            Mock Invoke-WebRequest {
                throw 'The bridge authorize request failed.'
            } -ModuleName XDRInternals

            Mock Invoke-RestMethod {
                throw 'The token endpoint should not be used when the bridge authorize request fails.'
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $token = Get-XdrAzureAccessToken -Resource 'https://api.kusto.windows.net' `
                    -Scope 'https://contoso.westeurope.kusto.windows.net/.default' `
                    -ResourceDisplayName 'Azure Data Explorer'

                $token | Should -Be 'local-adx-token'
            }

            Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/authorize*' -and
                $Uri -notlike 'https://login.microsoftonline.com/*/oauth2/v2.0/authorize*'
            }

            Should -Invoke Invoke-XdrLocalAzureAccessTokenRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://api.kusto.windows.net'
            }
        }

        It 'omits SkipHttpErrorCheck when Invoke-WebRequest does not support it' {
            Mock Get-Command {
                [pscustomobject]@{
                    Parameters = @{}
                }
            } -ModuleName XDRInternals -ParameterFilter {
                $Name -eq 'Invoke-WebRequest'
            }

            Mock Invoke-WebRequest {
                [pscustomobject]@{
                    Headers      = @{ Location = 'msauth.com.msauth.unsignedapp://auth?code=auth-code' }
                    BaseResponse = [pscustomobject]@{
                        ResponseUri = [uri]'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize'
                        Headers     = @{ Location = 'msauth.com.msauth.unsignedapp://auth?code=auth-code' }
                    }
                }
            } -ModuleName XDRInternals

            Mock Invoke-RestMethod {
                [pscustomobject]@{
                    access_token = 'ests-session-token'
                }
            } -ModuleName XDRInternals -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/token'
            }

            InModuleScope XDRInternals {
                $token = Get-XdrAzureAccessToken -Resource 'https://graph.microsoft.com' `
                    -Scope 'https://graph.microsoft.com/.default' `
                    -ResourceDisplayName 'Microsoft Graph'

                $token | Should -Be 'ests-session-token'
            }

            Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                -not $PSBoundParameters.ContainsKey('SkipHttpErrorCheck')
            }
        }
    }

    Describe 'Send-XdrAzureDataExplorerQueuedIngestion' {
        It 'does not enable tracking unless requested' {
            Mock Invoke-XdrAzureDataExplorerRestRequest { $Body } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $body = Send-XdrAzureDataExplorerQueuedIngestion `
                    -IngestionUri 'https://ingest-contoso.westeurope.kusto.windows.net' `
                    -Database 'Investigations' `
                    -TableName 'DeviceTimeline' `
                    -MappingName 'DeviceTimeline_EventMapping' `
                    -Token 'preset-token' `
                    -Blobs @(@{ url = 'https://storage.blob.core.windows.net/ingest/blob1.json.gz?sig=abc'; rawSize = 42 })

                $body.properties.enableTracking | Should -BeNullOrEmpty
            }
        }

        It 'enables tracking when requested' {
            Mock Invoke-XdrAzureDataExplorerRestRequest { $Body } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $body = Send-XdrAzureDataExplorerQueuedIngestion `
                    -IngestionUri 'https://ingest-contoso.westeurope.kusto.windows.net' `
                    -Database 'Investigations' `
                    -TableName 'DeviceTimeline' `
                    -MappingName 'DeviceTimeline_EventMapping' `
                    -Token 'preset-token' `
                    -Blobs @(@{ url = 'https://storage.blob.core.windows.net/ingest/blob1.json.gz?sig=abc'; rawSize = 42 }) `
                    -TrackIngestion

                $body.properties.enableTracking | Should -BeTrue
            }
        }
    }

    Describe 'Export-XdrAzureDataExplorer' {
        BeforeEach {
            InModuleScope XDRInternals {
                $script:AzureDataExplorerConnection = [pscustomobject]@{
                    ClusterUri              = [uri]'https://contoso.westeurope.kusto.windows.net'
                    IngestionUri            = [uri]'https://ingest-contoso.westeurope.kusto.windows.net'
                    Database                = 'Investigations'
                    TenantId                = $null
                    ManagedIdentityClientId = $null
                    AccessToken             = $null
                }
            }

            Mock Get-XdrAzureAccessToken { 'preset-token' } -ModuleName XDRInternals
            Mock Initialize-XdrAzureDataExplorerTable {} -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerIngestionConfiguration {
                [pscustomobject]@{
                    containerSettings = [pscustomobject]@{
                        preferredUploadMethod = 'Storage'
                        containers            = @(
                            [pscustomobject]@{
                                path = 'https://storage.blob.core.windows.net/ingest?sig=abc'
                            }
                        )
                    }
                    ingestionSettings = [pscustomobject]@{
                        maxBlobsPerBatch = 20
                        maxDataSize      = 1073741824
                    }
                }
            } -ModuleName XDRInternals
            Mock Send-XdrAzureDataExplorerBlobUpload {} -ModuleName XDRInternals
            Mock Send-XdrAzureDataExplorerQueuedIngestion {
                [pscustomobject]@{
                    ingestionOperationId = 'ingest-op-1'
                }
            } -ModuleName XDRInternals
            Mock Wait-XdrAzureDataExplorerQueuedIngestion {
                @(
                    [pscustomobject]@{
                        OperationId = 'ingest-op-1'
                        Status      = 'Succeeded'
                        Succeeded   = 1
                        Failed      = 0
                        InProgress  = 0
                        Canceled    = 0
                        IsTerminal  = $true
                        HasFailures = $false
                        Details     = $null
                    }
                )
            } -ModuleName XDRInternals
        }

        It 'bootstraps the raw table and queues a compressed blob upload' {
            $records = @(
                [pscustomobject]@{ DeviceId = 'device-1'; EventType = 'ProcessCreated' },
                [pscustomobject]@{ DeviceId = 'device-2'; EventType = 'NetworkConnection' }
            )

            $result = @($records | Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $TestDrive -PassThru)

            $result.Count | Should -Be 2

            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'DeviceTimeline' -and
                $MappingName -eq 'DeviceTimeline_EventMapping'
            }

            Should -Invoke Get-XdrAzureAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Resource -eq 'https://api.kusto.windows.net' -and
                $Scope -eq 'https://contoso.westeurope.kusto.windows.net/.default'
            }

            Should -Invoke Send-XdrAzureDataExplorerBlobUpload -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $FilePath -like '*.json.gz' -and
                $BlobUri -like 'https://storage.blob.core.windows.net/ingest/*'
            }

            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Database -eq 'Investigations' -and
                $TableName -eq 'DeviceTimeline' -and
                $MappingName -eq 'DeviceTimeline_EventMapping' -and
                -not $TrackIngestion -and
                $Blobs.Count -eq 1 -and
                $Blobs[0].url -like '*.json.gz*' -and
                $Blobs[0].rawSize -gt 0
            }
        }

        It 'preserves deep payloads when exporting raw records to a named table' {
            $records = @(
                [pscustomobject]@{
                    DeviceId  = 'device-1'
                    EventType = 'ProcessCreated'
                    level1    = [pscustomobject]@{
                        level2 = [pscustomobject]@{
                            level3 = [pscustomobject]@{
                                level4 = [pscustomobject]@{
                                    level5 = [pscustomobject]@{
                                        level6 = [pscustomobject]@{
                                            level7 = [pscustomobject]@{
                                                level8 = [pscustomobject]@{
                                                    level9 = [pscustomobject]@{
                                                        level10 = [pscustomobject]@{
                                                            level11 = 'preserved'
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            )

            $null = @($records | Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $TestDrive -KeepTempFiles -DisableCompression)

            $stagedJsonPath = Get-ChildItem -Path $TestDrive -Recurse -Filter '*.json' | Select-Object -First 1 -ExpandProperty FullName
            $stagedJson = @(Get-Content -Path $stagedJsonPath -Raw | ConvertFrom-Json)

            $stagedJson[0].level1.level2.level3.level4.level5.level6.level7.level8.level9.level10.level11 | Should -Be 'preserved'
        }

        It 'submits multiple queued requests when the service maxDataSize would be exceeded' {
            Mock Get-XdrAzureDataExplorerIngestionConfiguration {
                [pscustomobject]@{
                    containerSettings = [pscustomobject]@{
                        preferredUploadMethod = 'Storage'
                        containers            = @(
                            [pscustomobject]@{
                                path = 'https://storage.blob.core.windows.net/ingest?sig=abc'
                            }
                        )
                    }
                    ingestionSettings = [pscustomobject]@{
                        maxBlobsPerBatch = 20
                        maxDataSize      = 120
                    }
                }
            } -ModuleName XDRInternals

            $records = @(
                [pscustomobject]@{ DeviceId = 'device-1'; EventType = 'This string is intentionally long to force a service-sized rollover boundary.' },
                [pscustomobject]@{ DeviceId = 'device-2'; EventType = 'This string is intentionally long to force a service-sized rollover boundary.' }
            )

            $null = @($records | Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $TestDrive)

            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 2 -Exactly
        }

        It 'requests ingestion tracking only when TrackIngestion is specified' {
            $records = @(
                [pscustomobject]@{ DeviceId = 'device-1'; EventType = 'ProcessCreated' }
            )

            $null = @($records | Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $TestDrive -TrackIngestion)

            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TrackIngestion
            }
        }

        It 'waits for ingestion and implicitly enables tracking when WaitForIngestion is specified' {
            $records = @(
                [pscustomobject]@{ DeviceId = 'device-1'; EventType = 'ProcessCreated' }
            )

            $null = @($records | Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $TestDrive -WaitForIngestion)

            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TrackIngestion
            }

            Should -Invoke Wait-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Database -eq 'Investigations' -and
                $TableName -eq 'DeviceTimeline' -and
                $OperationId.Count -eq 1 -and
                $OperationId[0] -eq 'ingest-op-1'
            }
        }

        It 'refreshes the queued ingestion configuration before upload when the refresh interval has elapsed' {
            Mock Get-XdrAzureDataExplorerIngestionConfiguration {
                [pscustomobject]@{
                    containerSettings = [pscustomobject]@{
                        preferredUploadMethod = 'Storage'
                        refreshInterval       = '00:00:00'
                        containers            = @(
                            [pscustomobject]@{
                                path = 'https://storage.blob.core.windows.net/ingest?sig=abc'
                            }
                        )
                    }
                    ingestionSettings = [pscustomobject]@{
                        maxBlobsPerBatch = 20
                        maxDataSize      = 1073741824
                    }
                }
            } -ModuleName XDRInternals

            $records = @(
                [pscustomobject]@{ DeviceId = 'device-1'; EventType = 'ProcessCreated' }
            )

            $null = @($records | Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $TestDrive)

            Should -Invoke Get-XdrAzureDataExplorerIngestionConfiguration -ModuleName XDRInternals -Times 2 -Exactly
        }

        It 'retains SkipBootstrap behavior' {
            $null = [pscustomobject]@{ DeviceId = 'device-1' } |
                Export-XdrAzureDataExplorer -TableName 'ExistingTable' -TempPath $TestDrive -SkipBootstrap

            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 0 -Exactly
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly
        }

        It 'removes staging data when runtime configuration fails during begin' {
            Mock Get-XdrAzureDataExplorerIngestionConfiguration { throw 'configuration failed' } -ModuleName XDRInternals
            $stagingRoot = Join-Path $TestDrive 'configuration-failure'

            { [pscustomobject]@{ DeviceId = 'device-1' } |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot } |
                Should -Throw '*configuration failed*'

            @(Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue) | Should -HaveCount 0
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'removes staging data when bootstrap fails' {
            Mock Initialize-XdrAzureDataExplorerTable { throw 'bootstrap failed' } -ModuleName XDRInternals
            $stagingRoot = Join-Path $TestDrive 'bootstrap-failure'

            { [pscustomobject]@{ DeviceId = 'device-1' } |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot } |
                Should -Throw '*bootstrap failed*'

            @(Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue) | Should -HaveCount 0
            Should -Invoke Send-XdrAzureDataExplorerBlobUpload -ModuleName XDRInternals -Times 0 -Exactly
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'closes writers and removes staging data when serialization fails' {
            $script:serializationCount = 0
            $stagingRoot = Join-Path $TestDrive 'serialization-failure'
            Mock ConvertTo-Json {
                $script:serializationCount++
                if ($script:serializationCount -eq 2) {
                    throw 'serialization failed'
                }

                '{"DeviceId":"device-1"}'
            } -ModuleName XDRInternals

            $records = @(
                [pscustomobject]@{ DeviceId = 'device-1' },
                [pscustomobject]@{ DeviceId = 'device-2' }
            )

            { $records | Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot } |
                Should -Throw '*serialization failed*'

            @(Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue) | Should -HaveCount 0
            Should -Invoke Send-XdrAzureDataExplorerBlobUpload -ModuleName XDRInternals -Times 0 -Exactly
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'removes staging data when upload fails' {
            Mock Send-XdrAzureDataExplorerBlobUpload { throw 'upload failed' } -ModuleName XDRInternals
            $stagingRoot = Join-Path $TestDrive 'upload-failure'

            { [pscustomobject]@{ DeviceId = 'device-1' } |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot } |
                Should -Throw '*upload failed*'

            @(Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue) | Should -HaveCount 0
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'removes staging data when ingestion waiting fails after submission' {
            Mock Wait-XdrAzureDataExplorerQueuedIngestion { throw 'wait failed' } -ModuleName XDRInternals
            $stagingRoot = Join-Path $TestDrive 'wait-failure'

            { [pscustomobject]@{ DeviceId = 'device-1' } |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot -WaitForIngestion } |
                Should -Throw '*wait failed*'

            @(Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue) | Should -HaveCount 0
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly
        }

        It 'removes staging data when queued ingestion submission fails' {
            Mock Send-XdrAzureDataExplorerQueuedIngestion { throw 'submission failed' } -ModuleName XDRInternals
            $stagingRoot = Join-Path $TestDrive 'submission-failure'

            { [pscustomobject]@{ DeviceId = 'device-1' } |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot } |
                Should -Throw '*submission failed*'

            @(Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue) | Should -HaveCount 0
            Should -Invoke Send-XdrAzureDataExplorerBlobUpload -ModuleName XDRInternals -Times 1 -Exactly
        }

        It 'keeps staging files after a failure when requested' {
            Mock Send-XdrAzureDataExplorerBlobUpload { throw 'upload failed' } -ModuleName XDRInternals
            $stagingRoot = Join-Path $TestDrive 'kept-upload-failure'

            { [pscustomobject]@{ DeviceId = 'device-1' } |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot -KeepTempFiles } |
                Should -Throw '*upload failed*'

            @(Get-ChildItem -LiteralPath $stagingRoot -Recurse -File) | Should -Not -BeNullOrEmpty
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'does not upload or submit buffered data after downstream pipeline cancellation' {
            $records = 1..3 | ForEach-Object { [pscustomobject]@{ Sequence = $_ } }
            $stagingRoot = Join-Path $TestDrive 'pipeline-cancellation'

            $result = @($records |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot -PassThru |
                    Select-Object -First 1)

            $result | Should -HaveCount 1
            @(Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue) | Should -HaveCount 0
            Should -Invoke Send-XdrAzureDataExplorerBlobUpload -ModuleName XDRInternals -Times 0 -Exactly
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'keeps closed staging files after downstream cancellation when requested' {
            $records = 1..3 | ForEach-Object { [pscustomobject]@{ Sequence = $_ } }
            $stagingRoot = Join-Path $TestDrive 'kept-pipeline-cancellation'

            $null = @($records |
                    Export-XdrAzureDataExplorer -TableName 'DeviceTimeline' -TempPath $stagingRoot -PassThru -KeepTempFiles |
                    Select-Object -First 1)

            $stagedJsonPath = Get-ChildItem -LiteralPath $stagingRoot -Recurse -Filter '*.json' |
                Select-Object -First 1 -ExpandProperty FullName
            $stagedJsonPath | Should -Not -BeNullOrEmpty
            $exclusiveHandle = [System.IO.File]::Open($stagedJsonPath, 'Open', 'ReadWrite', 'None')
            $exclusiveHandle.Dispose()
            Should -Invoke Send-XdrAzureDataExplorerBlobUpload -ModuleName XDRInternals -Times 0 -Exactly
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 0 -Exactly
        }

    }

    Describe 'Get-XdrAzureDataExplorerIngestionStatus' {
        BeforeEach {
            InModuleScope XDRInternals {
                $script:AzureDataExplorerConnection = [pscustomobject]@{
                    ClusterUri              = [uri]'https://contoso.westeurope.kusto.windows.net'
                    IngestionUri            = [uri]'https://ingest-contoso.westeurope.kusto.windows.net'
                    Database                = 'Investigations'
                    TenantId                = $null
                    ManagedIdentityClientId = $null
                    AccessToken             = $null
                }
            }

            Mock Get-XdrAzureAccessToken { 'preset-token' } -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerQueuedIngestionStatus {
                [pscustomobject]@{
                    OperationId = $OperationId
                    Status      = 'InProgress'
                    Succeeded   = 0
                    Failed      = 0
                    InProgress  = 1
                    Canceled    = 0
                    IsTerminal  = $false
                    HasFailures = $false
                    Details     = $null
                }
            } -ModuleName XDRInternals
            Mock Wait-XdrAzureDataExplorerQueuedIngestion {
                @(
                    [pscustomobject]@{
                        OperationId = 'ingest-op-1'
                        Status      = 'Succeeded'
                        Succeeded   = 1
                        Failed      = 0
                        InProgress  = 0
                        Canceled    = 0
                        IsTerminal  = $true
                        HasFailures = $false
                        Details     = @()
                    }
                )
            } -ModuleName XDRInternals
        }

        It 'queries the current status for each operation id' {
            $result = @(
                'ingest-op-1', 'ingest-op-2' | Get-XdrAzureDataExplorerIngestionStatus -TableName 'DeviceTimeline'
            )

            $result.Count | Should -Be 2
            $result[0].OperationId | Should -Be 'ingest-op-1'
            $result[1].OperationId | Should -Be 'ingest-op-2'

            Should -Invoke Get-XdrAzureDataExplorerQueuedIngestionStatus -ModuleName XDRInternals -Times 2 -Exactly -ParameterFilter {
                $Database -eq 'Investigations' -and
                $TableName -eq 'DeviceTimeline'
            }
        }

        It 'waits for completion when requested' {
            $result = @(
                Get-XdrAzureDataExplorerIngestionStatus -TableName 'DeviceTimeline' -OperationId 'ingest-op-1' -WaitForCompletion -Details
            )

            $result.Count | Should -Be 1
            $result[0].Status | Should -Be 'Succeeded'

            Should -Invoke Wait-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Database -eq 'Investigations' -and
                $TableName -eq 'DeviceTimeline' -and
                $OperationId.Count -eq 1 -and
                $OperationId[0] -eq 'ingest-op-1' -and
                $Details
            }
        }
    }

    Describe 'Wait-XdrAzureDataExplorerQueuedIngestion' {
        It 'continues polling after transient status transport failures' {
            $script:statusAttempts = 0

            Mock Start-Sleep {} -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerQueuedIngestionStatus {
                $script:statusAttempts++
                if ($script:statusAttempts -eq 1) {
                    throw [System.IO.IOException]::new('Received an unexpected EOF or 0 bytes from the transport stream.')
                }

                [pscustomobject]@{
                    OperationId = $OperationId
                    Status      = 'Succeeded'
                    Succeeded   = 1
                    Failed      = 0
                    InProgress  = 0
                    Canceled    = 0
                    IsTerminal  = $true
                    HasFailures = $false
                    Details     = @()
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $result = Wait-XdrAzureDataExplorerQueuedIngestion `
                    -IngestionUri 'https://ingest-contoso.westeurope.kusto.windows.net' `
                    -Database 'Investigations' `
                    -TableName 'DeviceTimeline' `
                    -OperationId 'ingest-op-1' `
                    -Token 'token' `
                    -TimeoutMinutes 1 `
                    -PollingIntervalSeconds 1

                $result.Count | Should -Be 1
                $result[0].Status | Should -Be 'Succeeded'
            }

            Should -Invoke Get-XdrAzureDataExplorerQueuedIngestionStatus -ModuleName XDRInternals -Times 2 -Exactly
            Should -Invoke Start-Sleep -ModuleName XDRInternals -Times 1 -Exactly
        }
    }

    Describe 'Table Profiles' {
        It 'returns a non-empty hashtable with all expected table names' {
            InModuleScope XDRInternals {
                $profiles = Get-XdrAzureDataExplorerTableProfile

                $profiles | Should -BeOfType [hashtable]
                $profiles.Count | Should -BeGreaterThan 0

                $expectedTables = @(
                    'XDRDeviceTimelineProcessEvents'
                    'XDRDeviceTimelineFileEvents'
                    'XDRDeviceTimelineNetworkEvents'
                    'XDRDeviceTimelineRegistryEvents'
                    'XDRDeviceTimelineLogonEvents'
                    'XDRDeviceTimelineAlertEvents'
                    'XDRDeviceTimelineOtherEvents'
                    'XDRIdentityTimelineCloudAppEvents'
                    'XDRIdentityTimelineSignInEvents'
                    'XDRIdentityTimelineAlerts'
                    'XDRCloudAppsActivityTimeline'
                    'XDRAlerts'
                    'XDRIncidents'
                    'XDRDevices'
                    'XDRAdvancedHuntingResults'
                )

                foreach ($table in $expectedTables) {
                    $profiles.ContainsKey($table) | Should -BeTrue -Because "profile for '$table' should exist"
                }
            }
        }

        It 'each profile has required keys: TableName, Source, RoutingField, RoutingValues, ColumnMappings' {
            InModuleScope XDRInternals {
                $profiles = Get-XdrAzureDataExplorerTableProfile

                foreach ($key in $profiles.Keys) {
                    $p = $profiles[$key]
                    $p.TableName | Should -Not -BeNullOrEmpty -Because "'$key' needs TableName"
                    $p.Source | Should -Not -BeNullOrEmpty -Because "'$key' needs Source"
                    $p.ContainsKey('RoutingField') | Should -BeTrue -Because "'$key' needs RoutingField key"
                    $p.ContainsKey('RoutingValues') | Should -BeTrue -Because "'$key' needs RoutingValues key"
                    $p.ColumnMappings | Should -Not -BeNullOrEmpty -Because "'$key' needs ColumnMappings"
                }
            }
        }

        It 'each profile ColumnMappings contains at minimum a Timestamp or ActionTime column and an Event column' {
            InModuleScope XDRInternals {
                $profiles = Get-XdrAzureDataExplorerTableProfile

                foreach ($key in $profiles.Keys) {
                    $p = $profiles[$key]
                    $columns = $p.ColumnMappings | ForEach-Object { $_.Column }

                    $hasTimestamp = ($columns -contains 'Timestamp') -or ($columns -contains 'ActionTime') -or ($columns -contains 'QueryTimestamp') -or ($columns -contains 'CreatedTime') -or ($columns -contains 'startTimeUtc') -or ($columns -contains 'LastSeen')
                    $hasTimestamp | Should -BeTrue -Because "'$key' needs a timestamp column"

                    $columns | Should -Contain 'Event' -Because "'$key' needs an Event column"
                }
            }
        }
    }

    Describe 'Profile Resolution' {
        It 'routes DeviceTimeline ProcessCreated to XDRDeviceTimelineProcessEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ ActionType = 'ProcessCreated' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'DeviceTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRDeviceTimelineProcessEvents'
            }
        }

        It 'routes DeviceTimeline FileCreated to XDRDeviceTimelineFileEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ ActionType = 'FileCreated' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'DeviceTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRDeviceTimelineFileEvents'
            }
        }

        It 'routes DeviceTimeline ConnectionSuccess to XDRDeviceTimelineNetworkEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ ActionType = 'ConnectionSuccess' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'DeviceTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRDeviceTimelineNetworkEvents'
            }
        }

        It 'routes DeviceTimeline RegistryValueSet to XDRDeviceTimelineRegistryEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ ActionType = 'RegistryValueSet' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'DeviceTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRDeviceTimelineRegistryEvents'
            }
        }

        It 'routes DeviceTimeline LogonSuccess to XDRDeviceTimelineLogonEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ ActionType = 'LogonSuccess' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'DeviceTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRDeviceTimelineLogonEvents'
            }
        }

        It 'routes DeviceTimeline OneCyber to XDRDeviceTimelineAlertEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ ActionType = 'OneCyber' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'DeviceTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRDeviceTimelineAlertEvents'
            }
        }

        It 'routes DeviceTimeline unknown ActionType to XDRDeviceTimelineOtherEvents catch-all' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ ActionType = 'SomeUnknownType' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'DeviceTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRDeviceTimelineOtherEvents'
            }
        }

        It 'routes IdentityTimeline CloudAppEvents to XDRIdentityTimelineCloudAppEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ SourceTable = 'CloudAppEvents' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'IdentityTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRIdentityTimelineCloudAppEvents'
            }
        }

        It 'routes IdentityTimeline SignInEvents to XDRIdentityTimelineSignInEvents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ SourceTable = 'SignInEvents' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'IdentityTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRIdentityTimelineSignInEvents'
            }
        }

        It 'routes IdentityTimeline Alerts to XDRIdentityTimelineAlerts' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ SourceTable = 'Alerts' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'IdentityTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRIdentityTimelineAlerts'
            }
        }

        It 'routes CloudAppsActivityTimeline source to XDRCloudAppsActivityTimeline' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ _id = 'activity-1'; appName = 'Microsoft 365' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'CloudAppsActivityTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRCloudAppsActivityTimeline'
            }
        }

        It 'routes CloudAppsTimeline alias to XDRCloudAppsActivityTimeline' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ _id = 'activity-1'; appName = 'Microsoft 365' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'CloudAppsTimeline' -InputEvent $event
                $result.TableName | Should -Be 'XDRCloudAppsActivityTimeline'
            }
        }

        It 'routes Alert source to XDRAlerts with no routing field' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ alertId = 'alert-1' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'Alert' -InputEvent $event
                $result.TableName | Should -Be 'XDRAlerts'
            }
        }

        It 'routes Incident source to XDRIncidents' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ IncidentId = 42 }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'Incident' -InputEvent $event
                $result.TableName | Should -Be 'XDRIncidents'
            }
        }

        It 'routes Device source to XDRDevices' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ MachineId = 'machine-1' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'Device' -InputEvent $event
                $result.TableName | Should -Be 'XDRDevices'
            }
        }

        It 'routes AdvancedHunting source to XDRAdvancedHuntingResults' {
            InModuleScope XDRInternals {
                $event = [pscustomobject]@{ QueryTimestamp = '2024-01-01T00:00:00Z' }
                $result = Resolve-XdrAzureDataExplorerTableProfile -Source 'AdvancedHunting' -InputEvent $event
                $result.TableName | Should -Be 'XDRAdvancedHuntingResults'
            }
        }
    }

    Describe 'Typed Record Conversion' {
        It 'converts a DeviceTimeline ProcessCreated event with nested properties' {
            InModuleScope XDRInternals {
                $profiles = Get-XdrAzureDataExplorerTableProfile
                $profile = $profiles['XDRDeviceTimelineProcessEvents']

                $event = [pscustomobject]@{
                    ActionTime        = '2024-06-15T10:30:00Z'
                    ActionType        = 'ProcessCreated'
                    ReportId          = 12345
                    SourceProvider    = 'MDE'
                    Machine           = [pscustomobject]@{
                        MachineId = 'machine-abc'
                        Name      = 'WORKSTATION01'
                    }
                    Process           = [pscustomobject]@{
                        Id           = 1234
                        CreationTime = '2024-06-15T10:29:59Z'
                        CommandLine  = 'cmd.exe /c whoami'
                        ImageFile    = [pscustomobject]@{
                            FileName   = 'cmd.exe'
                            FolderPath = 'C:\Windows\System32'
                            Sha1       = 'abc123sha1'
                            Sha256     = 'abc123sha256'
                        }
                        User         = [pscustomobject]@{
                            AccountName       = 'testuser'
                            AccountDomainName = 'CONTOSO'
                            AccountSid        = 'S-1-5-21-123'
                        }
                    }
                    InitiatingProcess = [pscustomobject]@{
                        Id           = 5678
                        CreationTime = '2024-06-15T10:00:00Z'
                        CommandLine  = 'explorer.exe'
                        ImageFile    = [pscustomobject]@{
                            FileName   = 'explorer.exe'
                            FolderPath = 'C:\Windows'
                            Sha1       = 'def456sha1'
                        }
                        User         = [pscustomobject]@{
                            AccountName       = 'testuser'
                            AccountDomainName = 'CONTOSO'
                        }
                    }
                }

                $record = ConvertTo-XdrAzureDataExplorerTypedRecord -InputEvent $event -TableProfile $profile

                $record | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
                $record['ActionTime'] | Should -Be '2024-06-15T10:30:00Z'
                $record['ActionType'] | Should -Be 'ProcessCreated'
                $record['MachineId'] | Should -Be 'machine-abc'
                $record['MachineName'] | Should -Be 'WORKSTATION01'
                $record['ProcessId'] | Should -Be 1234
                $record['ProcessFileName'] | Should -Be 'cmd.exe'
                $record['ProcessCommandLine'] | Should -Be 'cmd.exe /c whoami'
                $record['ProcessSha1'] | Should -Be 'abc123sha1'
                $record['ProcessAccountName'] | Should -Be 'testuser'
                $record['ProcessAccountDomain'] | Should -Be 'CONTOSO'
                $record['ProcessAccountSid'] | Should -Be 'S-1-5-21-123'
                $record['InitiatingProcessId'] | Should -Be 5678
                $record['InitiatingProcessFileName'] | Should -Be 'explorer.exe'
                $record['InitiatingProcessAccountName'] | Should -Be 'testuser'
                $record['ReportId'] | Should -Be 12345
                $record['SourceProvider'] | Should -Be 'MDE'
                $record['Event'] | Should -Not -BeNullOrEmpty
            }
        }

        It 'handles missing optional nested fields gracefully with nulls' {
            InModuleScope XDRInternals {
                $profiles = Get-XdrAzureDataExplorerTableProfile
                $profile = $profiles['XDRDeviceTimelineProcessEvents']

                $event = [pscustomobject]@{
                    ActionTime = '2024-06-15T10:30:00Z'
                    ActionType = 'ProcessCreated'
                }

                $record = ConvertTo-XdrAzureDataExplorerTypedRecord -InputEvent $event -TableProfile $profile

                $record['ActionTime'] | Should -Be '2024-06-15T10:30:00Z'
                $record['ActionType'] | Should -Be 'ProcessCreated'
                $record['MachineId'] | Should -BeNullOrEmpty
                $record['ProcessId'] | Should -BeNullOrEmpty
                $record['ProcessFileName'] | Should -BeNullOrEmpty
                $record['Event'] | Should -Not -BeNullOrEmpty
            }
        }

        It 'converts a Cloud Apps activity event to the activity timeline table shape' {
            InModuleScope XDRInternals {
                $profiles = Get-XdrAzureDataExplorerTableProfile
                $profile = $profiles['XDRCloudAppsActivityTimeline']

                $event = [pscustomobject]@{
                    date         = '2026-04-28T12:00:00Z'
                    timestamp    = 1777377600000
                    _id          = 'activity-1'
                    recordId     = 'record-1'
                    userName     = 'user@contoso.com'
                    appName      = 'Microsoft 365'
                    activityType = 'Login'
                    ipAddress    = '203.0.113.10'
                    location     = 'Anchorage'
                    country      = 'US'
                }

                $record = ConvertTo-XdrAzureDataExplorerTypedRecord -InputEvent $event -TableProfile $profile

                $record['Date'] | Should -Be '2026-04-28T12:00:00Z'
                $record['Timestamp'] | Should -Be 1777377600000
                $record['ActivityId'] | Should -Be 'activity-1'
                $record['RecordId'] | Should -Be 'record-1'
                $record['UserName'] | Should -Be 'user@contoso.com'
                $record['AppName'] | Should -Be 'Microsoft 365'
                $record['ActivityType'] | Should -Be 'Login'
                $record['IpAddress'] | Should -Be '203.0.113.10'
                $record['Location'] | Should -Be 'Anchorage'
                $record['Country'] | Should -Be 'US'
                $record['Event'] | Should -Not -BeNullOrEmpty
            }
        }
    }

    Describe 'Export-XdrAzureDataExplorer with Source mode' {
        BeforeEach {
            InModuleScope XDRInternals {
                $script:AzureDataExplorerConnection = [pscustomobject]@{
                    ClusterUri              = [uri]'https://contoso.westeurope.kusto.windows.net'
                    IngestionUri            = [uri]'https://ingest-contoso.westeurope.kusto.windows.net'
                    Database                = 'Investigations'
                    TenantId                = $null
                    ManagedIdentityClientId = $null
                    AccessToken             = $null
                }
            }

            Mock Get-XdrAzureAccessToken { 'preset-token' } -ModuleName XDRInternals
            Mock Initialize-XdrAzureDataExplorerTable {} -ModuleName XDRInternals
            Mock Get-XdrAzureDataExplorerIngestionConfiguration {
                [pscustomobject]@{
                    containerSettings = [pscustomobject]@{
                        preferredUploadMethod = 'Storage'
                        containers            = @(
                            [pscustomobject]@{
                                path = 'https://storage.blob.core.windows.net/ingest?sig=abc'
                            }
                        )
                    }
                    ingestionSettings = [pscustomobject]@{
                        maxBlobsPerBatch = 20
                        maxDataSize      = 1073741824
                    }
                }
            } -ModuleName XDRInternals
            Mock Send-XdrAzureDataExplorerBlobUpload {} -ModuleName XDRInternals
            Mock Send-XdrAzureDataExplorerQueuedIngestion {
                [pscustomobject]@{
                    ingestionOperationId = 'ingest-op-1'
                }
            } -ModuleName XDRInternals
            Mock Wait-XdrAzureDataExplorerQueuedIngestion {
                @(
                    [pscustomobject]@{
                        OperationId = 'ingest-op-1'
                        Status      = 'Succeeded'
                        Succeeded   = 1
                        Failed      = 0
                        InProgress  = 0
                        Canceled    = 0
                        IsTerminal  = $true
                        HasFailures = $false
                        Details     = $null
                    }
                )
            } -ModuleName XDRInternals
        }

        It 'routes device timeline events to typed tables' {
            $records = @(
                [pscustomobject]@{ ActionType = 'ProcessCreated'; Machine = @{ MachineId = 'm1' } },
                [pscustomobject]@{ ActionType = 'FileCreated'; Machine = @{ MachineId = 'm2' } },
                [pscustomobject]@{ ActionType = 'ConnectionSuccess'; Machine = @{ MachineId = 'm3' } }
            )

            $null = @($records | Export-XdrAzureDataExplorer -Source 'DeviceTimeline' -TempPath $TestDrive)

            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 3 -Exactly
            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineProcessEvents' -and $TableProfile -ne $null
            }
            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineFileEvents' -and $TableProfile -ne $null
            }
            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineNetworkEvents' -and $TableProfile -ne $null
            }

            Should -Invoke Send-XdrAzureDataExplorerBlobUpload -ModuleName XDRInternals -Times 3 -Exactly
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 3 -Exactly
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineProcessEvents'
            }
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineFileEvents'
            }
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineNetworkEvents'
            }
        }

        It 'routes unknown ActionTypes to the OtherEvents catch-all table' {
            $records = @(
                [pscustomobject]@{ ActionType = 'SomethingNew'; Machine = @{ MachineId = 'm1' } }
            )

            $null = @($records | Export-XdrAzureDataExplorer -Source 'DeviceTimeline' -TempPath $TestDrive)

            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineOtherEvents'
            }
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRDeviceTimelineOtherEvents'
            }
        }

        It 'routes Cloud Apps activity timeline events to the typed Cloud Apps table' {
            $records = @(
                [pscustomobject]@{
                    date         = '2026-04-28T12:00:00Z'
                    timestamp    = 1777377600000
                    _id          = 'activity-1'
                    userName     = 'user@contoso.com'
                    appName      = 'Microsoft 365'
                    activityType = 'Login'
                }
            )

            $null = @($records | Export-XdrAzureDataExplorer -Source 'CloudAppsActivityTimeline' -TempPath $TestDrive)

            Should -Invoke Initialize-XdrAzureDataExplorerTable -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRCloudAppsActivityTimeline' -and $TableProfile -ne $null
            }
            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRCloudAppsActivityTimeline' -and
                $MappingName -eq 'XDRCloudAppsActivityTimeline_EventMapping'
            }
        }

        It 'preserves deep Cloud Apps event payloads in exported JSON records' {
            $records = @(
                [pscustomobject]@{
                    date         = '2026-04-28T12:00:00Z'
                    timestamp    = 1777377600000
                    _id          = 'activity-1'
                    userName     = 'user@contoso.com'
                    appName      = 'Microsoft 365'
                    activityType = 'Login'
                    level1       = [pscustomobject]@{
                        level2 = [pscustomobject]@{
                            level3 = [pscustomobject]@{
                                level4 = [pscustomobject]@{
                                    level5 = [pscustomobject]@{
                                        level6 = [pscustomobject]@{
                                            level7 = [pscustomobject]@{
                                                level8 = [pscustomobject]@{
                                                    level9 = [pscustomobject]@{
                                                        level10 = [pscustomobject]@{
                                                            level11 = 'preserved'
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            )

            $null = @($records | Export-XdrAzureDataExplorer -Source 'CloudAppsActivityTimeline' -TempPath $TestDrive -KeepTempFiles -DisableCompression)

            $stagedJsonPath = Get-ChildItem -Path $TestDrive -Recurse -Filter '*.json' | Select-Object -First 1 -ExpandProperty FullName
            $stagedJson = @(Get-Content -Path $stagedJsonPath -Raw | ConvertFrom-Json)

            $stagedJson[0].level1.level2.level3.level4.level5.level6.level7.level8.level9.level10.level11 | Should -Be 'preserved'
        }

        It 'routes Cloud Apps timeline alias to the typed Cloud Apps table' {
            $records = @(
                [pscustomobject]@{
                    timestamp    = 1777377600000
                    _id          = 'activity-1'
                    userName     = 'user@contoso.com'
                    appName      = 'Microsoft 365'
                    activityType = 'Login'
                }
            )

            $null = @($records | Export-XdrAzureDataExplorer -Source 'CloudAppsTimeline' -TempPath $TestDrive)

            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $TableName -eq 'XDRCloudAppsActivityTimeline'
            }
        }

        It 'returns original objects with PassThru in Source mode' {
            $records = @(
                [pscustomobject]@{ ActionType = 'ProcessCreated'; DeviceId = 'device-pass-1' },
                [pscustomobject]@{ ActionType = 'FileCreated'; DeviceId = 'device-pass-2' }
            )

            $result = @($records | Export-XdrAzureDataExplorer -Source 'DeviceTimeline' -TempPath $TestDrive -PassThru)

            $result.Count | Should -Be 2
            $result[0].DeviceId | Should -Be 'device-pass-1'
            $result[1].DeviceId | Should -Be 'device-pass-2'
        }

        It 'waits for ingestion for each typed table when WaitForIngestion is specified' {
            $records = @(
                [pscustomobject]@{ ActionType = 'ProcessCreated'; Machine = @{ MachineId = 'm1' } },
                [pscustomobject]@{ ActionType = 'FileCreated'; Machine = @{ MachineId = 'm2' } }
            )

            $null = @($records | Export-XdrAzureDataExplorer -Source 'DeviceTimeline' -TempPath $TestDrive -WaitForIngestion)

            Should -Invoke Send-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 2 -Exactly -ParameterFilter {
                $TrackIngestion
            }
            Should -Invoke Wait-XdrAzureDataExplorerQueuedIngestion -ModuleName XDRInternals -Times 2 -Exactly
        }
    }

    Describe 'Invoke-XdrAzureDataExplorerQuery' {
        BeforeEach {
            InModuleScope XDRInternals {
                $script:AzureDataExplorerConnection = [pscustomobject]@{
                    ClusterUri              = [uri]'https://contoso.westeurope.kusto.windows.net'
                    IngestionUri            = [uri]'https://ingest-contoso.westeurope.kusto.windows.net'
                    Database                = 'Investigations'
                    TenantId                = $null
                    ManagedIdentityClientId = $null
                    AccessToken             = $null
                }
            }
        }

        It 'sends a regular KQL query to the v2 query endpoint' {
            InModuleScope XDRInternals {
                Mock Get-XdrAzureAccessToken { return 'mock-token' }
                Mock Invoke-XdrAzureDataExplorerRestRequest {
                    return @(
                        @{ FrameType = 'DataSetHeader'; IsProgressive = $false },
                        @{ FrameType = 'DataTable'; TableKind = 'QueryProperties'; Columns = @(); Rows = @() },
                        @{ FrameType = 'DataTable'; TableKind = 'PrimaryResult'; Columns = @(
                                @{ ColumnName = 'Col1'; ColumnType = 'string' },
                                @{ ColumnName = 'Col2'; ColumnType = 'long' }
                            ); Rows = @(
                                , @('value1', 42)
                                , @('value2', 99)
                            )
                        },
                        @{ FrameType = 'DataSetCompletion'; HasErrors = $false }
                    )
                }

                $results = Invoke-XdrAzureDataExplorerQuery -Query 'MyTable | take 10'

                Should -Invoke Invoke-XdrAzureDataExplorerRestRequest -Times 1 -Exactly -ParameterFilter {
                    $Path -eq '/v2/rest/query' -and
                    $Body.db -eq 'Investigations' -and
                    $Body.csl -eq 'MyTable | take 10' -and
                    $TimeoutSec -eq 300
                }

                $results | Should -HaveCount 2
                $results[0].Col1 | Should -Be 'value1'
                $results[0].Col2 | Should -Be 42
                $results[1].Col1 | Should -Be 'value2'
                $results[1].Col2 | Should -Be 99
            }
        }

        It 'uses the shared response-table conversion for regular KQL queries' {
            InModuleScope XDRInternals {
                Mock Get-XdrAzureAccessToken { return 'mock-token' }
                Mock Invoke-XdrAzureDataExplorerRestRequest {
                    @(
                        @{ FrameType = 'DataSetHeader'; IsProgressive = $false },
                        @{ FrameType = 'DataTable'; TableKind = 'PrimaryResult'; Columns = @(
                                @{ ColumnName = 'Col1'; ColumnType = 'string' }
                            ); Rows = @(, @('value1'))
                        },
                        @{ FrameType = 'DataSetCompletion'; HasErrors = $false }
                    )
                }
                Mock ConvertFrom-XdrAzureDataExplorerResponseTable {
                    @([pscustomobject]@{ Col1 = 'converted-value' })
                }

                $results = Invoke-XdrAzureDataExplorerQuery -Query 'MyTable | take 1'

                $results | Should -HaveCount 1
                $results[0].Col1 | Should -Be 'converted-value'

                Should -Invoke ConvertFrom-XdrAzureDataExplorerResponseTable -Times 1 -Exactly -ParameterFilter {
                    $Response.Tables.Count -eq 1 -and
                    $Response.Tables[0].TableKind -eq 'PrimaryResult'
                }
            }
        }

        It 'sends management commands to the v1 mgmt endpoint' {
            InModuleScope XDRInternals {
                Mock Get-XdrAzureAccessToken { return 'mock-token' }
                Mock Invoke-XdrAzureDataExplorerRestRequest {
                    return @{ Tables = @( @{ Columns = @(@{ColumnName = 'Name'; DataType = 'String' }); Rows = @(, @('MyTable')) } ) }
                }

                $results = Invoke-XdrAzureDataExplorerQuery -Query '.show tables'

                Should -Invoke Invoke-XdrAzureDataExplorerRestRequest -Times 1 -Exactly -ParameterFilter {
                    $Path -eq '/v1/rest/mgmt'
                }

                $results | Should -HaveCount 1
                $results[0].Name | Should -Be 'MyTable'
            }
        }

        It 'returns raw response when -Raw is specified' {
            InModuleScope XDRInternals {
                Mock Get-XdrAzureAccessToken { return 'mock-token' }
                $mockResponse = @(
                    @{ FrameType = 'DataSetHeader'; IsProgressive = $false },
                    @{ FrameType = 'DataTable'; TableKind = 'PrimaryResult'; Columns = @(
                            @{ ColumnName = 'Col1'; ColumnType = 'string' }
                        ); Rows = @(, @('value1'))
                    },
                    @{ FrameType = 'DataSetCompletion'; HasErrors = $false }
                )
                Mock Invoke-XdrAzureDataExplorerRestRequest { return $mockResponse }

                $result = Invoke-XdrAzureDataExplorerQuery -Query 'MyTable | take 1' -Raw

                $result | Should -HaveCount 3
                $result[0].FrameType | Should -Be 'DataSetHeader'
            }
        }

        It 'uses -Database parameter to override connection database' {
            InModuleScope XDRInternals {
                Mock Get-XdrAzureAccessToken { return 'mock-token' }
                Mock Invoke-XdrAzureDataExplorerRestRequest {
                    return @(
                        @{ FrameType = 'DataTable'; TableKind = 'PrimaryResult'; Columns = @(); Rows = @() }
                    )
                }

                Invoke-XdrAzureDataExplorerQuery -Query 'MyTable | take 1' -Database 'OtherDB'

                Should -Invoke Invoke-XdrAzureDataExplorerRestRequest -Times 1 -Exactly -ParameterFilter {
                    $Body.db -eq 'OtherDB'
                }
            }
        }

        It 'includes server timeout in request properties' {
            InModuleScope XDRInternals {
                Mock Get-XdrAzureAccessToken { return 'mock-token' }
                Mock Invoke-XdrAzureDataExplorerRestRequest {
                    return @(
                        @{ FrameType = 'DataTable'; TableKind = 'PrimaryResult'; Columns = @(); Rows = @() }
                    )
                }

                Invoke-XdrAzureDataExplorerQuery -Query 'MyTable | take 1' -ServerTimeout ([timespan]::FromMinutes(10))

                Should -Invoke Invoke-XdrAzureDataExplorerRestRequest -Times 1 -Exactly -ParameterFilter {
                    $Body.properties.Options.servertimeout -eq ([timespan]::FromMinutes(10)).ToString()
                }
            }
        }
    }
}
