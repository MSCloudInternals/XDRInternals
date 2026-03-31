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

            Mock Get-AzAccessToken {
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

            Should -Invoke Get-AzAccessToken -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'prefers the Azure CLI public client bridge for Azure Data Explorer' {
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

            Mock Get-AzAccessToken {
                throw 'Az.Accounts should not be used when the Azure CLI-style bridge succeeds.'
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $token = Get-XdrAzureAccessToken -Resource 'https://api.kusto.windows.net' `
                    -Scope 'https://contoso.westeurope.kusto.windows.net/.default' `
                    -ResourceDisplayName 'Azure Data Explorer'

                $token | Should -Be 'bridge-adx-token'
            }

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

            Should -Invoke Get-AzAccessToken -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'falls back to Az.Accounts when the ADX bridge cannot complete silently' {
            Mock Invoke-WebRequest {
                [pscustomobject]@{
                    Headers      = @{ Location = 'https://login.microsoftonline.com/common/oauth2/nativeclient?error=interaction_required&error_description=Need%20user%20interaction' }
                    BaseResponse = [pscustomobject]@{
                        ResponseUri = [uri]'https://login.microsoftonline.com/organizations/oauth2/authorize'
                        Headers     = @{ Location = 'https://login.microsoftonline.com/common/oauth2/nativeclient?error=interaction_required&error_description=Need%20user%20interaction' }
                    }
                }
            } -ModuleName XDRInternals

            Mock Invoke-RestMethod {
                throw 'The token endpoint should not be called when silent auth returns interaction_required.'
            } -ModuleName XDRInternals

            Mock Get-AzAccessToken {
                [pscustomobject]@{
                    Token = 'az-fallback-token'
                }
            } -ModuleName XDRInternals

            InModuleScope XDRInternals {
                $token = Get-XdrAzureAccessToken -Resource 'https://api.kusto.windows.net' `
                    -Scope 'https://contoso.westeurope.kusto.windows.net/.default' `
                    -ResourceDisplayName 'Azure Data Explorer'

                $token | Should -Be 'az-fallback-token'
            }

            Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/authorize*' -and
                $Uri -notlike 'https://login.microsoftonline.com/*/oauth2/v2.0/authorize*'
            }

            Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 0 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/authorize*'
            }

            Should -Invoke Get-AzAccessToken -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $ResourceUrl -eq 'https://api.kusto.windows.net'
            }

            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/*/oauth2/v2.0/token'
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
                    $p.TableName       | Should -Not -BeNullOrEmpty -Because "'$key' needs TableName"
                    $p.Source          | Should -Not -BeNullOrEmpty -Because "'$key' needs Source"
                    $p.ContainsKey('RoutingField')  | Should -BeTrue -Because "'$key' needs RoutingField key"
                    $p.ContainsKey('RoutingValues') | Should -BeTrue -Because "'$key' needs RoutingValues key"
                    $p.ColumnMappings  | Should -Not -BeNullOrEmpty -Because "'$key' needs ColumnMappings"
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
                    ActionTime     = '2024-06-15T10:30:00Z'
                    ActionType     = 'ProcessCreated'
                    ReportId       = 12345
                    SourceProvider = 'MDE'
                    Machine        = [pscustomobject]@{
                        MachineId = 'machine-abc'
                        Name      = 'WORKSTATION01'
                    }
                    Process        = [pscustomobject]@{
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

                $record                        | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
                $record['ActionTime']          | Should -Be '2024-06-15T10:30:00Z'
                $record['ActionType']          | Should -Be 'ProcessCreated'
                $record['MachineId']           | Should -Be 'machine-abc'
                $record['MachineName']         | Should -Be 'WORKSTATION01'
                $record['ProcessId']           | Should -Be 1234
                $record['ProcessFileName']     | Should -Be 'cmd.exe'
                $record['ProcessCommandLine']  | Should -Be 'cmd.exe /c whoami'
                $record['ProcessSha1']         | Should -Be 'abc123sha1'
                $record['ProcessAccountName']  | Should -Be 'testuser'
                $record['ProcessAccountDomain'] | Should -Be 'CONTOSO'
                $record['ProcessAccountSid']   | Should -Be 'S-1-5-21-123'
                $record['InitiatingProcessId'] | Should -Be 5678
                $record['InitiatingProcessFileName']    | Should -Be 'explorer.exe'
                $record['InitiatingProcessAccountName'] | Should -Be 'testuser'
                $record['ReportId']            | Should -Be 12345
                $record['SourceProvider']      | Should -Be 'MDE'
                $record['Event']               | Should -Not -BeNullOrEmpty
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

                $record['ActionTime']     | Should -Be '2024-06-15T10:30:00Z'
                $record['ActionType']     | Should -Be 'ProcessCreated'
                $record['MachineId']      | Should -BeNullOrEmpty
                $record['ProcessId']      | Should -BeNullOrEmpty
                $record['ProcessFileName'] | Should -BeNullOrEmpty
                $record['Event']          | Should -Not -BeNullOrEmpty
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
                            ,@('value1', 42)
                            ,@('value2', 99)
                        ) },
                        @{ FrameType = 'DataSetCompletion'; HasErrors = $false }
                    )
                }

                $results = Invoke-XdrAzureDataExplorerQuery -Query 'MyTable | take 10'

                Should -Invoke Invoke-XdrAzureDataExplorerRestRequest -Times 1 -Exactly -ParameterFilter {
                    $Path -eq '/v2/rest/query' -and
                    $Body.db -eq 'Investigations' -and
                    $Body.csl -eq 'MyTable | take 10'
                }

                $results | Should -HaveCount 2
                $results[0].Col1 | Should -Be 'value1'
                $results[0].Col2 | Should -Be 42
                $results[1].Col1 | Should -Be 'value2'
                $results[1].Col2 | Should -Be 99
            }
        }

        It 'sends management commands to the v1 mgmt endpoint' {
            InModuleScope XDRInternals {
                Mock Get-XdrAzureAccessToken { return 'mock-token' }
                Mock Invoke-XdrAzureDataExplorerRestRequest {
                    return @{ Tables = @( @{ Columns = @(@{ColumnName='Name';DataType='String'}); Rows = @(,@('MyTable')) } ) }
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
                    ); Rows = @(,@('value1')) },
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
