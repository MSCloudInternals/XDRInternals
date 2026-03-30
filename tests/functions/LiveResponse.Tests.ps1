Describe 'Live Response batching' {
    BeforeAll {
        Import-Module "$global:testroot\..\XDRInternals\XDRInternals.psd1" -Force
    }

    Describe 'Invoke-XdrRateLimitedBatch' {
        It 'does not warn when all items fit in a single batch' {
            InModuleScope XDRInternals {
                $warnings = @()
                $result = @(Invoke-XdrRateLimitedBatch -Items @(1..5) -OperationName 'Example' -ItemScript {
                        param($Item, $SharedParameters)
                        $Item
                    } -WarningVariable warnings)

                $result.Count | Should -Be 5
                $warnings.Count | Should -Be 0
            }
        }

        It 'warns when multiple batches are required' {
            InModuleScope XDRInternals {
                $warnings = @()
                $result = @(Invoke-XdrRateLimitedBatch -Items @(1..11) -OperationName 'Example' -ItemScript {
                        param($Item, $SharedParameters)
                        $Item
                    } -BatchDelaySeconds 0 -WarningVariable warnings)

                $result.Count | Should -Be 11
                $warnings.Count | Should -Be 1
                $warnings[0].ToString() | Should -Match '11 items in 2 minute\(s\)'
            }
        }

        It 'invokes batch and completion callbacks' {
            InModuleScope XDRInternals {
                $startedBatches = [System.Collections.Generic.List[object]]::new()
                $completedItems = [System.Collections.Generic.List[int]]::new()

                $null = Invoke-XdrRateLimitedBatch -Items @(1..11) -OperationName 'Example' -ItemScript {
                    param($Item, $SharedParameters)
                    $Item
                } -BatchDelaySeconds 0 -BatchStartedScript {
                    param($BatchNumber, $TotalBatches, $Items)

                    $startedBatches.Add([PSCustomObject]@{
                            BatchNumber  = $BatchNumber
                            TotalBatches = $TotalBatches
                            Count        = @($Items).Count
                        }) | Out-Null
                } -ItemCompletedScript {
                    param($BatchNumber, $TotalBatches, $Result)

                    if ($Result.Success) {
                        $completedItems.Add([int]$Result.Item) | Out-Null
                    }
                }

                $startedBatches.Count | Should -Be 2
                $startedBatches[0].BatchNumber | Should -Be 1
                $startedBatches[0].TotalBatches | Should -Be 2
                $startedBatches[0].Count | Should -Be 10
                $startedBatches[1].Count | Should -Be 1
                @($completedItems | Sort-Object) | Should -Be @(1..11)
            }
        }
    }

    Describe 'Connect-XdrEndpointDeviceLiveResponse -NonInteractive' {
        BeforeEach {
            Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
            Mock Get-XdrRequestContextSnapshot {
                [PSCustomObject]@{
                    BaseUrl     = 'https://security.microsoft.com'
                    CookieData  = @()
                    HeadersData = @{}
                }
            } -ModuleName XDRInternals
        }

        It 'throws when more than 50 devices are piped to noninteractive connect' {
            $devices = 1..51 | ForEach-Object {
                [PSCustomObject]@{
                    SenseMachineId = ('{0:x40}' -f $_)
                }
            }

            {
                $devices | Connect-XdrEndpointDeviceLiveResponse -NonInteractive -WarningAction SilentlyContinue | Out-Null
            } | Should -Throw '*maximum of 50*'
        }

        It 'buffers all piped devices into a single rate-limited batch call' {
            Mock Invoke-XdrRateLimitedBatch {
                param($Items)

                @($Items | ForEach-Object {
                        [PSCustomObject]@{
                            Success   = $true
                            Item      = $_
                            ErrorText = $null
                            Result    = [PSCustomObject]@{
                                SessionId = "CLR-$($_.DeviceId.Substring(0, 6))"
                                DeviceId  = $_.DeviceId
                            }
                        }
                    })
            } -ModuleName XDRInternals

            $devices = 1..27 | ForEach-Object {
                [PSCustomObject]@{
                    SenseMachineId  = ('{0:x40}' -f $_)
                    ComputerDnsName = "device$_"
                    LastSeen        = '2026-03-25T12:34:56Z'
                    OsPlatform      = 'Windows10'
                }
            }

            $result = @($devices | Connect-XdrEndpointDeviceLiveResponse -NonInteractive -WarningAction SilentlyContinue)

            $result.Count | Should -Be 27
            Should -Invoke Invoke-XdrRateLimitedBatch -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $OperationName -eq 'Connect-XdrEndpointDeviceLiveResponse -NonInteractive' -and
                $Items.Count -eq 27 -and
                $Items[0].DeviceName -eq 'device1' -and
                $Items[0].LastSeen -eq '2026-03-25T12:34:56Z' -and
                $Items[0].OsPlatform -eq 'Windows10'
            }
        }

        It 'suppresses the live status table when NoStatusTable is used' {
            Mock Invoke-XdrRateLimitedBatch {
                param($Items, $BatchStartedScript, $ItemCompletedScript)

                if ($BatchStartedScript) {
                    & $BatchStartedScript -BatchNumber 1 -TotalBatches 1 -Items $Items
                }

                $results = @($Items | ForEach-Object {
                        $result = [PSCustomObject]@{
                            Success   = $true
                            Item      = $_
                            ErrorText = $null
                            Result    = [PSCustomObject]@{
                                SessionId          = "CLR-$($_.DeviceId.Substring(0, 6))"
                                DeviceId           = $_.DeviceId
                                DeviceName         = $_.DeviceName
                                OsPlatform         = $_.OsPlatform
                                CurrentDirectory   = 'C:\'
                                CommandDefinitions = @()
                                AvailableCommands  = @('processes')
                                ConnectedOnUtc     = '2026-03-26T05:00:00Z'
                            }
                        }

                        if ($ItemCompletedScript) {
                            & $ItemCompletedScript -BatchNumber 1 -TotalBatches 1 -Result $result
                        }

                        $result
                    })

                @($results)
            } -ModuleName XDRInternals
            Mock Write-Host {} -ModuleName XDRInternals

            $devices = 1..2 | ForEach-Object {
                [PSCustomObject]@{
                    SenseMachineId  = ('{0:x40}' -f $_)
                    ComputerDnsName = "device$_"
                    LastSeen        = '2026-03-25T12:34:56Z'
                    OsPlatform      = 'Windows10'
                }
            }

            $result = @($devices | Connect-XdrEndpointDeviceLiveResponse -NonInteractive -NoStatusTable -WarningAction SilentlyContinue)

            $result.Count | Should -Be 2
            Should -Invoke Write-Host -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'updates the live status title as items complete' {
            $hostLines = [System.Collections.Generic.List[string]]::new()

            Mock Invoke-XdrRateLimitedBatch {
                param($Items, $BatchStartedScript, $ItemCompletedScript)

                if ($BatchStartedScript) {
                    & $BatchStartedScript -BatchNumber 1 -TotalBatches 1 -Items $Items
                }

                $results = @()
                foreach ($item in @($Items)) {
                    $result = [PSCustomObject]@{
                        Success   = $true
                        Item      = $item
                        ErrorText = $null
                        Result    = [PSCustomObject]@{
                            SessionId          = "CLR-$($item.DeviceId.Substring(0, 6))"
                            DeviceId           = $item.DeviceId
                            DeviceName         = $item.DeviceName
                            OsPlatform         = $item.OsPlatform
                            CurrentDirectory   = 'C:\'
                            CommandDefinitions = @()
                            AvailableCommands  = @('processes')
                            ConnectedOnUtc     = '2026-03-26T05:00:00Z'
                        }
                    }

                    if ($ItemCompletedScript) {
                        & $ItemCompletedScript -BatchNumber 1 -TotalBatches 1 -Result $result
                    }

                    $results += $result
                }

                @($results)
            } -ModuleName XDRInternals
            Mock Write-Host {
                param($Object, $ForegroundColor, [switch]$NoNewline)
                if (-not $NoNewline -and $null -ne $Object) {
                    $hostLines.Add([string]$Object) | Out-Null
                }
            } -ModuleName XDRInternals

            $devices = 1..2 | ForEach-Object {
                [PSCustomObject]@{
                    SenseMachineId  = ('{0:x40}' -f $_)
                    ComputerDnsName = "device$_"
                    LastSeen        = '2026-03-25T12:34:56Z'
                    OsPlatform      = 'Windows10'
                }
            }

            $result = @($devices | Connect-XdrEndpointDeviceLiveResponse -NonInteractive -WarningAction SilentlyContinue)

            $result.Count | Should -Be 2
            @($hostLines | Where-Object { $_ -like 'Connecting Live Response sessions:*' } | ForEach-Object { $_.TrimEnd() }) | Should -Contain 'Connecting Live Response sessions: 1/2 completed'
            @($hostLines | Where-Object { $_ -like 'Connecting Live Response sessions:*' } | ForEach-Object { $_.TrimEnd() }) | Should -Contain 'Connecting Live Response sessions: 2/2 completed'
        }
    }

    Describe 'Invoke-XdrEndpointDeviceLiveResponseCommand' {
        BeforeEach {
            Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
            Mock Get-XdrRequestContextSnapshot {
                [PSCustomObject]@{
                    BaseUrl     = 'https://security.microsoft.com'
                    CookieData  = @()
                    HeadersData = @{}
                }
            } -ModuleName XDRInternals
        }

        It 'unwraps nested command definitions for alias and positional parsing' {
            $createCommandBodies = [System.Collections.Generic.List[object]]::new()

            Mock Invoke-RestMethod {
                if ($Uri -like '*create_command*') {
                    $createCommandBodies.Add(($Body | ConvertFrom-Json -Depth 10)) | Out-Null
                    return [PSCustomObject]@{ command_id = 'cmd-1' }
                }

                if ($Uri -like '*commands/cmd-1*') {
                    return [PSCustomObject]@{
                        command_id            = 'cmd-1'
                        command_definition_id = 'dir'
                        raw_command_line      = 'ls C:\Windows'
                        status                = 1
                        completed_on          = '2026-03-26T06:30:00Z'
                        outputs               = @()
                        errors                = @()
                    }
                }

                throw "Unexpected Uri: $Uri"
            } -ModuleName XDRInternals

            $nestedDefinitions = @(
                @(
                    [PSCustomObject]@{
                        command_definition_id = 'dir'
                        aliases               = @('ls')
                        params                = @(
                            [PSCustomObject]@{
                                param_id = 'path'
                                optional = $true
                                isHidden = $false
                            }
                        )
                        flags                 = @()
                    }
                )
            )

            $result = @(Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId 'CLR1' -Command 'ls C:\Windows' -CommandDefinitions $nestedDefinitions -WarningAction SilentlyContinue)

            $result.Count | Should -Be 1
            $result[0].PSObject.TypeNames[0] | Should -Be 'XdrEndpointDeviceLiveResponseCommand'
            $createCommandBodies.Count | Should -Be 1
            $createCommandBodies[0].command_definition_id | Should -Be 'dir'
            $createCommandBodies[0].params.Count | Should -Be 1
            $createCommandBodies[0].params[0].param_id | Should -Be 'path'
            $createCommandBodies[0].params[0].value | Should -Be 'C:\Windows'
            $createCommandBodies[0].raw_command_line | Should -Be 'ls C:\Windows'
        }

        It 'batches piped session objects and preserves session properties' {
            Mock Invoke-XdrRateLimitedBatch {
                param($Items)

                @($Items | ForEach-Object {
                        [PSCustomObject]@{
                            Success   = $true
                            Item      = $_
                            ErrorText = $null
                            Result    = [PSCustomObject]@{
                                SessionId        = $_.SessionId
                                Status           = 1
                                completed_on     = '2026-03-25T12:34:56Z'
                                raw_command_line = 'processes'
                            }
                        }
                    })
            } -ModuleName XDRInternals

            $sessions = 1..12 | ForEach-Object {
                [PSCustomObject]@{
                    SessionId          = "CLR$_"
                    DeviceId           = ('{0:x40}' -f $_)
                    DeviceName         = "device$_"
                    CurrentDirectory   = '/'
                    CommandDefinitions = @([PSCustomObject]@{ command_definition_id = 'processes' })
                }
            }

            $result = @($sessions | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -WarningAction SilentlyContinue)

            $result.Count | Should -Be 12
            $result[0].DeviceId | Should -Be ('{0:x40}' -f 1)
            $result[0].DeviceName | Should -Be 'device1'
            $result[0].Timestamp | Should -Be ([datetime]'2026-03-25T12:34:56Z')
            $result[0].ShortDeviceId | Should -Be ((('{0:x40}' -f 1).Substring(0, 12)) + '...')
            $result[0].StatusText | Should -Be 'Completed'
            Should -Invoke Invoke-XdrRateLimitedBatch -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $OperationName -eq 'Invoke-XdrEndpointDeviceLiveResponseCommand' -and
                $Items.Count -eq 12 -and
                (@($Items | Where-Object { $_.CurrentDirectory -ne '/' }).Count -eq 0) -and
                (@($Items | Where-Object { [string]::IsNullOrWhiteSpace($_.DeviceId) }).Count -eq 0) -and
                (@($Items | Where-Object { [string]::IsNullOrWhiteSpace($_.DeviceName) }).Count -eq 0) -and
                (@($Items | Where-Object { $_.Command -ne 'processes' }).Count -eq 0) -and
                (@($Items | Where-Object { @($_.CommandDefinitions).Count -eq 0 }).Count -eq 0)
            }
        }

        It 'accepts piped session id strings for batch execution' {
            Mock Invoke-XdrRateLimitedBatch {
                param($Items)

                @($Items | ForEach-Object {
                        [PSCustomObject]@{
                            Success   = $true
                            Item      = $_
                            ErrorText = $null
                            Result    = [PSCustomObject]@{
                                SessionId = $_.SessionId
                                Status    = 1
                            }
                        }
                    })
            } -ModuleName XDRInternals

            $result = @('CLR100', 'CLR200' | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -WarningAction SilentlyContinue)

            $result.Count | Should -Be 2
            Should -Invoke Invoke-XdrRateLimitedBatch -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $OperationName -eq 'Invoke-XdrEndpointDeviceLiveResponseCommand' -and
                $Items.Count -eq 2 -and
                $Items[0].SessionId -eq 'CLR100' -and
                $Items[1].SessionId -eq 'CLR200'
            }
        }

        It 'can expand table output rows with stamped metadata' {
            Mock Invoke-RestMethod {
                if ($Uri -like '*create_command*') {
                    return [PSCustomObject]@{ command_id = 'cmd-1' }
                }

                if ($Uri -like '*commands/cmd-1*') {
                    return [PSCustomObject]@{
                        SessionId        = 'CLR1'
                        session_id       = 'CLR1'
                        status           = 1
                        completed_on     = '2026-03-25T12:34:56Z'
                        raw_command_line = 'processes'
                        duration_seconds = 2.5
                        outputs          = @(
                            [PSCustomObject]@{
                                data_type = 'table'
                                data      = @(
                                    [PSCustomObject]@{ name = 'proc1'; pid = 100 },
                                    [PSCustomObject]@{ name = 'proc2'; pid = 200 }
                                )
                            }
                        )
                    }
                }

                throw "Unexpected Uri: $Uri"
            } -ModuleName XDRInternals

            $sessions = @(
                [PSCustomObject]@{
                    SessionId          = 'CLR1'
                    DeviceId           = ('{0:x40}' -f 1)
                    DeviceName         = 'device1'
                    CurrentDirectory   = '/'
                    CommandDefinitions = @([PSCustomObject]@{ command_definition_id = 'processes' })
                }
            )

            $result = @($sessions | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -ExpandTableOutput -WarningAction SilentlyContinue)

            $result.Count | Should -Be 2
            $result[0].PSObject.TypeNames[0] | Should -Be 'XdrEndpointDeviceLiveResponseProcessRow'
            $result[0].DeviceName | Should -Be 'device1'
            $result[0].DeviceId | Should -Be ('{0:x40}' -f 1)
            $result[0].StatusText | Should -Be 'Completed'
            $result[0].Command | Should -Be 'processes'
            $result[0].Name | Should -Be 'proc1'
            $result[1].Pid | Should -Be 200
        }

        It 'auto-expands structured command results by default' {
            Mock Invoke-RestMethod {
                if ($Uri -like '*create_command*') {
                    return [PSCustomObject]@{ command_id = 'cmd-1' }
                }

                if ($Uri -like '*commands/cmd-1*') {
                    return [PSCustomObject]@{
                        SessionId             = 'CLR1'
                        session_id            = 'CLR1'
                        command_definition_id = 'processes'
                        status                = 1
                        completed_on          = '2026-03-25T12:34:56Z'
                        raw_command_line      = 'processes'
                        duration_seconds      = 2.5
                        outputs               = @(
                            [PSCustomObject]@{
                                data_type = 'table'
                                data      = @(
                                    [PSCustomObject]@{ name = 'proc2'; pid = 200; parent_id = 1; user_name = 'user2'; status = 'Running'; 'memory (K)' = 100; 'cpu_cycles (K)' = 2 },
                                    [PSCustomObject]@{ name = 'proc1'; pid = 100; parent_id = 1; user_name = 'user1'; status = 'Running'; 'memory (K)' = 500; 'cpu_cycles (K)' = 10 }
                                )
                            }
                        )
                    }
                }

                throw "Unexpected Uri: $Uri"
            } -ModuleName XDRInternals

            $session = [PSCustomObject]@{
                SessionId          = 'CLR1'
                DeviceId           = ('{0:x40}' -f 1)
                DeviceName         = 'device1'
                CurrentDirectory   = '/'
                CommandDefinitions = @([PSCustomObject]@{ command_definition_id = 'processes' })
            }

            $result = @($session | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -WarningAction SilentlyContinue)

            $result.Count | Should -Be 2
            $result[0].PSObject.TypeNames[0] | Should -Be 'XdrEndpointDeviceLiveResponseProcessRow'
            $result[0].Name | Should -Be 'proc1'
            $result[1].Name | Should -Be 'proc2'
        }

        It 'can return the raw command result without structured expansion' {
            Mock Invoke-RestMethod {
                if ($Uri -like '*create_command*') {
                    return [PSCustomObject]@{ command_id = 'cmd-1' }
                }

                if ($Uri -like '*commands/cmd-1*') {
                    return [PSCustomObject]@{
                        SessionId             = 'CLR1'
                        session_id            = 'CLR1'
                        command_definition_id = 'processes'
                        status                = 1
                        completed_on          = '2026-03-25T12:34:56Z'
                        raw_command_line      = 'processes'
                        duration_seconds      = 2.5
                        outputs               = @(
                            [PSCustomObject]@{
                                data_type = 'table'
                                data      = @(
                                    [PSCustomObject]@{ name = 'proc1'; pid = 100 }
                                )
                            }
                        )
                    }
                }

                throw "Unexpected Uri: $Uri"
            } -ModuleName XDRInternals

            $session = [PSCustomObject]@{
                SessionId          = 'CLR1'
                DeviceId           = ('{0:x40}' -f 1)
                DeviceName         = 'device1'
                CurrentDirectory   = '/'
                CommandDefinitions = @([PSCustomObject]@{ command_definition_id = 'processes' })
            }

            $result = @($session | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -RawCommandResult -WarningAction SilentlyContinue)

            $result.Count | Should -Be 1
            $result[0].PSObject.TypeNames[0] | Should -Be 'XdrEndpointDeviceLiveResponseCommand'
            $result[0].Command | Should -Be 'processes'
            $result[0].outputs.Count | Should -Be 1
        }

        It 'sorts expanded rows by device name across batch results' {
            Mock Invoke-XdrRateLimitedBatch {
                param($Items)

                @($Items | ForEach-Object {
                        [PSCustomObject]@{
                            Success   = $true
                            Item      = $_
                            ErrorText = $null
                            Result    = [PSCustomObject]@{
                                SessionId             = $_.SessionId
                                session_id            = $_.SessionId
                                command_definition_id = 'processes'
                                status                = 1
                                completed_on          = '2026-03-25T12:34:56Z'
                                raw_command_line      = 'processes'
                                duration_seconds      = 2.5
                                outputs               = @(
                                    [PSCustomObject]@{
                                        data_type = 'table'
                                        data      = @(
                                            [PSCustomObject]@{ name = $_.DeviceName; pid = 100; parent_id = 1; user_name = 'user'; status = 'Running'; 'memory (K)' = 100; 'cpu_cycles (K)' = 1 }
                                        )
                                    }
                                )
                            }
                        }
                    })
            } -ModuleName XDRInternals

            $sessions = @(
                [PSCustomObject]@{ SessionId = 'CLR2'; DeviceId = ('{0:x40}' -f 2); DeviceName = 'device-b'; CurrentDirectory = '/'; CommandDefinitions = @([PSCustomObject]@{ command_definition_id = 'processes' }) },
                [PSCustomObject]@{ SessionId = 'CLR1'; DeviceId = ('{0:x40}' -f 1); DeviceName = 'device-a'; CurrentDirectory = '/'; CommandDefinitions = @([PSCustomObject]@{ command_definition_id = 'processes' }) }
            )

            $result = @($sessions | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -WarningAction SilentlyContinue)

            $result.Count | Should -Be 2
            $result[0].DeviceName | Should -Be 'device-a'
            $result[1].DeviceName | Should -Be 'device-b'
        }

        It 'flattens persistence object output into rows' {
            Mock Invoke-RestMethod {
                if ($Uri -like '*create_command*') {
                    return [PSCustomObject]@{ command_id = 'cmd-1' }
                }

                if ($Uri -like '*commands/cmd-1*') {
                    return [PSCustomObject]@{
                        SessionId             = 'CLR1'
                        session_id            = 'CLR1'
                        command_definition_id = 'persistence'
                        status                = 1
                        completed_on          = '2026-03-25T12:34:56Z'
                        raw_command_line      = 'persistence'
                        duration_seconds      = 2.5
                        outputs               = @(
                            [PSCustomObject]@{
                                data_type = 'object'
                                data      = [PSCustomObject]@{
                                    autoruns = [PSCustomObject]@{
                                        startup_folders = @(
                                            [PSCustomObject]@{ filePath = 'C:\\Startup\\a.lnk'; executablePath = 'C:\\App\\a.exe'; category = '.lnk file' }
                                        )
                                        registry        = @(
                                            [PSCustomObject]@{ reg_path = 'HKLM\\Software\\Run'; display_name = 'Run -> App'; value_name = 'App'; value_type = 'REG_SZ'; value = 'C:\\App\\a.exe' }
                                        )
                                        schedule_tasks  = @(
                                            [PSCustomObject]@{
                                                id         = '\\TaskA'
                                                is_enabled = $true
                                                task       = [PSCustomObject]@{
                                                    registrationInfo = [PSCustomObject]@{ uri = '\\TaskA' }
                                                    principals       = [PSCustomObject]@{ principal = [PSCustomObject]@{ userId = 'SYSTEM'; id = 'Author' } }
                                                    actions          = [PSCustomObject]@{
                                                        exec = @([PSCustomObject]@{ command = 'cmd.exe'; arguments = '/c whoami' })
                                                    }
                                                }
                                            }
                                        )
                                    }
                                }
                            }
                        )
                    }
                }

                throw "Unexpected Uri: $Uri"
            } -ModuleName XDRInternals

            $session = [PSCustomObject]@{
                SessionId        = 'CLR1'
                DeviceId         = ('{0:x40}' -f 1)
                DeviceName       = 'device1'
                CurrentDirectory = '/'
            }

            $result = @($session | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'persistence' -WarningAction SilentlyContinue)

            $result.Count | Should -Be 3
            $result[0].PSObject.TypeNames[0] | Should -Be 'XdrEndpointDeviceLiveResponsePersistenceRow'
            $result[0].Category | Should -Be 'Registry'
            $result[1].Category | Should -Be 'ScheduledTask'
            $result[2].Category | Should -Be 'StartupFolder'
        }

        It 'can include the command result alongside expanded table rows' {
            Mock Invoke-RestMethod {
                if ($Uri -like '*create_command*') {
                    return [PSCustomObject]@{ command_id = 'cmd-1' }
                }

                if ($Uri -like '*commands/cmd-1*') {
                    return [PSCustomObject]@{
                        SessionId        = 'CLR1'
                        session_id       = 'CLR1'
                        status           = 1
                        completed_on     = '2026-03-25T12:34:56Z'
                        raw_command_line = 'processes'
                        duration_seconds = 2.5
                        outputs          = @(
                            [PSCustomObject]@{
                                data_type = 'table'
                                data      = @(
                                    [PSCustomObject]@{ name = 'proc1'; pid = 100 },
                                    [PSCustomObject]@{ name = 'proc2'; pid = 200 }
                                )
                            }
                        )
                    }
                }

                throw "Unexpected Uri: $Uri"
            } -ModuleName XDRInternals

            $session = [PSCustomObject]@{
                SessionId          = 'CLR1'
                DeviceId           = ('{0:x40}' -f 1)
                DeviceName         = 'device1'
                CurrentDirectory   = '/'
                CommandDefinitions = @([PSCustomObject]@{ command_definition_id = 'processes' })
            }

            $result = @($session | Invoke-XdrEndpointDeviceLiveResponseCommand -Command 'processes' -ExpandTableOutput -IncludeCommandResult -WarningAction SilentlyContinue)

            $result.Count | Should -Be 3
            $result[0].PSObject.TypeNames[0] | Should -Be 'XdrEndpointDeviceLiveResponseCommand'
            $result[0].Command | Should -Be 'processes'
            $result[0].SessionId | Should -Be 'CLR1'
            $result[0].DurationSeconds | Should -Be 2.5
            $result[1].PSObject.TypeNames[0] | Should -Be 'XdrEndpointDeviceLiveResponseProcessRow'
            $result[2].Name | Should -Be 'proc2'
        }
    }

    Describe 'Disconnect-XdrEndpointDeviceLiveResponse' {
        BeforeEach {
            Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    success    = $true
                    session_id = $Body | ConvertFrom-Json | Select-Object -ExpandProperty session_id
                }
            } -ModuleName XDRInternals
        }

        It 'accepts piped session objects by SessionId property' {
            $sessions = @(
                [PSCustomObject]@{ SessionId = 'CLR100' },
                [PSCustomObject]@{ SessionId = 'CLR200' }
            )

            $result = @($sessions | Disconnect-XdrEndpointDeviceLiveResponse)

            $result.Count | Should -Be 2
            $result[0].session_id | Should -Be 'CLR100'
            $result[1].session_id | Should -Be 'CLR200'
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly -ParameterFilter {
                $Uri -like '*close_session*'
            }
        }

        It 'accepts piped raw session id strings' {
            $result = @('CLR100', 'CLR200' | Disconnect-XdrEndpointDeviceLiveResponse)

            $result.Count | Should -Be 2
            $result[0].session_id | Should -Be 'CLR100'
            $result[1].session_id | Should -Be 'CLR200'
        }
    }
}