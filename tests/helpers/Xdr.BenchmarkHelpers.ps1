Set-StrictMode -Version Latest

$sharedHelperPath = Join-Path $PSScriptRoot 'Xdr.TestHelpers.ps1'
. $sharedHelperPath

function Get-XdrBenchmarkDefaultSettings {
    $testDefaults = Get-XdrDefaultTestSettings

    return @{
        benchmarks     = @{
            enabled = $false
        }
        authentication = $testDefaults.authentication
        execution      = @{
            resultsRoot                  = 'TestResults\Benchmarks'
            repeats                      = 3
            sequentialScenariosOnly      = $true
            stopOnError                  = $true
            warmupRun                    = $false
            defaultOutputFormat          = 'Json'
            defaultPageSize              = 999
            defaultChunkHours            = 0
            defaultThrottleLimit         = 16
            defaultDeviceConcurrency     = 1
            defaultRequestTimeoutSeconds = 60
            defaultMaxRetries            = 10
            defaultRetryDelaySeconds     = 30
            defaultPaginationDelayMinMilliseconds = 0
            defaultPaginationDelayMaxMilliseconds = 0
            keepTempFiles                = $false
            workingDirectory             = ''
        }
        branches       = @{
            current = @{
                label      = 'current'
                modulePath = '.\XDRInternals\XDRInternals.psd1'
                repoPath   = '.'
            }
        }
        devices        = @()
        windows        = @{
            '24h' = @{ hours = 24 }
            '7d'  = @{ days = 7 }
            '30d' = @{ days = 30 }
            '60d' = @{ days = 60 }
        }
        scenarios      = @{
            singleDevice      = @()
            concurrentDevices = @()
            saturationSweep   = @()
        }
    }
}

function Get-XdrBenchmarkSettings {
    param(
        [string]$ConfigurationPath
    )

    $settings = Get-XdrBenchmarkDefaultSettings
    $repoRoot = Get-XdrRepoRoot
    $candidatePaths = [System.Collections.Generic.List[string]]::new()

    if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
        $candidatePaths.Add($ConfigurationPath)
    }
    if ($env:XDRINTERNALS_BENCHMARK_CONFIG_PATH) {
        $candidatePaths.Add($env:XDRINTERNALS_BENCHMARK_CONFIG_PATH)
    }

    $candidatePaths.Add((Join-Path $repoRoot 'tests\benchmark.settings.json'))
    $candidatePaths.Add((Join-Path $repoRoot 'tests\benchmark.settings.sample.json'))

    $settingsPath = $null
    foreach ($candidatePath in $candidatePaths) {
        if (-not $candidatePath) {
            continue
        }

        $resolvedCandidate = Resolve-XdrTestPath -Path $candidatePath -BasePath $repoRoot
        if (-not (Test-Path $resolvedCandidate)) {
            continue
        }

        $settingsPath = (Resolve-Path $resolvedCandidate).Path
        $fileSettings = Get-Content -Path $settingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $fileSettings = ConvertTo-XdrHashtable -InputObject $fileSettings
        $settings = Merge-XdrHashtable -Base $settings -Overlay $fileSettings
        break
    }

    if ($env:XDRINTERNALS_ENABLE_BENCHMARKS) {
        $settings.benchmarks.enabled = ConvertTo-XdrBoolean -Value $env:XDRINTERNALS_ENABLE_BENCHMARKS
    }

    if ($env:XDRINTERNALS_TEST_KEYFILE) {
        $settings.authentication.keyFilePath = $env:XDRINTERNALS_TEST_KEYFILE
    }

    $configDirectory = if ($settingsPath) {
        Split-Path -Parent $settingsPath
    } else {
        Join-Path $repoRoot 'tests'
    }

    $settings['__meta'] = @{
        repoRoot           = $repoRoot
        configurationPath  = $settingsPath
        configurationDir   = $configDirectory
    }

    $settings.authentication.keyFilePath = Resolve-XdrBenchmarkPath -Path $settings.authentication.keyFilePath -BasePath $configDirectory
    $settings.execution.resultsRoot = Resolve-XdrBenchmarkPath -Path $settings.execution.resultsRoot -BasePath $repoRoot

    foreach ($branchName in @($settings.branches.Keys)) {
        $branch = $settings.branches[$branchName]
        if (-not $branch.ContainsKey('label') -or [string]::IsNullOrWhiteSpace([string]$branch.label)) {
            $branch.label = $branchName
        }

        if ($branch.ContainsKey('modulePath')) {
            $branch.modulePath = Resolve-XdrBenchmarkPath -Path $branch.modulePath -BasePath $repoRoot
        }
        if ($branch.ContainsKey('repoPath')) {
            $branch.repoPath = Resolve-XdrBenchmarkPath -Path $branch.repoPath -BasePath $repoRoot
        }
    }

    return $settings
}

function Resolve-XdrBenchmarkPath {
    param(
        [string]$Path,
        [string]$BasePath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        if (Test-Path $Path) {
            return (Resolve-Path $Path).Path
        }

        return [System.IO.Path]::GetFullPath($Path)
    }

    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        $BasePath = Get-XdrRepoRoot
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-XdrBenchmarkWindowTable {
    param(
        [hashtable]$Settings,
        [datetime]$CapturedToDate = (Get-Date).ToUniversalTime()
    )

    $windowTable = @{}
    foreach ($windowName in @($Settings.windows.Keys)) {
        $windowDefinition = $Settings.windows[$windowName]
        $hours = 0.0
        if ($windowDefinition.ContainsKey('hours')) {
            $hours += [double]$windowDefinition.hours
        }
        if ($windowDefinition.ContainsKey('days')) {
            $hours += ([double]$windowDefinition.days * 24)
        }

        if ($hours -le 0) {
            throw "Benchmark window '$windowName' must define a positive number of hours or days."
        }

        $windowTable[$windowName] = @{
            name       = $windowName
            fromDate   = $CapturedToDate.AddHours(-$hours)
            toDate     = $CapturedToDate
            totalHours = [math]::Round($hours, 2)
            totalDays  = [math]::Round($hours / 24, 2)
        }
    }

    return $windowTable
}

function Get-XdrBenchmarkValue {
    param(
        $InputObject,
        [string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject -is [hashtable]) {
        if ($InputObject.ContainsKey($Name)) {
            return $InputObject[$Name]
        }

        return $Default
    }

    $match = $InputObject.PSObject.Properties.Match($Name)
    if ($match.Count -gt 0) {
        return $match[0].Value
    }

    return $Default
}

function Get-XdrBenchmarkScenarioBranchOrder {
    param(
        [string[]]$BranchNames,
        [int]$RepeatNumber
    )

    if ($RepeatNumber % 2 -eq 0) {
        $reversed = @($BranchNames)
        [array]::Reverse($reversed)
        return $reversed
    }

    return @($BranchNames)
}

function Get-XdrBenchmarkRunPlan {
    param(
        [hashtable]$Settings,
        [hashtable]$WindowTable,
        [string]$Include = '*',
        [string]$Exclude = ''
    )

    $deviceTable = @{}
    foreach ($device in @(Get-XdrSequenceItems -InputObject $Settings.devices)) {
        $deviceTable[[string]$device.name] = $device
    }

    $runPlan = [System.Collections.Generic.List[object]]::new()
    $groupOrder = @{
        singleDevice      = 1
        concurrentDevices = 2
        saturationSweep   = 3
    }

    foreach ($scenarioGroup in @('singleDevice', 'concurrentDevices')) {
        foreach ($scenario in @(Get-XdrSequenceItems -InputObject $Settings.scenarios[$scenarioGroup])) {
            $repeats = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'repeats')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'repeats') } else { [int]$Settings.execution.repeats }
            $branchNames = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'branchNames')) | Where-Object { $_ })
            if ($branchNames.Count -eq 0) {
                $branchNames = @($Settings.branches.Keys)
            }

            $windowNames = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'windowNames')) | Where-Object { $_ })
            if ($windowNames.Count -eq 0) {
                throw "Scenario '$($scenario.name)' must define one or more windowNames."
            }

            $deviceSets = @()
            if ($scenarioGroup -eq 'singleDevice') {
                foreach ($deviceName in @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceNames')) | Where-Object { $_ })) {
                    $deviceSets += , @($deviceName)
                }
            } else {
                $deviceSets += , @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceNames')) | Where-Object { $_ })
            }

            foreach ($deviceNames in $deviceSets) {
                foreach ($deviceName in $deviceNames) {
                    if (-not $deviceTable.ContainsKey([string]$deviceName)) {
                        throw "Scenario '$($scenario.name)' references unknown device '$deviceName'."
                    }
                }

                $deviceSetLabel = ($deviceNames -join '+')
                foreach ($windowName in $windowNames) {
                    if (-not $WindowTable.ContainsKey([string]$windowName)) {
                        throw "Scenario '$($scenario.name)' references unknown window '$windowName'."
                    }

                    $baseLabel = "$scenarioGroup/$($scenario.name)/$deviceSetLabel/$windowName"
                    if ($baseLabel -notlike $Include) {
                        continue
                    }
                    if ($Exclude -and $baseLabel -like $Exclude) {
                        continue
                    }

                    for ($repeatIndex = 1; $repeatIndex -le $repeats; $repeatIndex++) {
                        $branchOrder = Get-XdrBenchmarkScenarioBranchOrder -BranchNames $branchNames -RepeatNumber $repeatIndex
                        $orderIndex = 0
                        foreach ($branchName in $branchOrder) {
                            if (-not $Settings.branches.ContainsKey([string]$branchName)) {
                                throw "Scenario '$($scenario.name)' references unknown branch '$branchName'."
                            }

                            $orderIndex++
                            $throttleLimit = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'throttleLimit')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'throttleLimit') } else { [int]$Settings.execution.defaultThrottleLimit }
                            $deviceConcurrency = if ($scenarioGroup -eq 'concurrentDevices') {
                                if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceConcurrency')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceConcurrency') } else { @($deviceNames).Count }
                            } else {
                                1
                            }

                            $runPlan.Add([pscustomobject]@{
                                    groupName            = $scenarioGroup
                                    groupOrder           = $groupOrder[$scenarioGroup]
                                    scenarioName         = [string]$scenario.name
                                    scenarioKey          = $baseLabel
                                    repeatNumber         = $repeatIndex
                                    pairOrder            = $orderIndex
                                    branchName           = [string]$branchName
                                    branchLabel          = [string]$Settings.branches[$branchName].label
                                    windowName           = [string]$windowName
                                    deviceNames          = @($deviceNames)
                                    deviceSetLabel       = $deviceSetLabel
                                    chunkHours           = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'chunkHours')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'chunkHours') } else { [int]$Settings.execution.defaultChunkHours }
                                    throttleLimit        = $throttleLimit
                                    deviceConcurrency    = $deviceConcurrency
                                    requestBudget        = $throttleLimit * [math]::Max(1, $deviceConcurrency)
                                    pageSize             = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'pageSize')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'pageSize') } else { [int]$Settings.execution.defaultPageSize }
                                    outputFormat         = if (Get-XdrBenchmarkValue -InputObject $scenario -Name 'outputFormat') { [string](Get-XdrBenchmarkValue -InputObject $scenario -Name 'outputFormat') } else { [string]$Settings.execution.defaultOutputFormat }
                                    requestTimeoutSeconds = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'requestTimeoutSeconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'requestTimeoutSeconds') } else { [int]$Settings.execution.defaultRequestTimeoutSeconds }
                                    maxRetries           = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'maxRetries')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'maxRetries') } else { [int]$Settings.execution.defaultMaxRetries }
                                    retryDelaySeconds    = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'retryDelaySeconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'retryDelaySeconds') } else { [int]$Settings.execution.defaultRetryDelaySeconds }
                                    paginationDelayMinMilliseconds = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMinMilliseconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMinMilliseconds') } else { [int]$Settings.execution.defaultPaginationDelayMinMilliseconds }
                                    paginationDelayMaxMilliseconds = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMaxMilliseconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMaxMilliseconds') } else { [int]$Settings.execution.defaultPaginationDelayMaxMilliseconds }
                                    allowPartial         = [bool](Get-XdrBenchmarkValue -InputObject $scenario -Name 'allowPartial' -Default $false)
                                })
                        }
                    }
                }
            }
        }
    }

    foreach ($scenario in @(Get-XdrSequenceItems -InputObject $Settings.scenarios.saturationSweep)) {
        $branchNames = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'branchNames')) | Where-Object { $_ })
        if ($branchNames.Count -eq 0) {
            $branchNames = @('current')
        }

        $windowNames = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'windowNames')) | Where-Object { $_ })
        $throttleLimits = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'throttleLimits')) | Where-Object { $null -ne $_ })
        $chunkHoursValues = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'chunkHoursValues')) | Where-Object { $null -ne $_ })
        $deviceConcurrencyValues = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceConcurrencyValues')) | Where-Object { $null -ne $_ })
        if ($throttleLimits.Count -eq 0) {
            $throttleLimits = @([int]$Settings.execution.defaultThrottleLimit)
        }
        if ($chunkHoursValues.Count -eq 0) {
            $chunkHoursValues = @([int]$Settings.execution.defaultChunkHours)
        }
        if ($deviceConcurrencyValues.Count -eq 0) {
            $deviceConcurrencyValues = @([int]$Settings.execution.defaultDeviceConcurrency)
        }

        foreach ($deviceName in @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceNames')) | Where-Object { $_ })) {
            if (-not $deviceTable.ContainsKey([string]$deviceName)) {
                throw "Scenario '$($scenario.name)' references unknown device '$deviceName'."
            }
        }

        foreach ($windowName in $windowNames) {
            if (-not $WindowTable.ContainsKey([string]$windowName)) {
                throw "Scenario '$($scenario.name)' references unknown window '$windowName'."
            }

            foreach ($branchName in $branchNames) {
                if (-not $Settings.branches.ContainsKey([string]$branchName)) {
                    throw "Scenario '$($scenario.name)' references unknown branch '$branchName'."
                }

                foreach ($throttleLimit in $throttleLimits) {
                    foreach ($chunkHours in $chunkHoursValues) {
                        foreach ($deviceConcurrency in $deviceConcurrencyValues) {
                            $scenarioKey = "saturationSweep/$($scenario.name)/$(@($scenario.deviceNames) -join '+')/$windowName/t$throttleLimit/c$chunkHours/d$deviceConcurrency"
                            if ($scenarioKey -notlike $Include) {
                                continue
                            }
                            if ($Exclude -and $scenarioKey -like $Exclude) {
                                continue
                            }

                            $runPlan.Add([pscustomobject]@{
                                    groupName             = 'saturationSweep'
                                    groupOrder            = $groupOrder.saturationSweep
                                    scenarioName          = [string]$scenario.name
                                    scenarioKey           = $scenarioKey
                                    repeatNumber          = 1
                                    pairOrder             = 1
                                    branchName            = [string]$branchName
                                    branchLabel           = [string]$Settings.branches[$branchName].label
                                    windowName            = [string]$windowName
                                    deviceNames           = @((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceNames')) | Where-Object { $_ })
                                    deviceSetLabel        = (@((Get-XdrSequenceItems -InputObject (Get-XdrBenchmarkValue -InputObject $scenario -Name 'deviceNames')) | Where-Object { $_ }) -join '+')
                                    chunkHours            = [int]$chunkHours
                                    throttleLimit         = [int]$throttleLimit
                                    deviceConcurrency     = [int]$deviceConcurrency
                                    requestBudget         = ([int]$throttleLimit) * [math]::Max(1, [int]$deviceConcurrency)
                                    pageSize              = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'pageSize')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'pageSize') } else { [int]$Settings.execution.defaultPageSize }
                                    outputFormat          = if (Get-XdrBenchmarkValue -InputObject $scenario -Name 'outputFormat') { [string](Get-XdrBenchmarkValue -InputObject $scenario -Name 'outputFormat') } else { [string]$Settings.execution.defaultOutputFormat }
                                    requestTimeoutSeconds = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'requestTimeoutSeconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'requestTimeoutSeconds') } else { [int]$Settings.execution.defaultRequestTimeoutSeconds }
                                    maxRetries            = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'maxRetries')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'maxRetries') } else { [int]$Settings.execution.defaultMaxRetries }
                                    retryDelaySeconds     = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'retryDelaySeconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'retryDelaySeconds') } else { [int]$Settings.execution.defaultRetryDelaySeconds }
                                    paginationDelayMinMilliseconds = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMinMilliseconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMinMilliseconds') } else { [int]$Settings.execution.defaultPaginationDelayMinMilliseconds }
                                    paginationDelayMaxMilliseconds = if ($null -ne (Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMaxMilliseconds')) { [int](Get-XdrBenchmarkValue -InputObject $scenario -Name 'paginationDelayMaxMilliseconds') } else { [int]$Settings.execution.defaultPaginationDelayMaxMilliseconds }
                                    allowPartial          = [bool](Get-XdrBenchmarkValue -InputObject $scenario -Name 'allowPartial' -Default $false)
                                })
                        }
                    }
                }
            }
        }
    }

    return @(
        $runPlan |
            Sort-Object groupOrder, scenarioName, windowName, deviceSetLabel, repeatNumber, pairOrder, branchLabel
    )
}

function New-XdrBenchmarkRunLabel {
    param(
        [Parameter(Mandatory)]
        [object]$Run
    )

    $parts = @(
        $Run.groupName
        $Run.scenarioName
        $Run.deviceSetLabel
        $Run.windowName
        "r$($Run.repeatNumber)"
        $Run.branchLabel
        "t$($Run.throttleLimit)"
        "c$($Run.chunkHours)"
        "d$($Run.deviceConcurrency)"
    )

    $joined = ($parts -join '-')
    return ($joined -replace '[\\/:*?"<>| ]', '_')
}

function Get-XdrBenchmarkPowerShellPath {
    $pwshCommand = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCommand) {
        return $pwshCommand.Source
    }

    throw "The benchmark harness requires pwsh (PowerShell 7) to execute worker runs."
}

function Start-XdrBenchmarkWorkerProcess {
    param(
        [hashtable]$Settings,
        [hashtable]$WindowTable,
        [object]$Run,
        [string]$BatchRoot,
        [object]$Device
    )

    $runLabel = New-XdrBenchmarkRunLabel -Run $Run
    $deviceLabel = ($Device.name -replace '[\\/:*?"<>| ]', '_')
    $runRoot = Join-Path $BatchRoot $runLabel
    $deviceRoot = Join-Path $runRoot $deviceLabel
    $null = New-Item -Path $deviceRoot -ItemType Directory -Force

    $branch = $Settings.branches[[string]$Run.branchName]
    $window = $WindowTable[[string]$Run.windowName]
    $workerPath = Join-Path $PSScriptRoot 'Xdr.BenchmarkWorker.ps1'
    $requestPath = Join-Path $deviceRoot 'request.json'
    $resultPath = Join-Path $deviceRoot 'result.json'
    $transcriptPath = Join-Path $deviceRoot 'transcript.txt'
    $stdoutPath = Join-Path $deviceRoot 'stdout.txt'
    $stderrPath = Join-Path $deviceRoot 'stderr.txt'
    $exportExtension = if ($Run.outputFormat -eq 'Ndjson') { 'ndjson' } else { 'json' }
    $exportPath = Join-Path $deviceRoot "timeline.$exportExtension"

    $request = @{
        branch         = @{
            name       = [string]$Run.branchName
            label      = [string]$branch.label
            modulePath = [string]$branch.modulePath
            repoPath   = [string]$branch.repoPath
        }
        authentication = $Settings.authentication
        execution      = @{
            outputPath            = $exportPath
            outputFormat          = [string]$Run.outputFormat
            pageSize              = [int]$Run.pageSize
            throttleLimit         = [int]$Run.throttleLimit
            chunkHours            = [int]$Run.chunkHours
            requestTimeoutSeconds = [int]$Run.requestTimeoutSeconds
            maxRetries            = [int]$Run.maxRetries
            retryDelaySeconds     = [int]$Run.retryDelaySeconds
            paginationDelayMinMilliseconds = [int]$Run.paginationDelayMinMilliseconds
            paginationDelayMaxMilliseconds = [int]$Run.paginationDelayMaxMilliseconds
            allowPartial          = [bool]$Run.allowPartial
            keepTempFiles         = [bool]$Settings.execution.keepTempFiles
            workingDirectory      = [string]$Settings.execution.workingDirectory
        }
        device         = @{
            name     = [string]$Device.name
            deviceId = [string]$Device.deviceId
            notes    = [string]$Device.notes
            tags     = @($Device.tags)
            cohort   = [string]$Device.cohort
        }
        scenario       = @{
            groupName         = [string]$Run.groupName
            scenarioName      = [string]$Run.scenarioName
            scenarioKey       = [string]$Run.scenarioKey
            repeatNumber      = [int]$Run.repeatNumber
            pairOrder         = [int]$Run.pairOrder
            deviceSetLabel    = [string]$Run.deviceSetLabel
            deviceConcurrency = [int]$Run.deviceConcurrency
            requestBudget     = [int]$Run.requestBudget
        }
        window         = @{
            name       = [string]$Run.windowName
            fromDate   = ([datetime]$window.fromDate).ToUniversalTime().ToString('o')
            toDate     = ([datetime]$window.toDate).ToUniversalTime().ToString('o')
            totalHours = [double]$window.totalHours
            totalDays  = [double]$window.totalDays
        }
    }

    $request | ConvertTo-Json -Depth 8 | Set-Content -Path $requestPath -Encoding UTF8

    $process = Start-Process -FilePath (Get-XdrBenchmarkPowerShellPath) `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $workerPath, '-RequestPath', $requestPath, '-ResultPath', $resultPath, '-TranscriptPath', $transcriptPath) `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru

    return @{
        Process        = $process
        ResultPath     = $resultPath
        RunLabel       = $runLabel
        RunRoot        = $runRoot
        DeviceRoot     = $deviceRoot
        StdoutPath     = $stdoutPath
        StderrPath     = $stderrPath
        TranscriptPath = $transcriptPath
    }
}

function Receive-XdrBenchmarkWorkerProcess {
    param(
        [hashtable]$Worker
    )

    $Worker.Process | Wait-Process

    if (Test-Path $Worker.ResultPath) {
        $result = Get-Content -Path $Worker.ResultPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $result = ConvertTo-XdrHashtable -InputObject $result
    } else {
        $result = @{
            status                 = 'Failed'
            error                  = "Worker result file was not produced. Exit code: $($Worker.Process.ExitCode)"
            commandWallClockSeconds = 0
        }
    }

    $result.workerExitCode = $Worker.Process.ExitCode
    $result.runLabel = $Worker.RunLabel
    $result.runRoot = $Worker.RunRoot
    $result.deviceRoot = $Worker.DeviceRoot
    $result.stdoutPath = $Worker.StdoutPath
    $result.stderrPath = $Worker.StderrPath
    $result.transcriptPath = $Worker.TranscriptPath

    return $result
}

function Add-XdrBenchmarkRecord {
    param(
        [hashtable]$Record,
        [string]$BatchResultsPath,
        [string]$AggregateResultsPath
    )

    $json = $Record | ConvertTo-Json -Depth 8 -Compress
    Add-Content -Path $BatchResultsPath -Value $json -Encoding UTF8
    Add-Content -Path $AggregateResultsPath -Value $json -Encoding UTF8
}

function Get-XdrBenchmarkMedian {
    param(
        [double[]]$Values
    )

    $ordered = @($Values | Sort-Object)
    if ($ordered.Count -eq 0) {
        return $null
    }

    $midpoint = [math]::Floor($ordered.Count / 2)
    if ($ordered.Count % 2 -eq 1) {
        return [math]::Round($ordered[$midpoint], 4)
    }

    return [math]::Round((($ordered[$midpoint - 1] + $ordered[$midpoint]) / 2), 4)
}

function Write-XdrBenchmarkSummary {
    param(
        [object[]]$Records,
        [string]$SummaryPath
    )

    $summary = @{
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        totalRecords   = @($Records).Count
        groups         = @()
        comparisons    = @()
    }

    $grouped = $Records | Group-Object {
        "$($_.groupName)|$($_.scenarioName)|$($_.windowName)|$($_.deviceSetLabel)|$($_.branchLabel)|$($_.throttleLimit)|$($_.chunkHours)|$($_.deviceConcurrency)"
    }

    foreach ($group in $grouped) {
        $items = @($group.Group)
        $summary.groups += @{
            groupName                     = $items[0].groupName
            scenarioName                  = $items[0].scenarioName
            windowName                    = $items[0].windowName
            deviceSetLabel                = $items[0].deviceSetLabel
            branchLabel                   = $items[0].branchLabel
            throttleLimit                 = $items[0].throttleLimit
            chunkHours                    = $items[0].chunkHours
            deviceConcurrency             = $items[0].deviceConcurrency
            medianCommandWallClockSeconds = Get-XdrBenchmarkMedian -Values @($items | ForEach-Object { [double]$_.commandWallClockSeconds })
            medianEffectiveRate           = Get-XdrBenchmarkMedian -Values @($items | ForEach-Object { [double]$_.effectiveRate })
            medianTotalEvents             = Get-XdrBenchmarkMedian -Values @($items | ForEach-Object { [double]$_.totalEvents })
            runCount                      = $items.Count
        }
    }

    $comparisonGroups = $Records | Group-Object {
        "$($_.groupName)|$($_.scenarioName)|$($_.windowName)|$($_.deviceSetLabel)|$($_.throttleLimit)|$($_.chunkHours)|$($_.deviceConcurrency)"
    }

    foreach ($comparisonGroup in $comparisonGroups) {
        $items = @($comparisonGroup.Group)
        $mainItems = @($items | Where-Object branchLabel -eq 'main')
        $currentItems = @($items | Where-Object branchLabel -eq 'current')
        if ($mainItems.Count -eq 0 -or $currentItems.Count -eq 0) {
            continue
        }

        $mainMedian = Get-XdrBenchmarkMedian -Values @($mainItems | ForEach-Object { [double]$_.commandWallClockSeconds })
        $currentMedian = Get-XdrBenchmarkMedian -Values @($currentItems | ForEach-Object { [double]$_.commandWallClockSeconds })
        $mainRate = Get-XdrBenchmarkMedian -Values @($mainItems | ForEach-Object { [double]$_.effectiveRate })
        $currentRate = Get-XdrBenchmarkMedian -Values @($currentItems | ForEach-Object { [double]$_.effectiveRate })

        $summary.comparisons += @{
            comparisonKey                  = $comparisonGroup.Name
            medianMainSeconds              = $mainMedian
            medianCurrentSeconds           = $currentMedian
            currentMinusMainSeconds        = [math]::Round(($currentMedian - $mainMedian), 4)
            currentVsMainPercent           = if ($mainMedian) { [math]::Round((($currentMedian - $mainMedian) / $mainMedian) * 100, 2) } else { $null }
            medianMainEffectiveRate        = $mainRate
            medianCurrentEffectiveRate     = $currentRate
            currentMinusMainEffectiveRate  = [math]::Round(($currentRate - $mainRate), 4)
        }
    }

    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $SummaryPath -Encoding UTF8
    return $summary
}

function Invoke-XdrBenchmarkSuite {
    param(
        [hashtable]$Settings,
        [string]$Include = '*',
        [string]$Exclude = ''
    )

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "The benchmark harness requires PowerShell 7 or later."
    }

    if (-not $Settings.benchmarks.enabled) {
        throw "Benchmarks are disabled. Set benchmarks.enabled to true in the benchmark configuration or use -EnableBenchmarks."
    }

    $resultsRoot = $Settings.execution.resultsRoot
    $null = New-Item -Path $resultsRoot -ItemType Directory -Force

    $batchId = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $batchRoot = Join-Path $resultsRoot $batchId
    $null = New-Item -Path $batchRoot -ItemType Directory -Force

    $capturedToDate = (Get-Date).ToUniversalTime()
    $windowTable = Get-XdrBenchmarkWindowTable -Settings $Settings -CapturedToDate $capturedToDate
    $runPlan = Get-XdrBenchmarkRunPlan -Settings $Settings -WindowTable $windowTable -Include $Include -Exclude $Exclude
    if ($runPlan.Count -eq 0) {
        throw "No benchmark scenarios matched the requested include/exclude filters."
    }

    $batchResultsPath = Join-Path $batchRoot 'results.ndjson'
    $aggregateResultsPath = Join-Path $resultsRoot 'results.ndjson'
    $summaryPath = Join-Path $batchRoot 'summary.json'
    $manifestPath = Join-Path $batchRoot 'manifest.json'

    @{
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        capturedToDate = $capturedToDate.ToString('o')
        runCount       = $runPlan.Count
        configuration  = $Settings.__meta.configurationPath
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

    if (-not (Test-Path $batchResultsPath)) {
        New-Item -Path $batchResultsPath -ItemType File -Force | Out-Null
    }
    if (-not (Test-Path $aggregateResultsPath)) {
        New-Item -Path $aggregateResultsPath -ItemType File -Force | Out-Null
    }

    $deviceTable = @{}
    foreach ($device in @(Get-XdrSequenceItems -InputObject $Settings.devices)) {
        $deviceTable[[string]$device.name] = $device
    }

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($run in $runPlan) {
        $runStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $startedAtUtc = (Get-Date).ToUniversalTime()
        $deviceResults = [System.Collections.Generic.List[object]]::new()

        if ($run.groupName -eq 'concurrentDevices' -or $run.deviceConcurrency -gt 1) {
            $workers = [System.Collections.Generic.List[object]]::new()
            foreach ($deviceName in $run.deviceNames) {
                $device = $deviceTable[[string]$deviceName]
                $workers.Add((Start-XdrBenchmarkWorkerProcess -Settings $Settings -WindowTable $windowTable -Run $run -BatchRoot $batchRoot -Device $device))
            }

            foreach ($worker in $workers) {
                $deviceResults.Add((Receive-XdrBenchmarkWorkerProcess -Worker $worker))
            }
        } else {
            $device = $deviceTable[[string]$run.deviceNames[0]]
            $worker = Start-XdrBenchmarkWorkerProcess -Settings $Settings -WindowTable $windowTable -Run $run -BatchRoot $batchRoot -Device $device
            $deviceResults.Add((Receive-XdrBenchmarkWorkerProcess -Worker $worker))
        }

        $runStopwatch.Stop()
        $completedAtUtc = (Get-Date).ToUniversalTime()
        $failedDeviceResults = @($deviceResults | Where-Object { $_.status -ne 'Succeeded' })
        $totalEvents = [double](($deviceResults | Measure-Object -Property totalEvents -Sum).Sum)
        $totalChunks = [double](($deviceResults | Measure-Object -Property totalChunks -Sum).Sum)
        $failedChunks = [double](($deviceResults | Measure-Object -Property failedChunks -Sum).Sum)
        $totalSizeMB = [double](($deviceResults | Measure-Object -Property totalSizeMB -Sum).Sum)
        $maxCommandSeconds = [double](($deviceResults | ForEach-Object { [double]$_.commandWallClockSeconds } | Measure-Object -Maximum).Maximum)
        $maxConnectSeconds = [double](($deviceResults | ForEach-Object { [double]$_.connectSeconds } | Measure-Object -Maximum).Maximum)
        $record = @{
            batchId                = $batchId
            startedAtUtc           = $startedAtUtc.ToString('o')
            completedAtUtc         = $completedAtUtc.ToString('o')
            endToEndWallClockSeconds = [math]::Round($runStopwatch.Elapsed.TotalSeconds, 2)
            groupName              = [string]$run.groupName
            scenarioName           = [string]$run.scenarioName
            scenarioKey            = [string]$run.scenarioKey
            repeatNumber           = [int]$run.repeatNumber
            pairOrder              = [int]$run.pairOrder
            branchName             = [string]$run.branchName
            branchLabel            = [string]$run.branchLabel
            windowName             = [string]$run.windowName
            fromDate               = [string]$windowTable[[string]$run.windowName].fromDate.ToString('o')
            toDate                 = [string]$windowTable[[string]$run.windowName].toDate.ToString('o')
            deviceNames            = @($run.deviceNames)
            deviceSetLabel         = [string]$run.deviceSetLabel
            deviceCount            = @($run.deviceNames).Count
            deviceConcurrency      = [int]$run.deviceConcurrency
            requestBudget          = [int]$run.requestBudget
            throttleLimit          = [int]$run.throttleLimit
            chunkHours             = [int]$run.chunkHours
            pageSize               = [int]$run.pageSize
            outputFormat           = [string]$run.outputFormat
            requestTimeoutSeconds  = [int]$run.requestTimeoutSeconds
            maxRetries             = [int]$run.maxRetries
            retryDelaySeconds      = [int]$run.retryDelaySeconds
            status                 = if ($failedDeviceResults.Count -gt 0) { 'Failed' } else { 'Succeeded' }
            totalEvents            = [int]$totalEvents
            totalChunks            = [int]$totalChunks
            failedChunks           = [int]$failedChunks
            totalSizeMB            = [math]::Round($totalSizeMB, 2)
            commandWallClockSeconds = [math]::Round($maxCommandSeconds, 2)
            connectSeconds         = [math]::Round($maxConnectSeconds, 2)
            effectiveRate          = if ($runStopwatch.Elapsed.TotalSeconds -gt 0) { [math]::Round(($totalEvents / $runStopwatch.Elapsed.TotalSeconds), 1) } else { 0 }
            branchCommit           = if ($deviceResults.Count -gt 0) { $deviceResults[0].branchCommit } else { $null }
            deviceResults          = @($deviceResults)
            errors                 = @($failedDeviceResults | ForEach-Object { $_.error })
        }

        Add-XdrBenchmarkRecord -Record $record -BatchResultsPath $batchResultsPath -AggregateResultsPath $aggregateResultsPath
        $records.Add([pscustomobject]$record)

        if ($record.status -eq 'Failed' -and $Settings.execution.stopOnError) {
            Write-XdrBenchmarkSummary -Records $records.ToArray() -SummaryPath $summaryPath | Out-Null
            throw "Benchmark scenario '$($run.scenarioKey)' failed."
        }
    }

    $summary = Write-XdrBenchmarkSummary -Records $records.ToArray() -SummaryPath $summaryPath
    return @{
        batchId      = $batchId
        batchRoot    = $batchRoot
        resultsPath  = $batchResultsPath
        summaryPath  = $summaryPath
        runCount     = $records.Count
        summary      = $summary
        records      = $records.ToArray()
        capturedToDate = $capturedToDate.ToString('o')
    }
}
