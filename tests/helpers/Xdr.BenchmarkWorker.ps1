param(
    [Parameter(Mandatory)]
    [string]$RequestPath,

    [Parameter(Mandatory)]
    [string]$ResultPath,

    [Parameter(Mandatory)]
    [string]$TranscriptPath
)

Set-StrictMode -Version Latest

$sharedHelperPath = Join-Path $PSScriptRoot 'Xdr.TestHelpers.ps1'
. $sharedHelperPath

function Get-XdrWorkerValue {
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

$request = Get-Content -Path $RequestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$request = ConvertTo-XdrHashtable -InputObject $request

$result = @{
    status                  = 'Failed'
    startedAtUtc            = (Get-Date).ToUniversalTime().ToString('o')
    completedAtUtc          = $null
    branchCommit            = $null
    connectSeconds          = 0
    commandWallClockSeconds = 0
    totalEvents             = 0
    totalChunks             = 0
    failedChunks            = 0
    totalSizeMB             = 0
    effectiveRate           = 0
    exportPath              = $request.execution.outputPath
    diagnosticsPath         = $null
    error                   = $null
}

$overallStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$transcriptStarted = $false
try {
    $transcriptDirectory = Split-Path -Parent $TranscriptPath
    if ($transcriptDirectory) {
        $null = New-Item -Path $transcriptDirectory -ItemType Directory -Force
    }

    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    $transcriptStarted = $true

    $modulePath = Resolve-XdrTestPath -Path $request.branch.modulePath -BasePath $request.branch.repoPath
    if (-not (Test-Path $modulePath)) {
        throw "Branch module path '$($request.branch.modulePath)' could not be resolved."
    }

    Remove-Module XDRInternals -ErrorAction Ignore
    Import-Module $modulePath -Force

    $moduleDirectory = Split-Path -Parent $modulePath
    $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($modulePath)
    $moduleImplementationPath = Join-Path $moduleDirectory "$moduleName.psm1"
    if (Test-Path $moduleImplementationPath) {
        Import-Module $moduleImplementationPath -Force
    }

    $result.branchCommit = ((& git -C $request.branch.repoPath rev-parse HEAD 2>$null) | Out-String).Trim()

    $connectParams = @{
        KeyFilePath = Resolve-XdrTestPath -Path $request.authentication.keyFilePath -BasePath (Split-Path -Parent $RequestPath)
        ErrorAction = 'Stop'
    }
    if ($request.authentication.tenantId) {
        $connectParams.TenantId = $request.authentication.tenantId
    }
    if ($request.authentication.keyVaultTenantId) {
        $connectParams.KeyVaultTenantId = $request.authentication.keyVaultTenantId
    }
    if ($request.authentication.keyVaultClientId) {
        $connectParams.KeyVaultClientId = $request.authentication.keyVaultClientId
    }
    if ($request.authentication.keyVaultApiVersion) {
        $connectParams.KeyVaultApiVersion = $request.authentication.keyVaultApiVersion
    }
    if ($request.authentication.userAgent) {
        $connectParams.UserAgent = $request.authentication.userAgent
    }

    $connectStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Connect-XdrBySoftwarePasskey @connectParams | Out-Null
    $connectStopwatch.Stop()
    $result.connectSeconds = [math]::Round($connectStopwatch.Elapsed.TotalSeconds, 2)

    $timelineCommand = Get-Command Get-XdrEndpointDeviceTimeline -ErrorAction Stop
    $timelineParams = @{
        DeviceId              = $request.device.deviceId
        FromDate              = [datetime]$request.window.fromDate
        ToDate                = [datetime]$request.window.toDate
        ErrorAction           = 'Stop'
    }

    if ($timelineCommand.Parameters.ContainsKey('WorkingDirectory') -and $timelineCommand.Parameters.ContainsKey('OutputPath')) {
        $timelineParams.OutputPath = $request.execution.outputPath
    } elseif ($timelineCommand.Parameters.ContainsKey('ExportPath') -and $timelineCommand.Parameters.ContainsKey('OutputPath')) {
        $timelineParams.OutputPath = Split-Path -Parent $request.execution.outputPath
        $timelineParams.ExportPath = $request.execution.outputPath
    } elseif ($timelineCommand.Parameters.ContainsKey('OutputPath')) {
        $timelineParams.OutputPath = $request.execution.outputPath
    } elseif ($timelineCommand.Parameters.ContainsKey('ExportPath')) {
        $timelineParams.ExportPath = $request.execution.outputPath
    }
    if ($timelineCommand.Parameters.ContainsKey('ExportFormat')) {
        $timelineParams.ExportFormat = $request.execution.outputFormat
    }
    if ($timelineCommand.Parameters.ContainsKey('DiagnosticsPath')) {
        $timelineParams.DiagnosticsPath = [System.IO.Path]::ChangeExtension($request.execution.outputPath, '.diagnostics.json')
        $result.diagnosticsPath = $timelineParams.DiagnosticsPath
    }
    if ($timelineCommand.Parameters.ContainsKey('PageSize')) {
        $timelineParams.PageSize = [int]$request.execution.pageSize
    }
    if ($timelineCommand.Parameters.ContainsKey('ThrottleLimit')) {
        $timelineParams.ThrottleLimit = [int]$request.execution.throttleLimit
    }
    if ($timelineCommand.Parameters.ContainsKey('RequestTimeoutSeconds')) {
        $timelineParams.RequestTimeoutSeconds = [int]$request.execution.requestTimeoutSeconds
    }
    if ($timelineCommand.Parameters.ContainsKey('MaxRetries')) {
        $timelineParams.MaxRetries = [int]$request.execution.maxRetries
    }
    if ($timelineCommand.Parameters.ContainsKey('RetryDelaySeconds')) {
        $timelineParams.RetryDelaySeconds = [int]$request.execution.retryDelaySeconds
    }
    if ($timelineCommand.Parameters.ContainsKey('PaginationDelayMinMilliseconds')) {
        $timelineParams.PaginationDelayMinMilliseconds = [int]$request.execution.paginationDelayMinMilliseconds
    }
    if ($timelineCommand.Parameters.ContainsKey('PaginationDelayMaxMilliseconds')) {
        $timelineParams.PaginationDelayMaxMilliseconds = [int]$request.execution.paginationDelayMaxMilliseconds
    }

    if ([int]$request.execution.chunkHours -gt 0 -and $timelineCommand.Parameters.ContainsKey('ChunkHours')) {
        $timelineParams.ChunkHours = [int]$request.execution.chunkHours
    }
    if ($request.execution.allowPartial -and $timelineCommand.Parameters.ContainsKey('AllowPartial')) {
        $timelineParams.AllowPartial = $true
    }
    if ($request.execution.keepTempFiles -and $timelineCommand.Parameters.ContainsKey('KeepTempFiles')) {
        $timelineParams.KeepTempFiles = $true
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$request.execution.workingDirectory) -and $timelineCommand.Parameters.ContainsKey('WorkingDirectory')) {
        $timelineParams.WorkingDirectory = $request.execution.workingDirectory
    }

    $commandStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $summary = Get-XdrEndpointDeviceTimeline @timelineParams
    $commandStopwatch.Stop()

    $result.status = 'Succeeded'
    $result.commandWallClockSeconds = [math]::Round($commandStopwatch.Elapsed.TotalSeconds, 2)
    $result.totalEvents = [int](Get-XdrWorkerValue -InputObject $summary -Name 'TotalEvents' -Default 0)
    $result.totalChunks = [int](Get-XdrWorkerValue -InputObject $summary -Name 'TotalChunks' -Default 0)
    $result.failedChunks = [int](Get-XdrWorkerValue -InputObject $summary -Name 'FailedChunks' -Default 0)
    $result.totalSizeMB = [double](Get-XdrWorkerValue -InputObject $summary -Name 'TotalSizeMB' -Default 0)
    $result.effectiveRate = [double](Get-XdrWorkerValue -InputObject $summary -Name 'EffectiveRate' -Default 0)
    $result.exportPath = [string](Get-XdrWorkerValue -InputObject $summary -Name 'ExportPath' -Default $request.execution.outputPath)
    $result.diagnosticsPath = [string](Get-XdrWorkerValue -InputObject $summary -Name 'DiagnosticsPath' -Default $result.diagnosticsPath)
}
catch {
    $result.error = $_.ToString()
}
finally {
    $overallStopwatch.Stop()
    $result.completedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    $result.processWallClockSeconds = [math]::Round($overallStopwatch.Elapsed.TotalSeconds, 2)
    if ($transcriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
        }
    }

    $result | ConvertTo-Json -Depth 6 | Set-Content -Path $ResultPath -Encoding UTF8
}

if ($result.status -ne 'Succeeded') {
    exit 1
}
