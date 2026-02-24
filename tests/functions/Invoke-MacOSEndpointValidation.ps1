[CmdletBinding()]
param(
    [Parameter()]
    [ValidateLength(40,40)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$DeviceId = '980dddb7036eae7e38d30dee7f11b51e573a6fc2',

    [Parameter()]
    [ValidateRange(0, 1800)]
    [int]$LiveResponseDelaySeconds = 90,

    [Parameter()]
    [ValidateRange(0, 3600)]
    [int]$MachineActionDelaySeconds = 300,

    [Parameter()]
    [ValidateRange(5, 300)]
    [int]$ActionPollSeconds = 30,

    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$ActionTimeoutMinutes = 20,

    [Parameter()]
    [string]$OutputDirectory = 'TestResults'
)

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$projectRoot = (& git rev-parse --show-toplevel).Trim()
if (-not $projectRoot) {
    throw 'Unable to determine repo root with git rev-parse --show-toplevel'
}

$outputRoot = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $projectRoot $OutputDirectory
}
$null = New-Item -Path $outputRoot -ItemType Directory -Force

$liveOutputPath = Join-Path $outputRoot "MacOS-LiveResponse-$timestamp.json"
$actionOutputPath = Join-Path $outputRoot "MacOS-MachineActions-$timestamp.json"
$summaryOutputPath = Join-Path $outputRoot "MacOS-Validation-Summary-$timestamp.md"
$limitationsOutputPath = Join-Path $outputRoot "MacOS-Limitations-$timestamp.md"

$liveResults = [System.Collections.Generic.List[object]]::new()
$actionResults = [System.Collections.Generic.List[object]]::new()
$limitations = [System.Collections.Generic.List[object]]::new()
$rollbackResults = [System.Collections.Generic.List[object]]::new()

$runState = [ordered]@{
    StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
    CompletedUtc = $null
    DeviceId = $DeviceId
    DeviceName = $null
    OsPlatform = $null
    Baseline = $null
    LiveResponseSessionId = $null
    LiveResponseDelaySeconds = $LiveResponseDelaySeconds
    MachineActionDelaySeconds = $MachineActionDelaySeconds
    ActionPollSeconds = $ActionPollSeconds
    ActionTimeoutMinutes = $ActionTimeoutMinutes
}

function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [string]$Color = 'Cyan'
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "`n[$stamp] $Message" -ForegroundColor $Color
}

function Get-ErrorText {
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $msg = $ErrorRecord.ToString()
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        $msg = $ErrorRecord.Exception.Message
    }
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $msg = $ErrorRecord.ErrorDetails.Message
    }
    return "$msg"
}

function Add-Limitation {
    param(
        [Parameter(Mandatory = $true)][string]$Area,
        [Parameter(Mandatory = $true)][string]$Item,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter()][string]$Evidence = ''
    )

    $limitations.Add([PSCustomObject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Area = $Area
        Item = $Item
        Reason = $Reason
        Evidence = $Evidence
    })
}

function Get-PropertyOrDefault {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$PropertyNames,
        [Parameter()][object]$Default = $null
    )

    foreach ($name in $PropertyNames) {
        if ($null -ne $Object -and $Object.PSObject.Properties[$name]) {
            $value = $Object.$name
            if ($null -ne $value -and "$value" -ne '') {
                return $value
            }
        }
    }

    return $Default
}

function ConvertTo-LrQuotedValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -match '\s' -and $Value -notmatch '^".*"$') {
        return '"' + ($Value -replace '"', '\"') + '"'
    }
    return $Value
}

function Expand-LrTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$Template,
        [Parameter(Mandatory = $true)][hashtable]$Context
    )

    $expanded = $Template
    $tokenMatches = [regex]::Matches($Template, '\{([A-Z_]+)\}')
    foreach ($match in $tokenMatches) {
        $token = $match.Groups[1].Value
        $value = $Context[$token]
        if ($null -eq $value -or "$value" -eq '') {
            return $null
        }
        $expanded = $expanded.Replace($match.Value, (ConvertTo-LrQuotedValue -Value "$value"))
    }

    return $expanded
}

function Get-LrOutputSummary {
    param([Parameter()][object]$Result)

    if (-not $Result -or -not $Result.outputs) {
        return [PSCustomObject]@{ OutputCount = 0; DataTypes = @(); Preview = @() }
    }

    $preview = [System.Collections.Generic.List[string]]::new()
    foreach ($out in @($Result.outputs)) {
        if ($null -eq $out.data) { continue }
        if ($out.data -is [array] -and $out.data.Count -gt 0) {
            $preview.Add(("$($out.data[0])").Trim())
        } elseif ($out.data) {
            $preview.Add(("$($out.data)").Trim())
        }
        if ($preview.Count -ge 3) { break }
    }

    return [PSCustomObject]@{
        OutputCount = @($Result.outputs).Count
        DataTypes = @($Result.outputs | ForEach-Object { $_.data_type } | Where-Object { $_ } | Select-Object -Unique)
        Preview = @($preview)
    }
}

function Get-RequestId {
    param([Parameter()][object]$Result)

    if (-not $Result) { return $null }
    foreach ($name in 'Id', 'RequestGuid', 'requestGuid', 'id', 'request_id') {
        if ($Result.PSObject.Properties[$name] -and "$($Result.$name)" -ne '') {
            return "$($Result.$name)"
        }
    }
    return $null
}

function Wait-ActionCompletion {
    param(
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter(Mandatory = $true)][string]$RequestId,
        [Parameter(Mandatory = $true)][int]$PollSeconds,
        [Parameter(Mandatory = $true)][int]$TimeoutMinutes
    )

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $terminal = @('Succeeded', 'Success', 'Completed', 'Failed', 'Cancelled', 'Canceled', 'Rejected', 'Unsupported', 'Error', 'Denied')
    $finalStatus = 'Unknown'
    $polls = [System.Collections.Generic.List[object]]::new()

    while ((Get-Date) -lt $deadline) {
        try {
            $raw = Get-XdrEndpointDeviceActionResult -DeviceId $DeviceId -RequestGuid $RequestId -ErrorAction Stop
            $entry = if ($raw -is [array]) { @($raw | Select-Object -First 1)[0] } else { $raw }
            $status = Get-PropertyOrDefault -Object $entry -PropertyNames @('RequestStatus', 'Status', 'ActionStatus', 'status') -Default 'Unknown'
            $finalStatus = "$status"
            $polls.Add([PSCustomObject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString('o'); Status = "$status" })
            if ($terminal -contains "$status") {
                return [PSCustomObject]@{ FinalStatus = "$status"; TimedOut = $false; Polls = @($polls) }
            }
        } catch {
            $polls.Add([PSCustomObject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString('o'); Status = 'PollError'; Error = (Get-ErrorText -ErrorRecord $_) })
        }

        Start-Sleep -Seconds $PollSeconds
    }

    return [PSCustomObject]@{ FinalStatus = $finalStatus; TimedOut = $true; Polls = @($polls) }
}

function Invoke-RollbackAction {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock
    )

    $started = Get-Date
    try {
        & $ScriptBlock
        $rollbackResults.Add([PSCustomObject]@{
            Name = $Name
            Status = 'Pass'
            StartedUtc = $started.ToUniversalTime().ToString('o')
            CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Error = $null
        })
    } catch {
        $msg = Get-ErrorText -ErrorRecord $_
        $rollbackResults.Add([PSCustomObject]@{
            Name = $Name
            Status = 'Fail'
            StartedUtc = $started.ToUniversalTime().ToString('o')
            CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Error = $msg
        })
        Add-Limitation -Area 'Rollback' -Item $Name -Reason 'Rollback step failed' -Evidence $msg
    }
}


function Get-LrDefinitionParameters {
    param([Parameter(Mandatory = $true)]$Definition)

    foreach ($prop in 'parameters', 'params', 'arguments') {
        if ($Definition.PSObject.Properties[$prop] -and $Definition.$prop) {
            return @($Definition.$prop)
        }
    }

    return @()
}

function Get-LrParameterId {
    param([Parameter(Mandatory = $true)]$Parameter)

    foreach ($prop in 'parameter_id', 'param_id', 'id', 'name') {
        if ($Parameter.PSObject.Properties[$prop] -and "$($Parameter.$prop)" -ne '') {
            return "$($Parameter.$prop)".ToLower()
        }
    }

    return $null
}

function Get-LrParameterDataType {
    param([Parameter(Mandatory = $true)]$Parameter)

    foreach ($prop in 'parameter_type', 'value_type', 'type', 'data_type') {
        if ($Parameter.PSObject.Properties[$prop] -and "$($Parameter.$prop)" -ne '') {
            return "$($Parameter.$prop)"
        }
    }

    return ''
}

function Test-LrParameterRequired {
    param([Parameter(Mandatory = $true)]$Parameter)

    foreach ($prop in 'required', 'is_required', 'is_mandatory', 'mandatory') {
        if ($Parameter.PSObject.Properties[$prop]) {
            $raw = $Parameter.$prop
            if ($raw -is [bool]) { return [bool]$raw }
            if ("$raw" -match '^(1|true|yes)$') { return $true }
            if ("$raw" -match '^(0|false|no)$') { return $false }
        }
    }

    # Live Response command metadata commonly uses optional=true/false
    foreach ($prop in 'optional', 'is_optional') {
        if ($Parameter.PSObject.Properties[$prop]) {
            $raw = $Parameter.$prop
            if ($raw -is [bool]) { return -not [bool]$raw }
            if ("$raw" -match '^(1|true|yes)$') { return $false }
            if ("$raw" -match '^(0|false|no)$') { return $true }
        }
    }

    return $false
}
function Get-LrParameterValidValues {
    param([Parameter(Mandatory = $true)]$Parameter)

    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($prop in 'valid_values', 'validValues', 'allowed_values', 'allowedValues', 'values') {
        if (-not $Parameter.PSObject.Properties[$prop] -or -not $Parameter.$prop) { continue }
        foreach ($entry in @($Parameter.$prop)) {
            if ($entry -is [string] -and "$entry" -ne '') {
                $values.Add("$entry")
                continue
            }
            foreach ($valueProp in 'value', 'id', 'name') {
                if ($entry -and $entry.PSObject -and $entry.PSObject.Properties[$valueProp] -and "$($entry.$valueProp)" -ne '') {
                    $values.Add("$($entry.$valueProp)")
                    break
                }
            }
        }
    }

    return @($values | Select-Object -Unique)
}

function Resolve-LrParameterValue {
    param(
        [Parameter(Mandatory = $true)][string]$CommandId,
        [Parameter(Mandatory = $true)][string]$ParameterId,
        [Parameter()][string]$DataType = ''
    )

    $commandIdLower = "$CommandId".ToLower()
    $parameterIdLower = "$ParameterId".ToLower()
    $typeLower = "$DataType".ToLower()
    $key = "$commandIdLower|$parameterIdLower"

    switch ($key) {
        'fg|command_id' { return '{BG_COMMAND_ID}' }
        'status|command_id' { return '{LAST_COMMAND_ID}' }
        'status|id' { return '{LAST_COMMAND_ID}' }
        'undo|type' { return '{UNDO_TYPE}' }
        'undo|target_id' { return '{UNDO_TARGET_ID}' }
        'undo|id' { return '{UNDO_TARGET_ID}' }
        'putfile|file_name' { return '{LIB_FILE_NAME}' }
        'putfile|filename' { return '{LIB_FILE_NAME}' }
        'putfile|id' { return '{LIB_FILE_NAME}' }
        'run|script_name' { return '{LIB_FILE_NAME}' }
        'run|filename' { return '{LIB_FILE_NAME}' }
        'run|id' { return '{LIB_FILE_NAME}' }
        'remediate|id' { return '/tmp/xdrinternals-placeholder' }
        'collect|output_folder' { return '/var/root' }
        'processes|name' { return 'launchd' }
        'findfile|name' { return 'hosts' }
    }

    if ($typeLower -match 'bool|switch') {
        return $true
    }
    if ($typeLower -match 'int|integer|number|long|double|float') {
        return 1
    }

    if ($parameterIdLower -match 'pid|process') { return '{PROCESS_PID}' }
    if ($parameterIdLower -match 'background|bg') { return '{BG_COMMAND_ID}' }
    if ($parameterIdLower -match 'command|request|job' -and $parameterIdLower -notmatch 'description|comment') { return '{LAST_COMMAND_ID}' }
    if ($parameterIdLower -match 'path|directory|folder') { return '/tmp' }
    if ($parameterIdLower -match 'file_name|filename|library') { return '{LIB_FILE_NAME}' }
    if ($parameterIdLower -eq 'id') { return '{LIB_FILE_NAME}' }
    if ($parameterIdLower -match 'file') { return '/etc/hosts' }
    if ($parameterIdLower -match 'name|query|pattern|search') { return 'hosts' }
    if ($parameterIdLower -match 'description|comment|notes') { return 'macOS validation' }
    if ($parameterIdLower -match 'hash') { return 'd41d8cd98f00b204e9800998ecf8427e' }
    if ($parameterIdLower -match 'type') { return 'file' }
    if ($parameterIdLower -match 'target|entity|item') { return '/tmp/xdrinternals-placeholder' }

    return '1'
}
function New-LrParameterArgument {
    param(
        [Parameter(Mandatory = $true)][string]$ParameterId,
        [Parameter()][object]$Value = $null,
        [Parameter()][string]$DataType = ''
    )

    $typeLower = "$DataType".ToLower()
    if ($typeLower -match 'bool|switch') {
        if ($Value -is [bool]) {
            if (-not $Value) { return $null }
        }
        return "-$ParameterId"
    }

    if ($Value -is [bool]) {
        if ($Value) { return "-$ParameterId" }
        return $null
    }
    if ($null -eq $Value -or "$Value" -eq '') {
        return $null
    }

    return "-$ParameterId $(ConvertTo-LrQuotedValue -Value "$Value")"
}

function New-LrTemplateForParameterCase {
    param(
        [Parameter(Mandatory = $true)][string]$CommandId,
        [Parameter(Mandatory = $true)][object[]]$Parameters,
        [Parameter()][string]$TargetParameterId = '',
        [Parameter()][object]$TargetValue = $null
    )

    $commandIdLower = "$CommandId".ToLower()
    $targetParameterLower = "$TargetParameterId".ToLower()

    $segments = [System.Collections.Generic.List[string]]::new()
    $segments.Add("$CommandId")

    foreach ($parameter in $Parameters) {
        $parameterId = Get-LrParameterId -Parameter $parameter
        if (-not $parameterId) { continue }
        $isRequired = Test-LrParameterRequired -Parameter $parameter
        $isTarget = ($targetParameterLower -and $parameterId -eq $targetParameterLower)

        # Some commands have implicit dependencies not modeled as required in metadata.
        $isConditionalRequired = $false
        if ($commandIdLower -eq 'remediate' -and $parameterId -eq 'id' -and $targetParameterLower -eq 'type') {
            if ("$TargetValue" -match '^(file|process)$') {
                $isConditionalRequired = $true
            }
        }

        if (-not $isRequired -and -not $isTarget -and -not $isConditionalRequired) { continue }

        $dataType = Get-LrParameterDataType -Parameter $parameter
        $value = if ($isTarget) {
            $TargetValue
        } else {
            Resolve-LrParameterValue -CommandId $CommandId -ParameterId $parameterId -DataType $dataType
        }
        if ($commandIdLower -eq 'remediate' -and $parameterId -eq 'id' -and $targetParameterLower -eq 'type') {
            if ("$TargetValue" -eq 'process') { $value = '{PROCESS_PID}' }
            elseif ("$TargetValue" -eq 'file') { $value = '/tmp/xdrinternals-placeholder' }
        }
        $argument = New-LrParameterArgument -ParameterId $parameterId -Value $value -DataType $dataType
        if (-not $argument) {
            if ($isRequired -or $isTarget -or $isConditionalRequired) {
                return $null
            }
            continue
        }
        $segments.Add($argument)
    }

    return ($segments -join ' ').Trim()
}
function ConvertTo-SafeCaseLabel {
    param([Parameter(Mandatory = $true)][string]$Value)

    $normalized = ($Value -replace '[^a-zA-Z0-9_]+', '_').Trim('_')
    if (-not $normalized) { return 'value' }
    return $normalized.ToLower()
}


$lrSession = $null
$lrDefs = @()
$lrCurrentDirectory = '/'
$lrContext = @{
    LAST_COMMAND_ID = $null
    BG_COMMAND_ID = '00000000-0000-0000-0000-000000000000'
    PROCESS_PID = '1'
    LIB_FILE_NAME = $null
    UNDO_TYPE = 'file'
    UNDO_TARGET_ID = '/tmp/xdrinternals-placeholder'
}
$lrUndoQueue = [System.Collections.Generic.List[string]]::new()
$libraryFilesToDelete = [System.Collections.Generic.List[string]]::new()
$baseline = $null

try {
    Write-Step 'Authenticating using TestScripts/Auth-XdrSession.ps1'
    & (Join-Path $projectRoot 'TestScripts\Auth-XdrSession.ps1')

    Write-Step 'Verifying XDR connection'
    $null = Get-XdrMtoTenantList -ErrorAction Stop

    Write-Step "Capturing baseline for device $DeviceId"
    $device = Get-XdrEndpointDevice -DeviceId $DeviceId -Force
    $deviceTags = Get-XdrEndpointDeviceTag -DeviceId $DeviceId -Force
    $baseline = [PSCustomObject]@{
        DeviceId = $DeviceId
        DeviceName = $device.ComputerDnsName
        OsPlatform = $device.OsPlatform
        LastSeen = $device.LastSeen
        AssetValue = Get-PropertyOrDefault -Object $device -PropertyNames @('AssetValue', 'assetValue') -Default 'Normal'
        CriticalityLevel = Get-PropertyOrDefault -Object $device -PropertyNames @('CriticalityLevel', 'criticalityLevel') -Default 'Reset'
        ExclusionState = Get-PropertyOrDefault -Object $device -PropertyNames @('ExclusionState', 'exclusionState') -Default 'Included'
        UserDefinedTags = @($deviceTags.UserDefinedTags)
    }

    $runState.DeviceName = $baseline.DeviceName
    $runState.OsPlatform = $baseline.OsPlatform
    $runState.Baseline = $baseline

    if ("$($baseline.OsPlatform)" -notmatch 'mac') {
        Add-Limitation -Area 'Preflight' -Item 'Device platform' -Reason 'Target is not reported as macOS' -Evidence "OsPlatform=$($baseline.OsPlatform)"
    }

    Write-Step 'Establishing Live Response session using -NonInteractive'
    $lrSession = Connect-XdrEndpointDeviceLiveResponse -DeviceId $DeviceId -NonInteractive -ErrorAction Stop
    $runState.LiveResponseSessionId = $lrSession.SessionId
    $lrDefs = @($lrSession.CommandDefinitions)
    $lrCurrentDirectory = if ($lrSession.CurrentDirectory) { "$($lrSession.CurrentDirectory)" } else { '/' }

    Write-Step 'Preparing temporary Live Response library files'
    $tmpLibraryMain = Join-Path $env:TEMP 'xdrinternals-macos-validation-main.sh'
    $tmpLibraryDelete = Join-Path $env:TEMP 'xdrinternals-macos-validation-delete.sh'
    Set-Content -Path $tmpLibraryMain -Value "#!/bin/bash`necho xdrinternals-macos-validation-main" -Encoding utf8
    Set-Content -Path $tmpLibraryDelete -Value "#!/bin/bash`necho xdrinternals-macos-validation-delete" -Encoding utf8

    $uploadMain = New-XdrEndpointDeviceLiveResponseLibraryFile -FilePath $tmpLibraryMain -Description 'macOS validation main file' -OverrideIfExists -ErrorAction Stop
    $uploadDelete = New-XdrEndpointDeviceLiveResponseLibraryFile -FilePath $tmpLibraryDelete -Description 'macOS validation delete file' -OverrideIfExists -ErrorAction Stop

    $mainFileName = Get-PropertyOrDefault -Object $uploadMain -PropertyNames @('file_name', 'FileName', 'name') -Default ([System.IO.Path]::GetFileName($tmpLibraryMain))
    $deleteFileName = Get-PropertyOrDefault -Object $uploadDelete -PropertyNames @('file_name', 'FileName', 'name') -Default ([System.IO.Path]::GetFileName($tmpLibraryDelete))

    $lrContext.LIB_FILE_NAME = "$mainFileName"
    $libraryFilesToDelete.Add("$mainFileName")
    $libraryFilesToDelete.Add("$deleteFileName")

    Write-Step 'Building and running Live Response command matrix'
    $lrCases = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $baseTemplates = @{
        'analyze' = 'analyze file /bin/ls'
        'cd' = 'cd /'
        'cls' = 'cls'
        'connect' = 'connect'
        'connections' = 'connections'
        'dir' = 'dir /'
        'drivers' = 'drivers'
        'fg' = 'fg {BG_COMMAND_ID}'
        'fileinfo' = 'fileinfo /bin/ls'
        'findfile' = 'findfile hosts'
        'getfile' = 'getfile /etc/hosts'
        'help' = 'help'
        'jobs' = 'jobs'
        'library' = 'library'
        'log' = 'log'
        'persistence' = 'persistence'
        'prefetch' = 'prefetch'
        'processes' = 'processes'
        'putfile' = 'putfile {LIB_FILE_NAME}'
        'registry' = 'registry /Library/Preferences'
        'remediate' = 'remediate list'
        'run' = 'run {LIB_FILE_NAME}'
        'scheduledtasks' = 'scheduledtasks'
        'services' = 'services'
        'startupfolders' = 'startupfolders'
        'status' = 'status {LAST_COMMAND_ID}'
        'trace' = 'trace'
        'undo' = 'undo {UNDO_TYPE} {UNDO_TARGET_ID}'
    }

    # Bootstrap commands for context
    $lrCases.Add([PSCustomObject]@{ Name='bootstrap-processes'; Kind='bootstrap'; CommandId='processes'; Template='processes'; Timeout=120; BackgroundMode=$false })
    $lrCases.Add([PSCustomObject]@{ Name='bootstrap-findfile-bg'; Kind='bootstrap'; CommandId='findfile'; Template='findfile hosts'; Timeout=180; BackgroundMode=$false })

    foreach ($def in ($lrDefs | Sort-Object -Property command_definition_id)) {
        $commandId = "$($def.command_definition_id)".ToLower()
        if (-not $commandId) { continue }

        $baseTemplate = if ($baseTemplates.ContainsKey($commandId)) {
            $baseTemplates[$commandId]
        } else {
            Add-Limitation -Area 'LiveResponse' -Item $commandId -Reason 'No template mapping defined; using command-only fallback'
            $commandId
        }

        $case = [PSCustomObject]@{ Name="$commandId-baseline"; Kind='baseline'; CommandId=$commandId; Template=$baseTemplate; Timeout=180; BackgroundMode=$false }
        $key = "$($case.CommandId)|$($case.Kind)|$($case.Template)|$($case.BackgroundMode)"
        if ($seen.Add($key)) { $lrCases.Add($case) }

        if ($def.aliases -and @($def.aliases).Count -gt 0) {
            $alias = @($def.aliases)[0]
            $alias = "$alias".Trim()
            if ($alias) {
                $aliasTemplate = $baseTemplate -replace "^$commandId", $alias
                $aliasCase = [PSCustomObject]@{ Name="$commandId-alias-$alias"; Kind='alias'; CommandId=$commandId; Template=$aliasTemplate; Timeout=180; BackgroundMode=$false }
                $aliasKey = "$($aliasCase.CommandId)|$($aliasCase.Kind)|$($aliasCase.Template)|$($aliasCase.BackgroundMode)"
                if ($seen.Add($aliasKey)) { $lrCases.Add($aliasCase) }
            }
        }

        foreach ($flag in @($def.flags)) {
            $flagId = if ($flag -is [string]) { "$flag" } else { "$($flag.flag_id)" }
            if (-not $flagId) { continue }
            $flagCase = [PSCustomObject]@{ Name="$commandId-flag-$flagId"; Kind='flag'; CommandId=$commandId; Template=("$baseTemplate -$flagId"); Timeout=180; BackgroundMode=$false }
            $flagKey = "$($flagCase.CommandId)|$($flagCase.Kind)|$($flagCase.Template)|$($flagCase.BackgroundMode)"
            if ($seen.Add($flagKey)) { $lrCases.Add($flagCase) }
        }

        $parameters = @(Get-LrDefinitionParameters -Definition $def)
        if ($parameters.Count -eq 0) {
            Add-Limitation -Area 'LiveResponse' -Item $commandId -Reason 'No command parameters metadata returned'
            continue
        }

        $requiredParameters = @($parameters | Where-Object { Test-LrParameterRequired -Parameter $_ })
        if ($requiredParameters.Count -gt 1) {
            $requiredTemplate = New-LrTemplateForParameterCase -CommandId $commandId -Parameters $parameters
            if ($requiredTemplate) {
                $requiredCase = [PSCustomObject]@{ Name="$commandId-required-all"; Kind='required'; CommandId=$commandId; Template=$requiredTemplate; Timeout=180; BackgroundMode=$false }
                $requiredKey = "$($requiredCase.CommandId)|$($requiredCase.Kind)|$($requiredCase.Template)|$($requiredCase.BackgroundMode)"
                if ($seen.Add($requiredKey)) { $lrCases.Add($requiredCase) }
            } else {
                Add-Limitation -Area 'LiveResponse' -Item $commandId -Reason 'Unable to construct required multi-parameter command case'
            }
        }

        foreach ($parameter in $parameters) {
            $parameterId = Get-LrParameterId -Parameter $parameter
            if (-not $parameterId) { continue }

            $dataType = Get-LrParameterDataType -Parameter $parameter
            $validValues = @(Get-LrParameterValidValues -Parameter $parameter)
            $isRequired = Test-LrParameterRequired -Parameter $parameter
            $safeParameterId = ConvertTo-SafeCaseLabel -Value $parameterId

            if ($validValues.Count -gt 0) {
                foreach ($validValue in $validValues) {
                    $template = New-LrTemplateForParameterCase -CommandId $commandId -Parameters $parameters -TargetParameterId $parameterId -TargetValue $validValue
                    if (-not $template) {
                        Add-Limitation -Area 'LiveResponse' -Item "$commandId -$parameterId $validValue" -Reason 'Unable to build valid_values command case from metadata'
                        continue
                    }
                    $safeValue = ConvertTo-SafeCaseLabel -Value "$validValue"
                    $validCase = [PSCustomObject]@{ Name="$commandId-param-$safeParameterId-value-$safeValue"; Kind='param-valid-value'; CommandId=$commandId; Template=$template; Timeout=180; BackgroundMode=$false }
                    $validKey = "$($validCase.CommandId)|$($validCase.Kind)|$($validCase.Template)|$($validCase.BackgroundMode)"
                    if ($seen.Add($validKey)) { $lrCases.Add($validCase) }
                }
                continue
            }

            if (-not $isRequired) {
                $resolvedValue = Resolve-LrParameterValue -CommandId $commandId -ParameterId $parameterId -DataType $dataType
                $template = New-LrTemplateForParameterCase -CommandId $commandId -Parameters $parameters -TargetParameterId $parameterId -TargetValue $resolvedValue
                if (-not $template) {
                    Add-Limitation -Area 'LiveResponse' -Item "$commandId -$parameterId" -Reason 'Unable to build optional parameter command case from metadata'
                    continue
                }
                $optionalCase = [PSCustomObject]@{ Name="$commandId-param-$safeParameterId"; Kind='param'; CommandId=$commandId; Template=$template; Timeout=180; BackgroundMode=$false }
                $optionalKey = "$($optionalCase.CommandId)|$($optionalCase.Kind)|$($optionalCase.Template)|$($optionalCase.BackgroundMode)"
                if ($seen.Add($optionalKey)) { $lrCases.Add($optionalCase) }
            }
        }
    }
    # Explicit library add/delete options
    $lrCases.Add([PSCustomObject]@{ Name='library-add'; Kind='context'; CommandId='library'; Template=('library add {0} -description "macOS temp" -hasparameters -parametersdescription "none" -overrideifexists' -f (ConvertTo-LrQuotedValue -Value $tmpLibraryDelete)); Timeout=180; BackgroundMode=$false })
    $lrCases.Add([PSCustomObject]@{ Name='library-delete'; Kind='context'; CommandId='library'; Template=("library delete $deleteFileName"); Timeout=180; BackgroundMode=$false })

    for ($i = 0; $i -lt $lrCases.Count; $i++) {
        $case = $lrCases[$i]
        if ($case.CommandId -eq 'fg' -and (-not $lrContext.BG_COMMAND_ID -or $lrContext.BG_COMMAND_ID -eq '00000000-0000-0000-0000-000000000000') -and $lrContext.LAST_COMMAND_ID) {
            $lrContext.BG_COMMAND_ID = "$($lrContext.LAST_COMMAND_ID)"
        }
        $command = Expand-LrTemplate -Template $case.Template -Context $lrContext
        if (-not $command) {
            $liveResults.Add([PSCustomObject]@{ Name=$case.Name; Kind=$case.Kind; CommandId=$case.CommandId; Template=$case.Template; ResolvedCommand=$null; Status='Skip'; Reason='Missing context placeholders'; TimestampUtc=(Get-Date).ToUniversalTime().ToString('o') })
            continue
        }

        Write-Host ("[{0}/{1}] LR: {2}" -f ($i + 1), $lrCases.Count, $command) -ForegroundColor Yellow

        $started = Get-Date
        try {
            $result = Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId $lrSession.SessionId -Command $command -CurrentDirectory $lrCurrentDirectory -CommandDefinitions $lrDefs -BackgroundMode:([bool]$case.BackgroundMode) -TimeoutSeconds ([int]$case.Timeout) -ErrorAction Stop

            if ($result.context -and $result.context.current_directory) {
                $lrCurrentDirectory = "$($result.context.current_directory)"
            }
            if ($result.command_id) {
                $lrContext.LAST_COMMAND_ID = "$($result.command_id)"
            }
            if ($case.BackgroundMode -and $result.command_id) {
                $lrContext.BG_COMMAND_ID = "$($result.command_id)"
            }

            if ($case.CommandId -eq 'processes' -and $result.outputs) {
                foreach ($out in @($result.outputs)) {
                    if ($out.data -is [array] -and $out.data.Count -gt 0) {
                        $processIdValue = Get-PropertyOrDefault -Object $out.data[0] -PropertyNames @('pid', 'ProcessId') -Default $null
                        if ($processIdValue) { $lrContext.PROCESS_PID = "$processIdValue"; break }
                    }
                }
            }

            if ($case.CommandId -eq 'remediate') {
                $undoType = $null
                $undoTarget = $null
                if ("$command" -match '^remediate\s+(file|process)\s+(.+)$') {
                    $undoType = "$($Matches[1])"
                    $undoTarget = "$($Matches[2])"
                } elseif ("$command" -match '^remediate\s+-type\s+(file|process)\s+-id\s+(.+)$') {
                    $undoType = "$($Matches[1])"
                    $undoTarget = "$($Matches[2])"
                } elseif ("$command" -match '^remediate\s+-id\s+(.+)\s+-type\s+(file|process)$') {
                    $undoType = "$($Matches[2])"
                    $undoTarget = "$($Matches[1])"
                }

                if ($undoType -and $undoTarget) {
                    $lrContext.UNDO_TYPE = "$undoType"
                    $lrContext.UNDO_TARGET_ID = "$undoTarget"
                    $lrUndoQueue.Add("undo -type $undoType -id $undoTarget")
                }
            }

            $errors = @()
            if ($result.errors) {
                $errors = @($result.errors | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.message } } | Where-Object { $_ })
            }
            $errorText = ($errors -join ' ; ')

            $status = if ($result.completed_on -and $errors.Count -eq 0) { 'Pass' } elseif ($result.completed_on -and $errors.Count -gt 0) { 'Warn' } else { 'Fail' }
            if ($errorText -match 'unsupported|not supported|not applicable|not available') {
                Add-Limitation -Area 'LiveResponse' -Item $command -Reason 'Command unsupported on macOS' -Evidence $errorText
            }

            $liveResults.Add([PSCustomObject]@{
                Name = $case.Name
                Kind = $case.Kind
                CommandId = $case.CommandId
                Template = $case.Template
                ResolvedCommand = $command
                Status = $status
                StartedUtc = $started.ToUniversalTime().ToString('o')
                CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                CommandGuid = $result.command_id
                ApiStatus = $result.status
                CompletedOn = $result.completed_on
                DurationSeconds = $result.duration_seconds
                CurrentDirectory = $lrCurrentDirectory
                Errors = @($errors)
                OutputSummary = (Get-LrOutputSummary -Result $result)
            })
        } catch {
            $msg = Get-ErrorText -ErrorRecord $_
            if ($msg -match 'unsupported|not supported|not applicable|not available') {
                Add-Limitation -Area 'LiveResponse' -Item $command -Reason 'Command unsupported on macOS' -Evidence $msg
            }
            $liveResults.Add([PSCustomObject]@{
                Name = $case.Name
                Kind = $case.Kind
                CommandId = $case.CommandId
                Template = $case.Template
                ResolvedCommand = $command
                Status = 'Fail'
                StartedUtc = $started.ToUniversalTime().ToString('o')
                CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                CommandGuid = $null
                ApiStatus = $null
                CompletedOn = $null
                DurationSeconds = $null
                CurrentDirectory = $lrCurrentDirectory
                Errors = @($msg)
                OutputSummary = $null
            })
        }

        if ($LiveResponseDelaySeconds -gt 0 -and $i -lt ($lrCases.Count - 1)) {
            Start-Sleep -Seconds $LiveResponseDelaySeconds
        }
    }

    foreach ($undoCommand in @($lrUndoQueue | Select-Object -Unique)) {
        try {
            $null = Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId $lrSession.SessionId -Command $undoCommand -CurrentDirectory $lrCurrentDirectory -CommandDefinitions $lrDefs -TimeoutSeconds 180 -ErrorAction Stop
        } catch {
            Add-Limitation -Area 'LiveResponse' -Item $undoCommand -Reason 'Queued undo failed' -Evidence (Get-ErrorText -ErrorRecord $_)
        }
    }

    Write-Step 'Executing machine actions'
    $actionCases = @(
        @{ Name = 'WhatIf-StartTroubleshoot-Default'; Params = @{ StartTroubleshoot = $true }; WhatIf = $true; Poll = $false; DelayAfter = $false; UnsupportedExpected = $false },
        @{ Name = 'Scan-Quick'; Params = @{ Scan = 'Quick' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'Scan-Full'; Params = @{ Scan = 'Full'; Comment = 'macOS validation full scan' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'Isolate-Full'; Params = @{ Isolate = 'Full'; Comment = 'macOS validation full isolation' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'Release-AfterFullIsolation'; Params = @{ ReleaseFromIsolation = $true; Comment = 'macOS rollback full isolation' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'Isolate-Selective'; Params = @{ Isolate = 'Selective'; Comment = 'macOS validation selective isolation' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'Release-AfterSelectiveIsolation'; Params = @{ ReleaseFromIsolation = $true; Comment = 'macOS rollback selective isolation' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'RestrictAppExecution'; Params = @{ RestrictAppExecution = $true; Comment = 'macOS unsupported check - restrict' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $true },
        @{ Name = 'RemoveAppExecutionRestriction'; Params = @{ RemoveAppExecutionRestriction = $true; Comment = 'macOS unsupported check - remove' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $true },
        @{ Name = 'CollectInvestigationPackage'; Params = @{ CollectInvestigationPackage = $true; Comment = 'macOS evidence collection' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'CollectSupportLogs'; Params = @{ CollectSupportLogs = $true; Comment = 'macOS support logs validation' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'StartTroubleshoot-1h'; Params = @{ StartTroubleshoot = $true; TroubleshootDurationHours = 1; Comment = 'macOS troubleshoot 1h' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'StopTroubleshoot-After1h'; Params = @{ StopTroubleshoot = $true; Comment = 'macOS troubleshoot stop' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'StartTroubleshoot-12h'; Params = @{ StartTroubleshoot = $true; TroubleshootDurationHours = 12; Comment = 'macOS troubleshoot 12h' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'StopTroubleshoot-After12h'; Params = @{ StopTroubleshoot = $true; Comment = 'macOS troubleshoot stop' }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetTags-Single'; Params = @{ SetTags = @('XDRInternals-MacOS-Validation') }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetTags-Multi'; Params = @{ SetTags = @('XDRInternals-MacOS-Validation', 'XDRInternals-MacOS-Validation-2') }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetAssetValue-Low'; Params = @{ SetAssetValue = 'Low' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetAssetValue-Normal'; Params = @{ SetAssetValue = 'Normal' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetAssetValue-High'; Params = @{ SetAssetValue = 'High' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetCriticality-VeryHigh'; Params = @{ SetCriticalityLevel = 'VeryHigh' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetCriticality-High'; Params = @{ SetCriticalityLevel = 'High' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetCriticality-Medium'; Params = @{ SetCriticalityLevel = 'Medium' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetCriticality-Low'; Params = @{ SetCriticalityLevel = 'Low' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetCriticality-Reset'; Params = @{ SetCriticalityLevel = 'Reset' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetExclusion-Excluded'; Params = @{ SetExclusionState = 'Excluded'; Justification = 'MachineOutOfScope'; Notes = 'macOS validation temporary exclude' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'SetExclusion-Included'; Params = @{ SetExclusionState = 'Included' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'ForceSync-Default'; Params = @{ ForceSync = $true }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'ForceSync-Custom'; Params = @{ ForceSync = $true; Comment = 'macOS force sync custom comment' }; WhatIf = $false; Poll = $false; DelayAfter = $true; UnsupportedExpected = $false },
        @{ Name = 'StartInvestigation'; Params = @{ StartInvestigation = $true }; WhatIf = $false; Poll = $true; DelayAfter = $true; UnsupportedExpected = $true }
    )

    for ($i = 0; $i -lt $actionCases.Count; $i++) {
        $case = $actionCases[$i]
        Write-Host ("[{0}/{1}] Action: {2}" -f ($i + 1), $actionCases.Count, $case.Name) -ForegroundColor Yellow

        $invokeParams = @{ DeviceId = $DeviceId }
        foreach ($kv in $case.Params.GetEnumerator()) { $invokeParams[$kv.Key] = $kv.Value }
        if ($case.WhatIf) { $invokeParams['WhatIf'] = $true } else { $invokeParams['Confirm'] = $false }

        $started = Get-Date
        $requestId = $null
        try {
            $result = Invoke-XdrEndpointDeviceAction @invokeParams -ErrorAction Stop
            $requestId = Get-RequestId -Result $result
            $pollResult = $null
            if (-not $case.WhatIf -and $case.Poll -and $requestId) {
                $pollResult = Wait-ActionCompletion -DeviceId $DeviceId -RequestId $requestId -PollSeconds $ActionPollSeconds -TimeoutMinutes $ActionTimeoutMinutes
            }

            $status = 'Pass'
            $statusEvidence = if ($pollResult) { "$($pollResult.FinalStatus)" } else { 'Submitted' }
            if ($pollResult -and $pollResult.TimedOut) {
                $status = 'Warn'
                $statusEvidence = 'Timed out waiting for terminal status'
            }
            if ($statusEvidence -match 'unsupported|not supported|not applicable|not available') {
                Add-Limitation -Area 'MachineAction' -Item $case.Name -Reason 'Action unsupported on macOS' -Evidence $statusEvidence
                if ($case.UnsupportedExpected) { $status = 'Pass' } else { $status = 'Warn' }
            }

            $actionResults.Add([PSCustomObject]@{
                Name = $case.Name
                WhatIf = [bool]$case.WhatIf
                UnsupportedExpected = [bool]$case.UnsupportedExpected
                StartedUtc = $started.ToUniversalTime().ToString('o')
                CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                RequestId = $requestId
                Status = $status
                StatusEvidence = $statusEvidence
                Parameters = $case.Params
                RawResult = $result
                Poll = $pollResult
                Errors = @()
            })
        } catch {
            $msg = Get-ErrorText -ErrorRecord $_
            if ($msg -match 'unsupported|not supported|not applicable|not available') {
                Add-Limitation -Area 'MachineAction' -Item $case.Name -Reason 'Action unsupported on macOS' -Evidence $msg
            }
            $status = if ($case.UnsupportedExpected -and $msg -match 'unsupported|not supported|not applicable|not available') { 'Pass' } else { 'Fail' }
            $actionResults.Add([PSCustomObject]@{
                Name = $case.Name
                WhatIf = [bool]$case.WhatIf
                UnsupportedExpected = [bool]$case.UnsupportedExpected
                StartedUtc = $started.ToUniversalTime().ToString('o')
                CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                RequestId = $requestId
                Status = $status
                StatusEvidence = $msg
                Parameters = $case.Params
                RawResult = $null
                Poll = $null
                Errors = @($msg)
            })
        }

        if (-not $case.WhatIf -and $MachineActionDelaySeconds -gt 0 -and $case.DelayAfter -and $i -lt ($actionCases.Count - 1)) {
            Start-Sleep -Seconds $MachineActionDelaySeconds
        }
    }
}
finally {
    Write-Step 'Running final rollback sequence' -Color 'Yellow'

    foreach ($libraryName in @($libraryFilesToDelete | Select-Object -Unique)) {
        Invoke-RollbackAction -Name ("RemoveLibraryFile:{0}" -f $libraryName) -ScriptBlock {
            try {
                Remove-XdrEndpointDeviceLiveResponseLibraryFile -FileName $libraryName -Confirm:$false -ErrorAction Stop | Out-Null
            } catch {
                $msg = Get-ErrorText -ErrorRecord $_
                if ($msg -match 'not found') {
                    return
                }
                throw
            }
        }
    }

    Invoke-RollbackAction -Name 'ReleaseFromIsolation' -ScriptBlock {
        Invoke-XdrEndpointDeviceAction -DeviceId $DeviceId -ReleaseFromIsolation -Comment 'Final rollback - release from isolation' -Confirm:$false -ErrorAction Stop | Out-Null
    }
    Invoke-RollbackAction -Name 'StopTroubleshoot' -ScriptBlock {
        Invoke-XdrEndpointDeviceAction -DeviceId $DeviceId -StopTroubleshoot -Comment 'Final rollback - stop troubleshoot' -Confirm:$false -ErrorAction Stop | Out-Null
    }

    $restoreExclusion = if ($baseline -and $baseline.ExclusionState) { "$($baseline.ExclusionState)" } else { 'Included' }
    if ($restoreExclusion -notin @('Excluded', 'Included')) { $restoreExclusion = 'Included' }
    Invoke-RollbackAction -Name ("RestoreExclusion:{0}" -f $restoreExclusion) -ScriptBlock {
        if ($restoreExclusion -eq 'Excluded') {
            Invoke-XdrEndpointDeviceAction -DeviceId $DeviceId -SetExclusionState Excluded -Justification 'MachineOutOfScope' -Notes 'Final rollback' -Confirm:$false -ErrorAction Stop | Out-Null
        } else {
            Invoke-XdrEndpointDeviceAction -DeviceId $DeviceId -SetExclusionState Included -Confirm:$false -ErrorAction Stop | Out-Null
        }
    }

    $restoreCriticality = if ($baseline -and $baseline.CriticalityLevel) { "$($baseline.CriticalityLevel)" } else { 'Reset' }
    if ($restoreCriticality -match '^0$') { $restoreCriticality = 'VeryHigh' }
    elseif ($restoreCriticality -match '^1$') { $restoreCriticality = 'High' }
    elseif ($restoreCriticality -match '^2$') { $restoreCriticality = 'Medium' }
    elseif ($restoreCriticality -match '^3$') { $restoreCriticality = 'Low' }
    if ($restoreCriticality -notin @('VeryHigh', 'High', 'Medium', 'Low', 'Reset')) { $restoreCriticality = 'Reset' }
    Invoke-RollbackAction -Name ("RestoreCriticality:{0}" -f $restoreCriticality) -ScriptBlock {
        Invoke-XdrEndpointDeviceAction -DeviceId $DeviceId -SetCriticalityLevel $restoreCriticality -Confirm:$false -ErrorAction Stop | Out-Null
    }

    $restoreAssetValue = if ($baseline -and $baseline.AssetValue) { "$($baseline.AssetValue)" } else { 'Normal' }
    if ($restoreAssetValue -notin @('Low', 'Normal', 'High')) { $restoreAssetValue = 'Normal' }
    Invoke-RollbackAction -Name ("RestoreAssetValue:{0}" -f $restoreAssetValue) -ScriptBlock {
        Invoke-XdrEndpointDeviceAction -DeviceId $DeviceId -SetAssetValue $restoreAssetValue -Confirm:$false -ErrorAction Stop | Out-Null
    }

    if ($baseline -and $baseline.UserDefinedTags -and @($baseline.UserDefinedTags).Count -gt 0) {
        $tagSet = @($baseline.UserDefinedTags)
        Invoke-RollbackAction -Name 'RestoreTags:BaselineSet' -ScriptBlock {
            Invoke-XdrEndpointDeviceAction -DeviceId $DeviceId -SetTags $tagSet -Confirm:$false -ErrorAction Stop | Out-Null
        }
    } else {
        Invoke-RollbackAction -Name 'RestoreTags:RemoveTestTags' -ScriptBlock {
            Set-XdrEndpointDeviceTag -DeviceId $DeviceId -Remove @('XDRInternals-MacOS-Validation', 'XDRInternals-MacOS-Validation-2') -ErrorAction Stop | Out-Null
        }
    }

    if ($lrSession -and $lrSession.SessionId) {
        Invoke-RollbackAction -Name 'DisconnectLiveResponse' -ScriptBlock {
            Disconnect-XdrEndpointDeviceLiveResponse -SessionId $lrSession.SessionId -ErrorAction Stop | Out-Null
        }
    }

    $runState.CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')

    $livePayload = [PSCustomObject]@{ RunState = $runState; Results = @($liveResults) }
    $actionPayload = [PSCustomObject]@{ RunState = $runState; Results = @($actionResults); Rollback = @($rollbackResults) }

    $livePayload | ConvertTo-Json -Depth 10 | Set-Content -Path $liveOutputPath -Encoding UTF8
    $actionPayload | ConvertTo-Json -Depth 10 | Set-Content -Path $actionOutputPath -Encoding UTF8

    $livePass = (@($liveResults | Where-Object { $_.Status -eq 'Pass' })).Count
    $liveWarn = (@($liveResults | Where-Object { $_.Status -eq 'Warn' })).Count
    $liveFail = (@($liveResults | Where-Object { $_.Status -eq 'Fail' })).Count
    $liveSkip = (@($liveResults | Where-Object { $_.Status -eq 'Skip' })).Count

    $actionPass = (@($actionResults | Where-Object { $_.Status -eq 'Pass' })).Count
    $actionWarn = (@($actionResults | Where-Object { $_.Status -eq 'Warn' })).Count
    $actionFail = (@($actionResults | Where-Object { $_.Status -eq 'Fail' })).Count

    $rollbackPass = (@($rollbackResults | Where-Object { $_.Status -eq 'Pass' })).Count
    $rollbackFail = (@($rollbackResults | Where-Object { $_.Status -eq 'Fail' })).Count

    $summary = @(
        '# macOS Endpoint Validation Summary',
        '',
        "- DeviceId: $DeviceId",
        "- DeviceName: $($runState.DeviceName)",
        "- OsPlatform: $($runState.OsPlatform)",
        "- StartedUtc: $($runState.StartedUtc)",
        "- CompletedUtc: $($runState.CompletedUtc)",
        '',
        '## Live Response Results',
        "- Pass: $livePass",
        "- Warn: $liveWarn",
        "- Fail: $liveFail",
        "- Skip: $liveSkip",
        "- Output: $liveOutputPath",
        '',
        '## Machine Action Results',
        "- Pass: $actionPass",
        "- Warn: $actionWarn",
        "- Fail: $actionFail",
        "- Output: $actionOutputPath",
        '',
        '## Rollback Results',
        "- Pass: $rollbackPass",
        "- Fail: $rollbackFail",
        '',
        '## Limitations',
        "- Count: $($limitations.Count)",
        "- Output: $limitationsOutputPath"
    )
    $summary | Set-Content -Path $summaryOutputPath -Encoding UTF8

    $limitLines = [System.Collections.Generic.List[string]]::new()
    $limitLines.Add('# macOS Validation Limitations')
    $limitLines.Add('')
    $limitLines.Add('| TimestampUtc | Area | Item | Reason | Evidence |')
    $limitLines.Add('| --- | --- | --- | --- | --- |')
    foreach ($item in $limitations) {
        $reason = ("$($item.Reason)" -replace '\|', '/' -replace '\r?\n', ' ')
        $evidence = ("$($item.Evidence)" -replace '\|', '/' -replace '\r?\n', ' ')
        $limitLines.Add("| $($item.TimestampUtc) | $($item.Area) | $($item.Item) | $reason | $evidence |")
    }
    $limitLines | Set-Content -Path $limitationsOutputPath -Encoding UTF8

    Write-Host 'Artifacts written:' -ForegroundColor Green
    Write-Host "  $liveOutputPath" -ForegroundColor Gray
    Write-Host "  $actionOutputPath" -ForegroundColor Gray
    Write-Host "  $summaryOutputPath" -ForegroundColor Gray
    Write-Host "  $limitationsOutputPath" -ForegroundColor Gray
}

[PSCustomObject]@{
    LiveResponseResultPath = $liveOutputPath
    MachineActionResultPath = $actionOutputPath
    SummaryPath = $summaryOutputPath
    LimitationsPath = $limitationsOutputPath
    LiveResponseCount = $liveResults.Count
    MachineActionCount = $actionResults.Count
    LimitationCount = $limitations.Count
    RollbackCount = $rollbackResults.Count
}















