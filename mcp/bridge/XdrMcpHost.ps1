#Requires -Version 7.2
<#
    .SYNOPSIS
        Persistent PowerShell host process for the XDRInternals MCP server.

    .DESCRIPTION
        Reads newline-delimited JSON requests from stdin, executes XDRInternals cmdlets inside a
        dedicated long-lived runspace, and writes newline-delimited JSON responses to stdout.

        The runspace keeps XDRInternals session state (portal cookies, XSRF token, module cache)
        alive between requests, so one interactive sign-in serves every later tool call.

        Every PowerShell stream (success, error, warning, information/Write-Host, verbose) is
        captured per request through the PowerShell API, so nothing except protocol JSON is ever
        written to stdout. Requests are executed one at a time; the runspace is single threaded.

    .PARAMETER ModulePath
        Module name or full path to XDRInternals.psd1. Defaults to the module name, which
        resolves through PSModulePath.

    .PARAMETER DefaultTimeoutSeconds
        Timeout applied when a request does not specify one.

    .NOTES
        Protocol (one JSON object per line, both directions):

        Request   { "id": "1", "op": "invoke", "command": "Get-XdrIncident",
                    "params": { "LookBackInDays": 7 }, "timeoutSeconds": 120,
                    "maxItems": 50, "properties": ["IncidentId"], "depth": 8 }
        Response  { "id": "1", "ok": true, "data": { "items": [], "totalCount": 0,
                    "truncated": false, "warnings": [], "information": [], "errors": [] } }

        Other ops: ping, reset (recycle the runspace and drop all session state),
        commands (list XDRInternals cmdlets), help (cmdlet help for one command).
#>
[CmdletBinding()]
param(
    [string]$ModulePath = 'XDRInternals',

    [ValidateRange(5, 3600)]
    [int]$DefaultTimeoutSeconds = 300
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
try {
    [Console]::OutputEncoding = $utf8NoBom
    [Console]::InputEncoding = $utf8NoBom
} catch {
    # Encoding cannot be changed when the streams are already redirected on some platforms.
}

$script:Runspace = $null
$script:AllowedCommands = @{}
$script:ModuleName = 'XDRInternals'
$script:CommonParameters = @(
    'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ProgressAction',
    'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer',
    'PipelineVariable', 'WhatIf', 'Confirm'
)

function Write-ProtocolResponse {
    <#
        .SYNOPSIS
            Writes a single response object to stdout as one line of JSON.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Payload,

        [int]$Depth = 12
    )

    if ($Depth -lt 3) { $Depth = 3 }
    if ($Depth -gt 100) { $Depth = 100 }

    try {
        $json = ConvertTo-Json -InputObject $Payload -Depth $Depth -Compress -WarningAction SilentlyContinue
    } catch {
        $json = ConvertTo-Json -InputObject @{
            id    = $Payload['id']
            ok    = $false
            error = "Failed to serialize the response: $($_.Exception.Message). Retry with a smaller maxItems value or a lower depth."
        } -Depth 4 -Compress
    }

    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}

function Format-ErrorRecordMessage {
    <#
        .SYNOPSIS
            Converts an ErrorRecord into a single readable line.
    #>
    param($ErrorRecord)

    if ($null -eq $ErrorRecord) { return $null }

    $exception = $ErrorRecord.Exception
    # EndInvoke wraps pipeline failures in a MethodInvocationException; report the real cause.
    while ($exception -is [System.Management.Automation.MethodInvocationException] -and $exception.InnerException) {
        $exception = $exception.InnerException
    }

    $message = if ($exception -and $exception.Message) {
        $exception.Message
    } else {
        [string]$ErrorRecord
    }

    $activity = $null
    if ($ErrorRecord.PSObject.Properties['CategoryInfo'] -and $ErrorRecord.CategoryInfo) {
        $activity = $ErrorRecord.CategoryInfo.Activity
    }

    $message = ($message -replace '\s+', ' ').Trim()
    if ($activity) { "[$activity] $message" } else { $message }
}

function Invoke-InRunspace {
    <#
        .SYNOPSIS
            Runs one command in the shared runspace and captures every stream.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [hashtable]$Parameters = @{},

        [int]$TimeoutSeconds = 300
    )

    $shell = [PowerShell]::Create()
    $shell.Runspace = $script:Runspace

    try {
        $null = $shell.AddCommand($Command)
        foreach ($key in $Parameters.Keys) {
            $null = $shell.AddParameter($key, $Parameters[$key])
        }

        $terminating = $null
        $output = @()
        $timedOut = $false

        $async = $shell.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            $timedOut = $true
            try { $shell.Stop() } catch { }
        } else {
            try {
                $output = $shell.EndInvoke($async)
            } catch {
                $terminating = $_
            }
        }

        if ($timedOut) {
            throw "Command '$Command' exceeded the $TimeoutSeconds second timeout and was cancelled. Narrow the time range or page size, or raise timeoutSeconds."
        }

        $errors = @()
        foreach ($record in $shell.Streams.Error) {
            $errors += Format-ErrorRecordMessage -ErrorRecord $record
        }
        if ($terminating) {
            $errors += Format-ErrorRecordMessage -ErrorRecord $terminating
        }

        $warnings = @()
        foreach ($record in $shell.Streams.Warning) {
            $warnings += ($record.Message -replace '\s+', ' ').Trim()
        }

        $information = @()
        foreach ($record in $shell.Streams.Information) {
            if ($null -ne $record.MessageData) {
                $text = ([string]$record.MessageData).Trim()
                if ($text) { $information += $text }
            }
        }

        [pscustomobject]@{
            Output      = @($output)
            Errors      = @($errors | Where-Object { $_ })
            Warnings    = @($warnings | Where-Object { $_ })
            Information = @($information)
            Failed      = [bool]$terminating
        }
    } finally {
        try { $shell.Dispose() } catch { }
    }
}

function Initialize-XdrRunspace {
    <#
        .SYNOPSIS
            Creates (or recreates) the runspace and imports XDRInternals into it.
    #>
    param()

    if ($script:Runspace) {
        try { $script:Runspace.Close() } catch { }
        try { $script:Runspace.Dispose() } catch { }
        $script:Runspace = $null
        $script:AllowedCommands = @{}
    }

    $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $state.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $runspace = [runspacefactory]::CreateRunspace($state)
    $runspace.Open()
    $script:Runspace = $runspace

    $import = Invoke-InRunspace -Command 'Import-Module' -TimeoutSeconds 180 -Parameters @{
        Name        = $ModulePath
        Force       = $true
        PassThru    = $true
        ErrorAction = 'Stop'
    }

    if ($import.Failed -or $import.Errors.Count -gt 0) {
        throw "Failed to import the XDRInternals module from '$ModulePath': $($import.Errors -join '; '). Install it with 'Install-Module XDRInternals' or set XDR_MODULE_PATH to the full path of XDRInternals.psd1."
    }

    if ($import.Output.Count -gt 0 -and $import.Output[0].Name) {
        $script:ModuleName = $import.Output[0].Name
    }

    $commands = Invoke-InRunspace -Command 'Get-Command' -TimeoutSeconds 60 -Parameters @{
        Module      = $script:ModuleName
        ErrorAction = 'Stop'
    }

    if ($commands.Output.Count -eq 0) {
        throw "The module '$script:ModuleName' was imported but exported no commands."
    }

    $script:AllowedCommands = @{}
    foreach ($command in $commands.Output) {
        $script:AllowedCommands[$command.Name] = $command
    }
    foreach ($extra in @('Get-Help', 'Get-Module')) {
        $script:AllowedCommands[$extra] = $null
    }
}

function Get-XdrRunspaceCommand {
    <#
        .SYNOPSIS
            Resolves an allowlisted command, initializing the runspace on first use.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $script:Runspace) { Initialize-XdrRunspace }

    $match = $script:AllowedCommands.Keys | Where-Object { $_ -eq $Name } | Select-Object -First 1
    if (-not $match) {
        throw "Command '$Name' is not exported by the XDRInternals module and cannot be executed. Use the cmdlet listing tool to discover valid commands."
    }

    [pscustomobject]@{
        Name        = $match
        CommandInfo = $script:AllowedCommands[$match]
    }
}

function ConvertTo-PlainHashtable {
    <#
        .SYNOPSIS
            Normalizes a deserialized JSON value into hashtables and arrays.
    #>
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $Value.Keys) {
            $result[[string]$key] = ConvertTo-PlainHashtable -Value $Value[$key]
        }
        return $result
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @(foreach ($item in $Value) { ConvertTo-PlainHashtable -Value $item })
    }

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $result = @{}
        foreach ($property in $Value.PSObject.Properties) {
            $result[$property.Name] = ConvertTo-PlainHashtable -Value $property.Value
        }
        return $result
    }

    return $Value
}

function Resolve-ParameterValue {
    <#
        .SYNOPSIS
            Coerces a JSON value into the type the target parameter expects.

        .DESCRIPTION
            Dates are parsed with invariant culture so the host locale cannot change the meaning
            of an ISO 8601 timestamp, hashtable parameters are rebuilt as real hashtables, and
            switch parameters accept booleans.
    #>
    param(
        $Value,
        [Type]$ParameterType
    )

    if ($null -eq $ParameterType -or $null -eq $Value) { return $Value }

    $elementType = if ($ParameterType.IsArray) { $ParameterType.GetElementType() } else { $ParameterType }

    if ($elementType -eq [System.Management.Automation.SwitchParameter]) {
        return [System.Management.Automation.SwitchParameter]::new([bool]$Value)
    }

    if ($elementType -eq [datetime]) {
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        $convert = {
            param($single)
            if ($single -is [datetime]) { return $single }
            [datetime]::Parse([string]$single, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
        }
        if ($ParameterType.IsArray) {
            return @(foreach ($item in @($Value)) { & $convert $item })
        }
        return & $convert $Value
    }

    if ($elementType -eq [hashtable] -or $elementType -eq [System.Collections.IDictionary]) {
        return ConvertTo-PlainHashtable -Value $Value
    }

    if ($elementType -eq [securestring]) {
        return ConvertTo-SecureString -String ([string]$Value) -AsPlainText -Force
    }

    if ($ParameterType.IsArray -and $Value -isnot [System.Collections.IEnumerable]) {
        return @($Value)
    }

    if ($Value -is [System.Collections.IDictionary]) {
        return ConvertTo-PlainHashtable -Value $Value
    }

    return $Value
}

function New-InvokeParameterSet {
    <#
        .SYNOPSIS
            Maps request parameters onto the resolved command, validating parameter names.
    #>
    param(
        [Parameter(Mandatory)]
        $Command,

        $RequestParameters
    )

    $result = @{}
    if ($null -eq $RequestParameters) { return $result }

    $normalized = ConvertTo-PlainHashtable -Value $RequestParameters
    if ($normalized -isnot [System.Collections.IDictionary]) {
        throw "The 'params' field must be a JSON object."
    }

    $metadata = $null
    if ($Command.CommandInfo) { $metadata = $Command.CommandInfo.Parameters }

    foreach ($key in $normalized.Keys) {
        $value = $normalized[$key]
        if ($null -eq $value) { continue }

        if ($metadata) {
            $parameterName = $metadata.Keys | Where-Object { $_ -eq $key } | Select-Object -First 1
            if (-not $parameterName) {
                $available = ($metadata.Keys | Where-Object { $script:CommonParameters -notcontains $_ } | Sort-Object) -join ', '
                throw "Parameter '$key' does not exist on '$($Command.Name)'. Available parameters: $available."
            }
            $result[$parameterName] = Resolve-ParameterValue -Value $value -ParameterType $metadata[$parameterName].ParameterType
        } else {
            $result[[string]$key] = $value
        }
    }

    return $result
}

function Invoke-RequestOperation {
    <#
        .SYNOPSIS
            Executes an 'invoke' request and returns the response data payload.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Request
    )

    $commandName = [string]$Request['command']
    if ([string]::IsNullOrWhiteSpace($commandName)) {
        throw "The 'command' field is required for the invoke operation."
    }

    $command = Get-XdrRunspaceCommand -Name $commandName
    $parameters = New-InvokeParameterSet -Command $command -RequestParameters $Request['params']

    $timeout = $DefaultTimeoutSeconds
    if ($Request['timeoutSeconds']) { $timeout = [int]$Request['timeoutSeconds'] }
    if ($timeout -lt 5) { $timeout = 5 }
    if ($timeout -gt 3600) { $timeout = 3600 }

    $result = Invoke-InRunspace -Command $command.Name -Parameters $parameters -TimeoutSeconds $timeout

    $items = @($result.Output)
    $totalCount = $items.Count

    $properties = @()
    if ($Request['properties']) { $properties = @($Request['properties'] | Where-Object { $_ }) }
    if ($properties.Count -gt 0) {
        $items = @($items | Select-Object -Property $properties)
    }

    $truncated = $false
    $maxItems = 0
    if ($Request['maxItems']) { $maxItems = [int]$Request['maxItems'] }
    if ($maxItems -gt 0 -and $totalCount -gt $maxItems) {
        $items = @($items | Select-Object -First $maxItems)
        $truncated = $true
    }

    @{
        items       = $items
        totalCount  = $totalCount
        truncated   = $truncated
        warnings    = $result.Warnings
        information = $result.Information
        errors      = $result.Errors
    }
}

function Get-CommandInventory {
    <#
        .SYNOPSIS
            Returns the exported cmdlets with their parameter names.
    #>
    param()

    if (-not $script:Runspace) { Initialize-XdrRunspace }

    $commands = foreach ($name in ($script:AllowedCommands.Keys | Sort-Object)) {
        $info = $script:AllowedCommands[$name]
        if (-not $info) { continue }

        $parameterNames = @()
        if ($info.Parameters) {
            $parameterNames = @($info.Parameters.Keys | Where-Object { $script:CommonParameters -notcontains $_ } | Sort-Object)
        }

        @{
            name       = $info.Name
            verb       = $info.Verb
            noun       = $info.Noun
            parameters = $parameterNames
        }
    }

    @{
        module      = $script:ModuleName
        totalCount  = @($commands).Count
        items       = @($commands)
        truncated   = $false
        warnings    = @()
        information = @()
        errors      = @()
    }
}

function Get-CommandHelp {
    <#
        .SYNOPSIS
            Returns structured help for a single exported cmdlet.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $command = Get-XdrRunspaceCommand -Name $Name
    $result = Invoke-InRunspace -Command 'Get-Help' -TimeoutSeconds 60 -Parameters @{
        Name        = $command.Name
        Full        = $true
        ErrorAction = 'Stop'
    }

    $help = $result.Output | Select-Object -First 1
    if (-not $help) {
        throw "No help content was found for '$($command.Name)'."
    }

    $parameters = @()
    if ($help.parameters -and $help.parameters.parameter) {
        foreach ($parameter in $help.parameters.parameter) {
            $parameters += @{
                name          = $parameter.name
                type          = if ($parameter.type) { $parameter.type.name } else { $null }
                required      = $parameter.required
                parameterSet  = $parameter.parameterSetName
                description   = (($parameter.description | ForEach-Object { $_.Text }) -join ' ').Trim()
            }
        }
    }

    $examples = @()
    if ($help.examples -and $help.examples.example) {
        foreach ($example in ($help.examples.example | Select-Object -First 5)) {
            $examples += @{
                title  = ($example.title -replace '-', '').Trim()
                code   = [string]$example.code
                remarks = (($example.remarks | ForEach-Object { $_.Text }) -join ' ').Trim()
            }
        }
    }

    @{
        items = @(
            @{
                name        = $command.Name
                synopsis    = (([string]$help.Synopsis) -replace '\s+', ' ').Trim()
                description = ((($help.description | ForEach-Object { $_.Text }) -join ' ') -replace '\s+', ' ').Trim()
                syntax      = @(
                    $help.syntax.syntaxItem | ForEach-Object {
                        $tokens = @($_.name)
                        foreach ($parameter in @($_.parameter)) {
                            $tokens += if ($parameter.required -eq 'true') { "-$($parameter.name)" } else { "[-$($parameter.name)]" }
                        }
                        $tokens -join ' '
                    }
                )
                parameters  = $parameters
                examples    = $examples
            }
        )
        totalCount  = 1
        truncated   = $false
        warnings    = $result.Warnings
        information = @()
        errors      = $result.Errors
    }
}

# Main request loop. One line in, one line out, strictly sequential.
while ($true) {
    $line = $null
    try {
        $line = [Console]::In.ReadLine()
    } catch {
        break
    }

    if ($null -eq $line) { break }
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    $requestId = $null
    $depth = 12

    try {
        $request = $line | ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop
        if ($request -isnot [System.Collections.IDictionary]) {
            throw 'Each request must be a JSON object.'
        }

        $requestId = $request['id']
        if ($request['depth']) { $depth = [int]$request['depth'] + 4 }

        $operation = [string]$request['op']
        switch ($operation) {
            'ping' {
                Write-ProtocolResponse -Depth 6 -Payload @{
                    id   = $requestId
                    ok   = $true
                    data = @{
                        runspaceReady = [bool]$script:Runspace
                        module        = $script:ModuleName
                        pwshVersion   = $PSVersionTable.PSVersion.ToString()
                    }
                }
            }
            'reset' {
                Initialize-XdrRunspace
                Write-ProtocolResponse -Depth 6 -Payload @{
                    id   = $requestId
                    ok   = $true
                    data = @{ runspaceReady = $true; module = $script:ModuleName }
                }
            }
            'commands' {
                Write-ProtocolResponse -Depth 8 -Payload @{
                    id   = $requestId
                    ok   = $true
                    data = Get-CommandInventory
                }
            }
            'help' {
                $name = [string]$request['command']
                if ([string]::IsNullOrWhiteSpace($name)) {
                    throw "The 'command' field is required for the help operation."
                }
                Write-ProtocolResponse -Depth 10 -Payload @{
                    id   = $requestId
                    ok   = $true
                    data = Get-CommandHelp -Name $name
                }
            }
            'invoke' {
                Write-ProtocolResponse -Depth $depth -Payload @{
                    id   = $requestId
                    ok   = $true
                    data = Invoke-RequestOperation -Request $request
                }
            }
            default {
                throw "Unknown operation '$operation'. Supported operations: ping, reset, commands, help, invoke."
            }
        }
    } catch {
        $message = Format-ErrorRecordMessage -ErrorRecord $_
        Write-ProtocolResponse -Depth 4 -Payload @{
            id    = $requestId
            ok    = $false
            error = $message
        }
    }
}

if ($script:Runspace) {
    try { $script:Runspace.Close() } catch { }
    try { $script:Runspace.Dispose() } catch { }
}
