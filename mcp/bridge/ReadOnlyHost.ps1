param(
    [string]$ModulePath = (Join-Path $PSScriptRoot '../../XDRInternals/XDRInternals.psd1')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-ArgumentSet {
    param([hashtable]$Arguments, [hashtable]$Limits)

    if ($Arguments.Count -ne $Limits.Count) { return $false }
    foreach ($key in $Arguments.Keys) {
        if (-not $Limits.ContainsKey($key)) { return $false }
        $value = $Arguments[$key]
        if ($value -isnot [int] -and $value -isnot [long]) { return $false }
        if ($value -lt $Limits[$key][0] -or $value -gt $Limits[$key][1]) { return $false }
    }
    return $true
}

function Limit-Text {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -isnot [string]) { throw 'invalid_response' }
    if ($Value.Length -gt 500) { return $Value.Substring(0, 500) }
    return $Value
}

function Limit-Integer {
    param($Value)

    $number = 0
    if ([int]::TryParse([string]$Value, [ref]$number)) { return $number }
    return $null
}

function Limit-Status {
    param($Value)

    if ($Value -is [int] -or $Value -is [long]) { return Limit-Integer $Value }
    return Limit-Text $Value
}

function Limit-Date {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) }
    if ($Value -isnot [string]) { throw 'invalid_response' }
    $date = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Value, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)) {
        return $null
    }
    return $date.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
}

function Send-Response {
    param([string]$Id, [bool]$Ok, $Data, [string]$ErrorCode)

    $response = @{ id = $Id; ok = $Ok }
    if ($Ok) { $response.data = $Data } else { $response.error = $ErrorCode }
    [Console]::Out.WriteLine(($response | ConvertTo-Json -Depth 5 -Compress))
    [Console]::Out.Flush()
}

function Get-UpstreamErrorCode {
    param($Failure)

    if ($Failure.Exception.Message -match '(?<!\d)(401|403)(?!\d)|unauthoriz|forbidden') {
        return 'not_connected'
    }
    return 'upstream_failed'
}

try {
    Import-Module $ModulePath -ErrorAction Stop | Out-Null
} catch {
    [Console]::Error.WriteLine('XDRInternals module could not be loaded.')
    exit 1
}

$connected = $false
if ($env:XDR_MCP_AUTH -in @('browser', 'software-passkey')) {
    try {
        if ($env:XDR_MCP_AUTH -eq 'browser') {
            Connect-XdrByBrowser -PrivateSession -ErrorAction Stop *> $null
        } else {
            $keyFile = $env:XDR_MCP_PASSKEY_FILE
            if (-not [System.IO.Path]::IsPathFullyQualified($keyFile) -or -not (Test-Path -LiteralPath $keyFile -PathType Leaf)) {
                throw 'invalid_passkey_path'
            }
            Connect-XdrBySoftwarePasskey -KeyFilePath $keyFile -ErrorAction Stop *> $null
        }
        $connected = $true
    } catch {
        [Console]::Error.WriteLine('Sign-in failed. Restart the server to try again.')
    }
}

while ($null -ne ($line = [Console]::In.ReadLine())) {
    $id = ''
    try {
        if ($line.Length -gt 8192) { throw 'invalid_request' }
        $request = ConvertFrom-Json -InputObject $line -AsHashtable -ErrorAction Stop
        if ($request -isnot [hashtable] -or $request.Keys.Count -ne 3 -or
            @($request.Keys | Where-Object { $_ -notin @('id', 'operation', 'args') }).Count -gt 0 -or
            $request.id -isnot [string] -or $request.id.Length -gt 64 -or
            $request.operation -isnot [string] -or
            $request.args -isnot [hashtable]) { throw 'invalid_request' }

        $id = $request.id
        $parameters = $request.args
        $limits = switch ($request.operation) {
            'list_incidents' { @{ days = @(1, 30); page = @(1, 10); pageSize = @(1, 50) }; break }
            'get_incident' { @{ incidentId = @(1, [int]::MaxValue) }; break }
            'list_incident_alerts' { @{ incidentId = @(1, [int]::MaxValue); page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_alerts' { @{ days = @(1, 30); page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_devices' { @{ days = @(1, 30); page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_identities' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_pending_actions' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_action_history' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_cloud_policies' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'get_device' { $null; break }
            'get_identity' { $null; break }
            default { throw 'operation_not_allowed' }
        }
        if ($request.operation -eq 'get_device') {
            if ($parameters.Count -ne 1 -or $parameters.deviceId -isnot [string] -or
                $parameters.deviceId -cnotmatch '^[0-9a-fA-F]{40}$') { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'get_identity') {
            if ($parameters.Count -ne 1 -or -not (
                    ($parameters.upn -is [string] -and $parameters.upn -cmatch '^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,189}$') -or
                    ($parameters.objectId -is [string] -and $parameters.objectId -cmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')
                )) { throw 'invalid_arguments' }
        } elseif (-not (Test-ArgumentSet -Arguments $parameters -Limits $limits)) { throw 'invalid_arguments' }
        if (-not $connected) { throw 'not_connected' }

        $data = switch ($request.operation) {
            'list_incidents' {
                try {
                    $items = @(Get-XdrIncident -LookBackInDays $parameters.days -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField TopRisk -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        @{ incidentId = Limit-Integer $_.IncidentId; title = Limit-Text $_.Title; severity = Limit-Text $_.SeverityName; status = Limit-Status $_.Status; lastUpdated = Limit-Date $_.LastUpdateTime; alertCount = Limit-Integer $_.AlertCount }
                    })
                break
            }
            'get_incident' {
                try { $item = Get-XdrIncident -IncidentId $parameters.incidentId -ErrorAction Stop } catch { throw (Get-UpstreamErrorCode $_) }
                if ($null -eq $item) { throw 'not_found' }
                if ($item -is [array] -or (Limit-Integer $item.IncidentId) -ne $parameters.incidentId) { throw 'invalid_response' }
                @{ incidentId = Limit-Integer $item.IncidentId; title = Limit-Text $item.Title; severity = Limit-Text $item.SeverityName; status = Limit-Status $item.Status; created = Limit-Date $item.CreatedTime; lastUpdated = Limit-Date $item.LastUpdateTime; alertCount = Limit-Integer $item.AlertCount }
                break
            }
            'list_incident_alerts' {
                try {
                    $items = @(Get-XdrIncidentAssociatedAlert -IncidentId $parameters.incidentId -PageIndex $parameters.page -PageSize $parameters.pageSize -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        @{ alertId = Limit-Text $_.alertId; title = Limit-Text $_.alertDisplayName; severity = Limit-Text $_.severity; status = Limit-Text $_.status; incidentId = $parameters.incidentId; generated = Limit-Date $_.timeGenerated }
                    })
                break
            }
            'list_alerts' {
                try {
                    $items = @(Get-XdrAlert -DaysAgo $parameters.days -PageNumber $parameters.page -PageSize $parameters.pageSize -Order desc -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        @{ alertId = Limit-Text $_.alertId; title = Limit-Text $_.alertDisplayName; severity = Limit-Text $_.severity; status = Limit-Text $_.status; incidentId = Limit-Integer $_.incidentId; generated = Limit-Date $_.timeGenerated }
                    })
                break
            }
            'list_devices' {
                try {
                    $items = @(Get-XdrEndpointDevice -LookingBackInDays $parameters.days -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField riskscore -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        $machineId = @($_.MachineId, $_.SenseMachineId, $_.id) | Where-Object { $_ -is [string] -and $_ -cmatch '^[0-9a-fA-F]{40}$' } | Select-Object -First 1
                        @{ deviceId = Limit-Text $machineId; name = Limit-Text $_.ComputerDnsName; risk = Limit-Status $_.RiskScore; health = Limit-Text $_.HealthStatus; lastSeen = Limit-Date $_.LastSeen }
                    })
                break
            }
            'list_identities' {
                try {
                    $items = @(Get-XdrIdentityIdentity -PageSize $parameters.pageSize -Skip (($parameters.page - 1) * $parameters.pageSize) -SortByField RepresentableName -SortDirection Asc -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        @{ name = Limit-Text $_.representableName; upn = Limit-Text $_.userPrincipalName; domain = Limit-Text $_.accountDomain; sid = Limit-Text $_.ids.sid; objectId = Limit-Text $_.ids.aad }
                    })
                break
            }
            'list_pending_actions' {
                try {
                    $items = @(Get-XdrActionsCenterPending -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField ActionUpdateTime -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        @{ approvalId = Limit-Text $_.bulkId; investigationId = Limit-Integer $_.investigationId; actionType = Limit-Text $_.actionType; asset = Limit-Text $_.computerName; status = Limit-Text $_.actionStatus; updated = Limit-Date $_.eventTime }
                    })
                break
            }
            'list_action_history' {
                try {
                    $items = @(Get-XdrActionsCenterHistory -Months 1 -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField ActionUpdateTime -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        @{ approvalId = Limit-Text $_.bulkId; investigationId = Limit-Integer $_.investigationId; actionType = Limit-Text $_.actionType; asset = Limit-Text $_.computerName; status = Limit-Text $_.actionStatus; updated = Limit-Date $_.eventTime }
                    })
                break
            }
            'list_cloud_policies' {
                try {
                    $items = @(Get-XdrCloudAppsPolicy -Limit $parameters.pageSize -Skip (($parameters.page - 1) * $parameters.pageSize) -SortField severity -SortDirection desc -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        @{ policyId = Limit-Text $_._id; name = Limit-Text $_.name; severity = Limit-Status $_.severity }
                    })
                break
            }
            'get_device' {
                try { $item = Get-XdrEndpointDevice -DeviceId $parameters.deviceId -ErrorAction Stop } catch { throw (Get-UpstreamErrorCode $_) }
                if ($null -eq $item) { throw 'not_found' }
                if ($item -is [array] -or $item.MachineId -ne $parameters.deviceId) { throw 'invalid_response' }
                @{ deviceId = Limit-Text $item.MachineId; name = Limit-Text $item.ComputerDnsName; risk = Limit-Status $item.RiskScore; health = Limit-Text $item.HealthStatus; lastSeen = Limit-Date $item.LastSeen }
                break
            }
            'get_identity' {
                try {
                    if ($parameters.ContainsKey('objectId')) {
                        $item = Get-XdrIdentityUser -AadId $parameters.objectId -ResolveOnly -ErrorAction Stop
                    } else {
                        $item = Get-XdrIdentityUser -Upn $parameters.upn -ResolveOnly -ErrorAction Stop
                    }
                } catch { throw (Get-UpstreamErrorCode $_) }
                if ($null -eq $item) { throw 'not_found' }
                if ($item -is [array]) { throw 'invalid_response' }
                if ($parameters.ContainsKey('objectId') -and $item.ids.aad -ne $parameters.objectId) { throw 'invalid_response' }
                if ($parameters.ContainsKey('upn') -and $item.userPrincipalName -and $item.userPrincipalName -ne $parameters.upn) { throw 'invalid_response' }
                @{ upn = Limit-Text $item.userPrincipalName; name = Limit-Text $item.displayName; objectId = Limit-Text $item.ids.aad; firstSeen = Limit-Date $item.firstSeen; lastSeen = Limit-Date $item.lastSeen }
                break
            }
        }
        Send-Response -Id $id -Ok $true -Data $data
    } catch {
        $errorCode = if ($_.Exception.Message -in @('invalid_request', 'invalid_arguments', 'operation_not_allowed', 'not_connected', 'not_found', 'invalid_response', 'upstream_failed')) { $_.Exception.Message } else { 'operation_failed' }
        if ($errorCode -eq 'not_connected') {
            $connected = $false
            try { Clear-XdrCache *> $null } catch { $null = $_ }
        }
        Send-Response -Id $id -Ok $false -ErrorCode $errorCode
    }
}