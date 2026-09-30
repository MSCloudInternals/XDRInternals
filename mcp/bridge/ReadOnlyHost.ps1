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
    $json = $response | ConvertTo-Json -Depth 5 -Compress
    if ([System.Text.Encoding]::UTF8.GetByteCount($json + [Environment]::NewLine) -gt 256 * 1024) {
        $json = @{ id = $Id; ok = $false; error = 'invalid_response' } | ConvertTo-Json -Compress
    }
    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}

function Get-UpstreamErrorCode {
    param($Failure)

    $exception = $Failure.Exception
    while ($null -ne $exception) {
        if ($null -ne $exception.Response -and $null -ne $exception.Response.StatusCode) {
            $statusCode = [int]$exception.Response.StatusCode
            if ($statusCode -in @(401, 403)) { return 'not_connected' }
            if ($statusCode -eq 404) { return 'not_found' }
            return 'upstream_failed'
        }
        $exception = $exception.InnerException
    }
    if ($Failure.FullyQualifiedErrorId -like 'XdrIdentityUserNotFound*') { return 'not_found' }
    return 'upstream_failed'
}

function Invoke-BoundedPortalHunt {
    param([string]$Query, [int]$PageSize)

    $end = [DateTime]::UtcNow
    $body = @{
        QueryText        = $Query
        EncodedQueryText = $Query
        StartTime        = $end.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        EndTime          = $end.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        MaxRecordCount   = $PageSize
    } | ConvertTo-Json -Compress
    try { $result = Invoke-XdrRestMethod -Uri 'https://security.microsoft.com/apiproxy/mtp/huntingService/queryExecutor' -Method Post -Body $body -ErrorAction Stop } catch { throw (Get-UpstreamErrorCode $_) }
    if ($result -isnot [pscustomobject] -or $result.Results -isnot [array] -or $result.Results.Count -gt $PageSize) { throw 'invalid_response' }
    return , @($result.Results)
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
            'get_alert' { $null; break }
            'list_devices' { @{ days = @(1, 30); page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_identities' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_pending_actions' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_action_history' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'list_cloud_policies' { @{ page = @(1, 10); pageSize = @(1, 50) }; break }
            'get_device' { $null; break }
            'list_device_timeline' { $null; break }
            'list_device_alert_evidence' { $null; break }
            'list_file_events' { $null; break }
            'list_network_observations' { $null; break }
            'list_user_alert_evidence' { $null; break }
            'list_user_device_logons' { $null; break }
            'list_user_timeline' { $null; break }
            'hunt_recent' { $null; break }
            'get_hunting_table_schema' { $null; break }
            'get_identity' { $null; break }
            default { throw 'operation_not_allowed' }
        }
        if ($request.operation -eq 'get_alert') {
            if ($parameters.Count -ne 1 -or $parameters.alertId -isnot [string] -or
                $parameters.alertId -cnotmatch '^[A-Za-z0-9._:-]{1,160}$') { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'get_hunting_table_schema') {
            if ($parameters.Count -ne 1 -or $parameters.table -isnot [string] -or
                $parameters.table -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,79}$') { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'list_device_timeline') {
            if ($parameters.Count -ne 3 -or $parameters.deviceId -isnot [string] -or
                $parameters.deviceId -cnotmatch '^[0-9a-fA-F]{40}$' -or
                -not (Test-ArgumentSet -Arguments @{ minutes = $parameters.minutes; pageSize = $parameters.pageSize } -Limits @{ minutes = @(1, 60); pageSize = @(1, 50) })) {
                throw 'invalid_arguments'
            }
        } elseif ($request.operation -eq 'list_device_alert_evidence') {
            if ($parameters.Count -ne 2 -or $parameters.deviceId -isnot [string] -or
                $parameters.deviceId -cnotmatch '^[0-9a-fA-F]{40}$' -or
                -not (Test-ArgumentSet -Arguments @{ pageSize = $parameters.pageSize } -Limits @{ pageSize = @(1, 50) })) {
                throw 'invalid_arguments'
            }
        } elseif ($request.operation -eq 'list_file_events') {
            if ($parameters.Count -ne 2 -or $parameters.sha256 -isnot [string] -or
                $parameters.sha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
                -not (Test-ArgumentSet -Arguments @{ pageSize = $parameters.pageSize } -Limits @{ pageSize = @(1, 50) })) { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'list_network_observations') {
            if ($parameters.Count -ne 3 -or $parameters.kind -cnotin @('ip', 'domain') -or
                $parameters.value -isnot [string] -or
                -not (Test-ArgumentSet -Arguments @{ pageSize = $parameters.pageSize } -Limits @{ pageSize = @(1, 50) })) { throw 'invalid_arguments' }
            if ($parameters.kind -eq 'ip') {
                $parsedIp = $null
                if ($parameters.value -cnotmatch '^[0-9a-fA-F:.]{3,45}$' -or
                    -not [System.Net.IPAddress]::TryParse($parameters.value, [ref]$parsedIp)) { throw 'invalid_arguments' }
            } elseif ($parameters.value -cnotmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$') {
                throw 'invalid_arguments'
            }
        } elseif ($request.operation -in @('list_user_alert_evidence', 'list_user_device_logons')) {
            if ($parameters.Count -ne 2 -or $parameters.upn -isnot [string] -or
                $parameters.upn -cnotmatch '^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,189}$' -or
                -not (Test-ArgumentSet -Arguments @{ pageSize = $parameters.pageSize } -Limits @{ pageSize = @(1, 50) })) { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'list_user_timeline') {
            if ($parameters.Count -ne 3 -or $parameters.upn -isnot [string] -or
                $parameters.upn -cnotmatch '^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,189}$' -or
                -not (Test-ArgumentSet -Arguments @{ minutes = $parameters.minutes; pageSize = $parameters.pageSize } -Limits @{ minutes = @(1, 60); pageSize = @(1, 50) })) { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'hunt_recent') {
            if ($parameters.Count -ne 2 -or $parameters.table -isnot [string] -or
                $parameters.table -cnotin @('DeviceEvents', 'DeviceFileEvents', 'DeviceNetworkEvents', 'AlertEvidence', 'IdentityLogonEvents') -or
                -not (Test-ArgumentSet -Arguments @{ pageSize = $parameters.pageSize } -Limits @{ pageSize = @(1, 20) })) { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'get_device') {
            if ($parameters.Count -ne 1 -or $parameters.deviceId -isnot [string] -or
                $parameters.deviceId -cnotmatch '^[0-9a-fA-F]{40}$') { throw 'invalid_arguments' }
        } elseif ($request.operation -eq 'get_identity') {
            if ($parameters.Count -ne 1 -or -not (
                    ($parameters.upn -is [string] -and $parameters.upn -cmatch '^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,189}$') -or
                    ($parameters.objectId -is [string] -and $parameters.objectId -cmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') -or
                    ($parameters.sid -is [string] -and $parameters.sid -cmatch '^S-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}$')
                )) { throw 'invalid_arguments' }
        } elseif (-not (Test-ArgumentSet -Arguments $parameters -Limits $limits)) { throw 'invalid_arguments' }
        if (-not $connected) { throw 'not_connected' }

        $data = switch ($request.operation) {
            'list_incidents' {
                try {
                    $items = @(Get-XdrIncident -LookBackInDays $parameters.days -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField TopRisk -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        if ((Limit-Integer $_.IncidentId) -le 0) { throw 'invalid_response' }
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
                        if ($_.alertId -isnot [string] -or [string]::IsNullOrWhiteSpace($_.alertId)) { throw 'invalid_response' }
                        @{ alertId = Limit-Text $_.alertId; title = Limit-Text $_.alertDisplayName; severity = Limit-Text $_.severity; status = Limit-Text $_.status; incidentId = $parameters.incidentId; generated = Limit-Date $_.timeGenerated }
                    })
                break
            }
            'list_alerts' {
                try {
                    $items = @(Get-XdrAlert -DaysAgo $parameters.days -PageNumber $parameters.page -PageSize $parameters.pageSize -Order desc -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        if ($_.alertId -isnot [string] -or [string]::IsNullOrWhiteSpace($_.alertId)) { throw 'invalid_response' }
                        @{ alertId = Limit-Text $_.alertId; title = Limit-Text $_.alertDisplayName; severity = Limit-Text $_.severity; status = Limit-Text $_.status; incidentId = Limit-Integer $_.incidentId; generated = Limit-Date $_.timeGenerated }
                    })
                break
            }
            'get_alert' {
                $uri = "https://security.microsoft.com/apiproxy/mtp/alertsApiService/alerts/$([uri]::EscapeDataString($parameters.alertId))"
                try { $item = Invoke-XdrRestMethod -Uri $uri -ErrorAction Stop } catch { throw (Get-UpstreamErrorCode $_) }
                if ($null -eq $item) { throw 'not_found' }
                if ($item -is [array] -or $item.alertId -cne $parameters.alertId) { throw 'invalid_response' }
                @{ alertId = Limit-Text $item.alertId; title = Limit-Text $item.alertDisplayName; severity = Limit-Text $item.severity; status = Limit-Text $item.status; incidentId = Limit-Integer $item.incidentId; generated = Limit-Date $item.timeGenerated }
                break
            }
            'list_devices' {
                try {
                    $items = @(Get-XdrEndpointDevice -LookingBackInDays $parameters.days -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField riskscore -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        $machineId = @($_.MachineId, $_.SenseMachineId, $_.id) | Where-Object { $_ -is [string] -and $_ -cmatch '^[0-9a-fA-F]{40}$' } | Select-Object -First 1
                        if ($null -eq $machineId) { throw 'invalid_response' }
                        @{ deviceId = Limit-Text $machineId; name = Limit-Text $_.ComputerDnsName; risk = Limit-Status $_.RiskScore; health = Limit-Text $_.HealthStatus; lastSeen = Limit-Date $_.LastSeen }
                    })
                break
            }
            'list_identities' {
                try {
                    $items = @(Get-XdrIdentityIdentity -PageSize $parameters.pageSize -Skip (($parameters.page - 1) * $parameters.pageSize) -SortByField RepresentableName -SortDirection Asc -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        if ($_.representableName -isnot [string] -and $_.userPrincipalName -isnot [string] -and
                            $_.ids.sid -isnot [string] -and $_.ids.aad -isnot [string]) { throw 'invalid_response' }
                        @{ name = Limit-Text $_.representableName; upn = Limit-Text $_.userPrincipalName; domain = Limit-Text $_.accountDomain; sid = Limit-Text $_.ids.sid; objectId = Limit-Text $_.ids.aad }
                    })
                break
            }
            'list_pending_actions' {
                try {
                    $items = @(Get-XdrActionsCenterPending -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField ActionUpdateTime -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        if ($_.bulkId -isnot [string] -and $_.actionType -isnot [string]) { throw 'invalid_response' }
                        @{ approvalId = Limit-Text $_.bulkId; investigationId = Limit-Integer $_.investigationId; actionType = Limit-Text $_.actionType; asset = Limit-Text $_.computerName; status = Limit-Text $_.actionStatus; updated = Limit-Date $_.eventTime }
                    })
                break
            }
            'list_action_history' {
                try {
                    $items = @(Get-XdrActionsCenterHistory -Months 1 -PageIndex $parameters.page -PageSize $parameters.pageSize -SortByField ActionUpdateTime -SortOrder Descending -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        if ($_.bulkId -isnot [string] -and $_.actionType -isnot [string]) { throw 'invalid_response' }
                        @{ approvalId = Limit-Text $_.bulkId; investigationId = Limit-Integer $_.investigationId; actionType = Limit-Text $_.actionType; asset = Limit-Text $_.computerName; status = Limit-Text $_.actionStatus; updated = Limit-Date $_.eventTime }
                    })
                break
            }
            'list_cloud_policies' {
                try {
                    $items = @(Get-XdrCloudAppsPolicy -Limit $parameters.pageSize -Skip (($parameters.page - 1) * $parameters.pageSize) -SortField severity -SortDirection desc -ErrorAction Stop)
                } catch { throw (Get-UpstreamErrorCode $_) }
                , @($items | Select-Object -First $parameters.pageSize | ForEach-Object {
                        if ($_._id -isnot [string] -and $_.name -isnot [string]) { throw 'invalid_response' }
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
            'list_device_timeline' {
                $end = [DateTime]::UtcNow
                $start = $end.AddMinutes(-$parameters.minutes)
                $query = @(
                    'generateIdentityEvents=false', 'includeIdentityEvents=false', 'supportMdiOnlyEvents=false',
                    "fromDate=$([uri]::EscapeDataString($start.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))",
                    "toDate=$([uri]::EscapeDataString($end.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))",
                    "correlationId=$([guid]::NewGuid())", 'doNotUseCache=false', 'forceUseCache=false',
                    "pageSize=$($parameters.pageSize)", 'includeSentinelEvents=false'
                ) -join '&'
                $uri = "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/$($parameters.deviceId)/events/?$query"
                try { $result = Invoke-XdrRestMethod -Uri $uri -ErrorAction Stop } catch { throw (Get-UpstreamErrorCode $_) }
                if ($result -isnot [pscustomobject] -or $result.Items -isnot [array]) { throw 'invalid_response' }
                $items = @($result.Items)
                if ($items.Count -gt $parameters.pageSize) { throw 'invalid_response' }
                , @($items | ForEach-Object {
                        if ($_ -isnot [pscustomobject]) { throw 'invalid_response' }
                        foreach ($field in @('MachineId', 'SenseMachineId', 'DeviceId')) {
                            if ($null -ne $_.$field -and $_.$field -ine $parameters.deviceId) { throw 'invalid_response' }
                        }
                        $eventType = if ($_.ActionType) { $_.ActionType } elseif ($_.Type) { $_.Type } else { $_.EventType }
                        $eventTime = if ($null -ne $_.Timestamp) { $_.Timestamp } elseif ($null -ne $_.ActionTimeIsoString) { $_.ActionTimeIsoString } else { $_.ActionTime }
                        if ($eventType -isnot [string] -or [string]::IsNullOrWhiteSpace($eventType) -or $null -eq $eventTime) { throw 'invalid_response' }
                        $timestamp = Limit-Date $eventTime
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        @{ timestamp = $timestamp; eventType = Limit-Text $eventType; title = Limit-Text $_.Title; deviceId = $parameters.deviceId }
                    })
                break
            }
            'list_device_alert_evidence' {
                $query = 'AlertEvidence | where Timestamp > ago(1d) and DeviceId == "{0}" | project Timestamp, DeviceId, AlertId, Title, Severity | take {1}' -f $parameters.deviceId.ToLowerInvariant(), $parameters.pageSize
                $rows = Invoke-BoundedPortalHunt -Query $query -PageSize $parameters.pageSize
                , @($rows | ForEach-Object {
                        if ($_ -isnot [pscustomobject] -or $_.DeviceId -ine $parameters.deviceId -or
                            $_.AlertId -isnot [string] -or [string]::IsNullOrWhiteSpace($_.AlertId)) { throw 'invalid_response' }
                        $timestamp = Limit-Date $_.Timestamp
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        @{ timestamp = $timestamp; deviceId = $parameters.deviceId; alertId = Limit-Text $_.AlertId; title = Limit-Text $_.Title; severity = Limit-Text $_.Severity }
                    })
                break
            }
            'list_file_events' {
                $query = 'DeviceFileEvents | where Timestamp > ago(1d) and SHA256 =~ "{0}" | project Timestamp, DeviceId, FileName, SHA256 | take {1}' -f $parameters.sha256, $parameters.pageSize
                $rows = Invoke-BoundedPortalHunt -Query $query -PageSize $parameters.pageSize
                , @($rows | ForEach-Object {
                        if ($_ -isnot [pscustomobject] -or $_.SHA256 -ine $parameters.sha256) { throw 'invalid_response' }
                        $timestamp = Limit-Date $_.Timestamp
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        @{ timestamp = $timestamp; deviceId = Limit-Text $_.DeviceId; fileName = Limit-Text $_.FileName; sha256 = $parameters.sha256 }
                    })
                break
            }
            'list_network_observations' {
                if ($parameters.kind -eq 'ip') {
                    $predicate = 'ipv6_is_match(RemoteIP, "{0}")' -f $parsedIp.ToString()
                } else {
                    $predicate = 'RemoteUrl has "{0}" | extend UrlHost = tostring(parse_url(iff(RemoteUrl matches regex @"^[A-Za-z][A-Za-z0-9+.-]*://", RemoteUrl, strcat("https://", RemoteUrl))).Host) | where UrlHost =~ "{0}" or UrlHost endswith ".{0}"' -f $parameters.value
                }
                $query = 'DeviceNetworkEvents | where Timestamp > ago(1d) and {0} | project Timestamp, DeviceId, RemoteIP, RemoteUrl | take {1}' -f $predicate, $parameters.pageSize
                $rows = Invoke-BoundedPortalHunt -Query $query -PageSize $parameters.pageSize
                , @($rows | ForEach-Object {
                        if ($_ -isnot [pscustomobject]) { throw 'invalid_response' }
                        if ($parameters.kind -eq 'ip') {
                            $remoteIp = $null
                            if ($_.RemoteIP -isnot [string] -or -not [System.Net.IPAddress]::TryParse($_.RemoteIP, [ref]$remoteIp)) { throw 'invalid_response' }
                            $normalizedRemoteIp = if ($remoteIp.IsIPv4MappedToIPv6) { $remoteIp.MapToIPv4() } else { $remoteIp }
                            $normalizedTargetIp = if ($parsedIp.IsIPv4MappedToIPv6) { $parsedIp.MapToIPv4() } else { $parsedIp }
                            if (-not $normalizedRemoteIp.Equals($normalizedTargetIp)) { throw 'invalid_response' }
                        } else {
                            if ($_.RemoteUrl -isnot [string]) { throw 'invalid_response' }
                            $remoteUrl = $null
                            $urlToParse = if ($_.RemoteUrl -cmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $_.RemoteUrl } else { "https://$($_.RemoteUrl)" }
                            if (-not [uri]::TryCreate($urlToParse, [UriKind]::Absolute, [ref]$remoteUrl)) { throw 'invalid_response' }
                            if ($remoteUrl.Host -ine $parameters.value -and -not $remoteUrl.Host.EndsWith(".$($parameters.value)", [StringComparison]::OrdinalIgnoreCase)) { throw 'invalid_response' }
                        }
                        $timestamp = Limit-Date $_.Timestamp
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        @{ timestamp = $timestamp; deviceId = Limit-Text $_.DeviceId; remoteIp = Limit-Text $_.RemoteIP; remoteUrl = Limit-Text $_.RemoteUrl }
                    })
                break
            }
            'list_user_alert_evidence' {
                $query = 'AlertEvidence | where Timestamp > ago(1d) and AccountUpn =~ "{0}" | project Timestamp, AccountUpn, DeviceId, AlertId, Title, Severity | take {1}' -f $parameters.upn, $parameters.pageSize
                $rows = Invoke-BoundedPortalHunt -Query $query -PageSize $parameters.pageSize
                , @($rows | ForEach-Object {
                        if ($_ -isnot [pscustomobject] -or $_.AccountUpn -ine $parameters.upn -or
                            $_.AlertId -isnot [string] -or [string]::IsNullOrWhiteSpace($_.AlertId)) { throw 'invalid_response' }
                        $timestamp = Limit-Date $_.Timestamp
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        @{ timestamp = $timestamp; upn = $parameters.upn; deviceId = Limit-Text $_.DeviceId; alertId = Limit-Text $_.AlertId; title = Limit-Text $_.Title; severity = Limit-Text $_.Severity }
                    })
                break
            }
            'list_user_device_logons' {
                $query = 'IdentityLogonEvents | where Timestamp > ago(1d) and AccountUpn =~ "{0}" and isnotempty(DeviceName) | project Timestamp, AccountUpn, DeviceName | take {1}' -f $parameters.upn, $parameters.pageSize
                $rows = Invoke-BoundedPortalHunt -Query $query -PageSize $parameters.pageSize
                , @($rows | ForEach-Object {
                        if ($_ -isnot [pscustomobject] -or $_.AccountUpn -ine $parameters.upn -or
                            $_.DeviceName -isnot [string] -or [string]::IsNullOrWhiteSpace($_.DeviceName)) { throw 'invalid_response' }
                        $timestamp = Limit-Date $_.Timestamp
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        @{ timestamp = $timestamp; upn = $parameters.upn; deviceName = Limit-Text $_.DeviceName }
                    })
                break
            }
            'list_user_timeline' {
                $query = 'IdentityLogonEvents | where Timestamp > ago({0}m) and AccountUpn =~ "{1}" | project Timestamp, AccountUpn, ActionType, DeviceName | take {2}' -f $parameters.minutes, $parameters.upn, $parameters.pageSize
                $rows = Invoke-BoundedPortalHunt -Query $query -PageSize $parameters.pageSize
                , @($rows | ForEach-Object {
                        if ($_ -isnot [pscustomobject] -or $_.AccountUpn -ine $parameters.upn -or
                            $_.ActionType -isnot [string] -or [string]::IsNullOrWhiteSpace($_.ActionType)) { throw 'invalid_response' }
                        $timestamp = Limit-Date $_.Timestamp
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        @{ timestamp = $timestamp; upn = $parameters.upn; eventType = Limit-Text $_.ActionType; deviceName = Limit-Text $_.DeviceName }
                    })
                break
            }
            'hunt_recent' {
                $columns = switch -CaseSensitive ($parameters.table) {
                    'DeviceEvents' { 'Timestamp, DeviceId, ActionType' }
                    'DeviceFileEvents' { 'Timestamp, DeviceId, FileName' }
                    'DeviceNetworkEvents' { 'Timestamp, DeviceId, RemoteUrl' }
                    'AlertEvidence' { 'Timestamp, DeviceId, AlertId, Title' }
                    'IdentityLogonEvents' { 'Timestamp, AccountUpn, DeviceName' }
                }
                $query = '{0} | where Timestamp > ago(1h) | project {1} | take {2}' -f $parameters.table, $columns, $parameters.pageSize
                $rows = Invoke-BoundedPortalHunt -Query $query -PageSize $parameters.pageSize
                , @($rows | ForEach-Object {
                        if ($_ -isnot [pscustomobject]) { throw 'invalid_response' }
                        $row = $_
                        $timestamp = Limit-Date $_.Timestamp
                        if ($null -eq $timestamp) { throw 'invalid_response' }
                        $summary = switch -CaseSensitive ($parameters.table) {
                            'DeviceEvents' { $row.ActionType }
                            'DeviceFileEvents' { $row.FileName }
                            'DeviceNetworkEvents' { $row.RemoteUrl }
                            'AlertEvidence' { $row.Title }
                            'IdentityLogonEvents' { $row.DeviceName }
                        }
                        @{ table = $parameters.table; timestamp = $timestamp; deviceId = Limit-Text $_.DeviceId; summary = Limit-Text $summary; alertId = Limit-Text $_.AlertId; upn = Limit-Text $_.AccountUpn }
                    })
                break
            }
            'get_hunting_table_schema' {
                try { $result = Invoke-XdrRestMethod -Uri 'https://security.microsoft.com/apiproxy/mtp/huntingService/schema' -ErrorAction Stop } catch { throw (Get-UpstreamErrorCode $_) }
                if ($result -isnot [pscustomobject] -or $result.Tables -isnot [array]) { throw 'invalid_response' }
                $tables = @($result.Tables | Where-Object { $_ -is [pscustomobject] -and $_.Name -is [string] -and $_.Name -ceq $parameters.table })
                if ($tables.Count -eq 0) { throw 'not_found' }
                if ($tables.Count -ne 1 -or $tables[0].Schema -isnot [array]) { throw 'invalid_response' }
                $columns = @($tables[0].Schema)
                @{ table = $parameters.table; truncated = $columns.Count -gt 50; columns = @($columns | Select-Object -First 50 | ForEach-Object {
                            if ($_ -isnot [pscustomobject] -or $_.Name -isnot [string] -or
                                $_.Name -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,79}$' -or
                                $_.Type -isnot [string] -or [string]::IsNullOrWhiteSpace($_.Type)) { throw 'invalid_response' }
                            @{ name = Limit-Text $_.Name; type = Limit-Text $_.Type; description = Limit-Text $_.Description }
                        })
                }
                break
            }
            'get_identity' {
                try {
                    if ($parameters.ContainsKey('objectId')) {
                        $item = Get-XdrIdentityUser -AadId $parameters.objectId -ResolveOnly -ErrorAction Stop
                    } elseif ($parameters.ContainsKey('sid')) {
                        $item = Get-XdrIdentityUser -Sid $parameters.sid -ResolveOnly -ErrorAction Stop
                    } else {
                        $item = Get-XdrIdentityUser -Upn $parameters.upn -ResolveOnly -ErrorAction Stop
                    }
                } catch { throw (Get-UpstreamErrorCode $_) }
                if ($null -eq $item) { throw 'not_found' }
                if ($item -is [array]) { throw 'invalid_response' }
                if ($parameters.ContainsKey('objectId') -and $item.ids.aad -ne $parameters.objectId) { throw 'invalid_response' }
                if ($parameters.ContainsKey('sid') -and $item.ids.sid -cne $parameters.sid) { throw 'invalid_response' }
                if ($parameters.ContainsKey('upn') -and $item.userPrincipalName -and $item.userPrincipalName -ne $parameters.upn) { throw 'invalid_response' }
                @{ upn = Limit-Text $item.userPrincipalName; name = Limit-Text $item.displayName; objectId = Limit-Text $item.ids.aad; sid = Limit-Text $item.ids.sid; firstSeen = Limit-Date $item.firstSeen; lastSeen = Limit-Date $item.lastSeen }
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