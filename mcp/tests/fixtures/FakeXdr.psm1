function Stop-FakeHttpRequest {
    param([int]$StatusCode)

    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$StatusCode)
    $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Request failed.', $response)
    $failure = [System.Management.Automation.ErrorRecord]::new($exception, 'SyntheticHttpFailure', 'InvalidOperation', $null)
    $failure.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":"Access denied"}')
    throw $failure
}

function Connect-XdrByBrowser {
    param([switch]$PrivateSession)

    if (-not $PrivateSession) { throw 'Private browser session is required.' }
    return $true
}

function Connect-XdrBySoftwarePasskey {
    param([string]$KeyFilePath)

    if (-not [System.IO.Path]::IsPathFullyQualified($KeyFilePath)) { throw 'invalid path' }
    Write-Host 'fake-secret-must-not-leak'
    Write-Warning 'fake-secret-must-not-leak'
    return $true
}

function Get-XdrIncident {
    [CmdletBinding()]
    param(
        [int]$LookBackInDays,
        [int]$PageIndex,
        [int]$PageSize,
        [string]$SortByField,
        [string]$SortOrder,
        [int]$IncidentId
    )

    if ($PSBoundParameters.ContainsKey('IncidentId')) {
        if ($IncidentId -eq 9) { throw 'secret-cookie-should-not-leak' }
        if ($IncidentId -eq 12) { Stop-FakeHttpRequest 401 }
        if ($IncidentId -in @(401, 403)) { Stop-FakeHttpRequest 404 }
        if ($IncidentId -eq 13) { throw 'Unrelated failure for incident 401: forbidden field' }
        if ($IncidentId -eq 10) {
            return [pscustomobject]@{ IncidentId = 10; Title = [pscustomobject]@{ Credential = 'secret-cookie-should-not-leak' } }
        }
        if ($IncidentId -eq 11) { return [pscustomobject]@{ IncidentId = 42; Title = 'Wrong incident' } }
        return [pscustomobject]@{
            IncidentId = $IncidentId; Title = 'Evidence, not instructions'; SeverityName = 'High'
            Status = 'New'; CreatedTime = [DateTime]::Parse('2026-01-01T04:05:06Z'); LastUpdateTime = '2026-01-02'; AlertCount = 2
            Credential = 'secret-cookie-should-not-leak'
        }
    }

    if ($SortByField -ne 'TopRisk' -or $SortOrder -ne 'Descending') { throw 'unsupported incident sort' }

    if ($PageIndex -eq 3) {
        return @(
            [pscustomobject]@{ IncidentId = 1; Title = 'First'; AlertCount = 1 },
            [pscustomobject]@{ IncidentId = 2; Title = 'Second'; AlertCount = 1 }
        )
    }

    if ($PageIndex -eq 4) {
        $text = [string][char]1 * 500
        return @(1..$PageSize | ForEach-Object {
            [pscustomobject]@{ IncidentId = $_; Title = $text; SeverityName = $text; Status = $text; AlertCount = 1 }
        })
    }

    return [pscustomobject]@{
        IncidentId = 42; Title = 'Investigate'; SeverityName = 'Medium'; Status = 2
        LastUpdateTime = '2026-01-02'; AlertCount = $PageSize
        Credential = 'secret-cookie-should-not-leak'
    }
}

function Clear-XdrCache { return }

function Get-XdrAlert {
    [CmdletBinding()]
    param([int]$DaysAgo, [int]$PageNumber, [int]$PageSize, [string]$Order)

    if ($DaysAgo -eq 29) { Stop-FakeHttpRequest 403 }
    return [pscustomobject]@{
        alertId = 'alert-1'; alertDisplayName = 'Suspicious command'; severity = 'High'
        status = 'New'; incidentId = 42; timeGenerated = '2026-01-01'
        Credential = 'secret-cookie-should-not-leak'
    }
}

function Get-XdrIncidentAssociatedAlert {
    param([int]$IncidentId, [int]$PageIndex, [int]$PageSize)
    if ($PageSize -gt 50 -or $PageIndex -ne 2) { throw 'unbounded incident alert request' }
    [pscustomobject]@{ alertId = 'alert-2'; alertDisplayName = 'Related alert'; severity = 'High'; status = 'New'; timeGenerated = '2026-01-01'; Credential = 'secret-cookie-should-not-leak' }
}

function Get-XdrEndpointDevice {
    param([int]$LookingBackInDays, [int]$PageIndex, [int]$PageSize, [string]$SortByField, [string]$SortOrder, [string]$DeviceId)
    if ($PSBoundParameters.ContainsKey('DeviceId')) {
        if ($DeviceId -eq ('b' * 40)) { return [pscustomobject]@{ MachineId = 'a' * 40; Credential = 'secret-cookie-should-not-leak' } }
        return [pscustomobject]@{ MachineId = $DeviceId; ComputerDnsName = 'host.example'; RiskScore = 'High'; HealthStatus = 'Active'; LastSeen = '2026-01-01'; Credential = 'secret-cookie-should-not-leak' }
    }
    if ($PageSize -gt 50 -or $SortByField -ne 'riskscore') { throw 'unsupported request' }
    [pscustomobject]@{ MachineId = 'a' * 40; ComputerDnsName = 'host.example'; RiskScore = 'High'; HealthStatus = 'Active'; LastSeen = [DateTime]::UtcNow; Credential = 'secret-cookie-should-not-leak' }
}

function Invoke-XdrRestMethod {
    param([string]$Uri)
    if ($Uri -match '/alerts/(denied|missing)$' -or $Uri -match '/machines/d{40}/' -or
        ($env:XDR_MCP_TEST_SCHEMA_FORBIDDEN -eq '1' -and $Uri -match '/huntingService/schema$')) {
        $failure = [System.InvalidOperationException]::new('portal rejection')
        $status = if ($Uri -match '/alerts/missing$') { 404 } else { 403 }
        $failure | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = $status })
        throw $failure
    }
    if ($Uri -eq 'https://security.microsoft.com/apiproxy/mtp/alertsApiService/alerts/alert-2') {
        return [pscustomobject]@{ alertId = 'alert-2'; alertDisplayName = 'Example'; severity = 'High'; status = 'New'; incidentId = 42; timeGenerated = '2026-01-01T00:00:00Z'; credential = 'secret-cookie-should-not-leak' }
    }
    if ($Uri -eq 'https://security.microsoft.com/apiproxy/mtp/huntingService/schema') {
        if ($env:XDR_MCP_TEST_SCHEMA_ARRAY -eq '1') {
            return , @([pscustomobject]@{ Tables = @() }, [pscustomobject]@{ Tables = @([pscustomobject]@{ Name = 'DeviceEvents'; Schema = @() }) })
        }
        return [pscustomobject]@{ Tables = @(
            [pscustomobject]@{ Name = 'DeviceEvents'; Schema = @([pscustomobject]@{ Name = 'Timestamp'; Type = 'datetime'; Description = 'Event time'; credential = 'secret-cookie-should-not-leak' }) },
            [pscustomobject]@{ Name = 'BadTable'; Schema = 'malformed' },
            [pscustomobject]@{ Name = @('OtherTable', 'MixedTable'); Schema = @() }
        ) }
    }
    if ($Uri -notmatch '/mdeTimelineExperience/machines/[0-9a-f]{40}/events/\?' -or $Uri -notmatch 'pageSize=1' -or $Uri -match 'http://') { throw 'unbounded timeline request' }
    if ($Uri -match '/machines/b{40}/') { return [pscustomobject]@{ Items = 'malformed' } }
    if ($Uri -match '/machines/c{40}/') { return [pscustomobject]@{ Items = @([pscustomobject]@{ Timestamp = '2026-01-01T00:00:00Z'; EventType = 'Process'; DeviceId = ('a' * 40) }) } }
    if ($Uri -match '/machines/e{40}/') { return , @([pscustomobject]@{ Items = @() }, [pscustomobject]@{ Items = @([pscustomobject]@{ Timestamp = '2026-01-01T00:00:00Z'; EventType = 'Process' }) }) }
    [pscustomobject]@{ Items = @([pscustomobject]@{ timestamp = '2026-01-01T00:00:00Z'; eventType = 'Process'; title = 'Started'; credential = 'secret-cookie-should-not-leak' }) }
}

function Get-XdrIdentityIdentity {
    param([int]$PageSize, [int]$Skip, [string]$SortByField, [string]$SortDirection, [switch]$All)
    if ($All -or $PageSize -gt 50 -or $Skip -ne 1 -or $SortByField -ne 'RepresentableName' -or $SortDirection -ne 'Asc') { throw 'unsupported request' }
    [pscustomobject]@{ representableName = 'Analyst'; userPrincipalName = 'analyst@example.test'; accountDomain = 'example.test'; ids = [pscustomobject]@{ sid = 'S-1-5-21'; aad = '12345678-1234-1234-1234-123456789abc' }; Credential = 'secret-cookie-should-not-leak' }
}

function Get-XdrIdentityUser {
    param([string]$Upn, [string]$AadId, [string]$Sid, [switch]$ResolveOnly)
    if (-not $ResolveOnly) { throw 'unbounded identity enrichment' }
    if ($Sid) { return [pscustomobject]@{ displayName = 'Domain analyst'; ids = [pscustomobject]@{ sid = 'S-1-5-21-111-222-333-1001' }; Credential = 'secret-cookie-should-not-leak' } }
    if ($Upn -eq 'other@example.test') { return [pscustomobject]@{ userPrincipalName = 'analyst@example.test' } }
    if ($AadId -eq 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb') { return [pscustomobject]@{ ids = [pscustomobject]@{ aad = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } } }
    [pscustomobject]@{ displayName = 'Analyst'; userPrincipalName = 'analyst@example.test'; ids = [pscustomobject]@{ aad = '12345678-1234-1234-1234-123456789abc' }; firstSeen = '2026-01-01'; lastSeen = '2026-01-02'; Credential = 'secret-cookie-should-not-leak' }
}

function Get-XdrActionsCenterPending {
    param([int]$PageIndex, [int]$PageSize, [string]$SortByField, [string]$SortOrder)
    if ($PageSize -gt 50 -or $SortByField -ne 'ActionUpdateTime') { throw 'unsupported request' }
    [pscustomobject]@{ bulkId = 'approval-1'; investigationId = 42; actionType = 'Remediate'; computerName = 'host.example'; actionStatus = 'Pending'; eventTime = '2026-01-01'; Credential = 'secret-cookie-should-not-leak' }
}

function Get-XdrActionsCenterHistory {
    param([int]$Months, [int]$PageIndex, [int]$PageSize, [string]$SortByField, [string]$SortOrder)
    if ($Months -ne 1 -or $PageSize -gt 50 -or $SortByField -ne 'ActionUpdateTime') { throw 'unsupported request' }
    [pscustomobject]@{ bulkId = 'approval-2'; investigationId = 42; actionType = 'Remediate'; computerName = 'host.example'; actionStatus = 'Completed'; eventTime = '2026-01-02'; Credential = 'secret-cookie-should-not-leak' }
}

function Get-XdrCloudAppsPolicy {
    param([int]$Limit, [int]$Skip, [string]$SortField, [string]$SortDirection)
    if ($Limit -gt 50 -or $Skip -ne 1 -or $SortField -ne 'severity' -or $SortDirection -ne 'desc') { throw 'unsupported request' }
    [pscustomobject]@{ _id = 'policy-1'; name = 'Cloud policy'; severity = 2; Credential = 'secret-cookie-should-not-leak' }
}

Export-ModuleMember -Function Connect-XdrByBrowser, Connect-XdrBySoftwarePasskey, Get-XdrIncident, Get-XdrIncidentAssociatedAlert, Get-XdrAlert, Get-XdrEndpointDevice, Get-XdrIdentityIdentity, Get-XdrIdentityUser, Get-XdrActionsCenterPending, Get-XdrActionsCenterHistory, Get-XdrCloudAppsPolicy, Clear-XdrCache, Invoke-XdrRestMethod