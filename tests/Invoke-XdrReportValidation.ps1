[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$KeyFilePath,

    [Parameter()]
    [string[]]$Name = @('*'),

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 30,

    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot '../TestResults/Reports.Live.json')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module (Join-Path $PSScriptRoot '../XDRInternals/XDRInternals.psd1') -Force
Connect-XdrBySoftwarePasskey -KeyFilePath $KeyFilePath 6>$null | Out-Null
$definitions = @(Get-XdrReportDefinition -Name $Name)
if ($definitions.Count -eq 0) { throw 'No report operations matched the requested names.' }
$fromDate = [datetime]::UtcNow.Date.AddDays(-$Days)
$toDate = [datetime]::UtcNow
$domainTargets = $null
$results = foreach ($definition in $definitions) {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $downloadPath = $null
    try {
        $parameters = @{ Name = $definition.Name; FromDate = $fromDate; ToDate = $toDate; ErrorAction = 'Stop' }
        if ($definition.RequiredParameters) {
            if ($null -eq $domainTargets) {
                $domains = @(Get-XdrReport -Name 'WebThreat.allDomains' -Force -ErrorAction Stop)
                $domainTargets = @($domains | ForEach-Object {
                    if ($_.id) { $_ } else {
                        foreach ($field in @('value', 'domains', 'data', 'items', 'results', 'currentPage')) { $_.$field | Where-Object id }
                    }
                })
            }
            if ($domainTargets.Count -eq 0) { throw [System.InvalidOperationException]::new('NoDrilldownTarget') }
            $parameters.Parameters = @{ id = [string]$domainTargets[0].id }
        }
        if ($definition.Binary) {
            $downloadPath = Join-Path ([IO.Path]::GetTempPath()) ('xdr-report-' + [guid]::NewGuid().ToString('N') + '.zip')
            $parameters.OutFile = $downloadPath
        }
        $response = @(Get-XdrReport @parameters -Force)
        if (-not $definition.Binary) {
            $cached = @(Get-XdrReport @parameters)
            $responseJson = ConvertTo-Json -InputObject $response -Depth 100 -Compress
            $cachedJson = ConvertTo-Json -InputObject $cached -Depth 100 -Compress
            if ($responseJson -cne $cachedJson) { throw 'Cached report response differs from the fresh response.' }
        } elseif ($response[0].Length -eq 0) { throw 'The downloaded report file is empty.' }
        $fields = if ($response.Count -gt 0 -and $null -ne $response[0]) { @($response[0].PSObject.Properties.Name) } else { @() }
        $recordCount = $response.Count
        foreach ($field in @('value', 'currentPage', 'Rows', 'Data', 'Results', 'Items')) {
            if ($fields -contains $field) { $recordCount = @($response[0].$field).Count; break }
        }
        if ($response.Count -gt 0 -and $null -ne $response[0].properties.rows) { $recordCount = @($response[0].properties.rows).Count }
        $entry = [pscustomobject]@{
            Name = $definition.Name
            Status = 'Passed'
            HttpStatus = 200
            ResultCount = $response.Count
            RecordCount = $recordCount
            Fields = $fields
            ValidationResult = if ($definition.Name -like '*.Validate') { $response[0].Result } else { $null }
            CacheVerified = -not $definition.Binary
            DurationSeconds = [math]::Round($watch.Elapsed.TotalSeconds, 2)
        }
    } catch {
        $exception = $_.Exception
        $status = $null
        while ($exception) {
            if ($exception.Response -and $exception.Response.StatusCode) {
                $status = [int]$exception.Response.StatusCode
                break
            }
            $exception = $exception.InnerException
        }
        $validationError = $null
        if ($status -eq 400 -and $_.ErrorDetails.Message) {
            $validationError = $_.ErrorDetails.Message -replace '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', '[id]'
            $validationError = $validationError -replace '[\w.+-]+@[\w.-]+', '[address]'
            $validationError = $validationError -replace '(?i)(token|cookie|authorization|passkey|secret|credential)[^,}\r\n]*', '[redacted]'
        }
        $entry = [pscustomobject]@{
            Name = $definition.Name
            Status = if ($_.FullyQualifiedErrorId -match '^XdrReport(NoResults|TooManyResults)' -or $_.Exception.Message -eq 'NoDrilldownTarget') { 'Unavailable' } else { 'Failed' }
            Reason = if ($_.FullyQualifiedErrorId -match '^XdrReport(NoResults|TooManyResults)') { $Matches[1] } elseif ($_.Exception.Message -eq 'NoDrilldownTarget') { 'NoDrilldownTarget' } else { $null }
            HttpStatus = $status
            ExceptionType = $_.Exception.GetType().Name
            ValidationError = $validationError
            CacheVerified = $false
            DurationSeconds = [math]::Round($watch.Elapsed.TotalSeconds, 2)
        }
    } finally {
        if ($downloadPath -and (Test-Path -LiteralPath $downloadPath)) { Remove-Item -LiteralPath $downloadPath -Force }
    }
    Write-Host "$($entry.Name): $($entry.Status) HTTP=$($entry.HttpStatus)"
    $entry
}
if ($Name -contains '*') {
    foreach ($reportType in @('SummaryStatistics', 'Policies', 'CookMark')) {
        try {
            $fresh = @(Get-XdrEndpointDeviceControlReport -ReportType $reportType -Force -ErrorAction Stop)
            $cached = @(Get-XdrEndpointDeviceControlReport -ReportType $reportType -ErrorAction Stop)
            if ((ConvertTo-Json -InputObject $fresh -Depth 100 -Compress) -cne (ConvertTo-Json -InputObject $cached -Depth 100 -Compress)) { throw 'Device Control cached response mismatch.' }
            $entry = [pscustomobject]@{ Name = "Cmdlet.Get-XdrEndpointDeviceControlReport.$reportType"; Status = 'Passed'; ResultCount = $fresh.Count; CacheVerified = $true }
        } catch {
            $entry = [pscustomobject]@{ Name = "Cmdlet.Get-XdrEndpointDeviceControlReport.$reportType"; Status = 'Failed'; ExceptionType = $_.Exception.GetType().Name; CacheVerified = $false }
        }
        Write-Host "$($entry.Name): $($entry.Status)"
        $results = @($results) + $entry
    }
}
$results | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding utf8
[pscustomobject]@{
    Total = $results.Count
    Passed = @($results | Where-Object Status -eq 'Passed').Count
    Failed = @($results | Where-Object Status -eq 'Failed').Count
    Unavailable = @($results | Where-Object Status -eq 'Unavailable').Count
    OutputPath = $OutputPath
} | Format-List