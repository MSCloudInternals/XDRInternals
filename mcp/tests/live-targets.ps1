$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$phase = 'authentication'
try {
    Import-Module (Join-Path $PSScriptRoot '../../XDRInternals/XDRInternals.psd1') *> $null
    Connect-XdrBySoftwarePasskey -KeyFilePath $env:XDR_MCP_PASSKEY_FILE *> $null
    $queries = [ordered]@{
        devices  = 'DeviceEvents | where Timestamp > ago(1h) and isnotempty(DeviceId) | summarize Timestamp=max(Timestamp) by DeviceId | top 5 by Timestamp desc | project DeviceId'
        evidence = 'AlertEvidence | where Timestamp > ago(1d) and isnotempty(DeviceId) and isnotempty(AlertId) | top 1 by Timestamp desc | project DeviceId'
        files    = 'DeviceFileEvents | where Timestamp > ago(1d) and isnotempty(SHA256) | top 1 by Timestamp desc | project SHA256'
        network  = 'DeviceNetworkEvents | where Timestamp > ago(1d) and isnotempty(RemoteIP) | top 1 by Timestamp desc | project RemoteIP'
        domains  = 'DeviceNetworkEvents | where Timestamp > ago(1d) and isnotempty(RemoteUrl) | top 20 by Timestamp desc | project RemoteUrl'
    }
    $targets = @{}
    foreach ($entry in $queries.GetEnumerator()) {
        $phase = $entry.Key
        $end = [datetime]::UtcNow
        $body = @{
            QueryText        = $entry.Value
            EncodedQueryText = $entry.Value
            StartTime        = $end.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            EndTime          = $end.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            MaxRecordCount   = 20
        } | ConvertTo-Json -Compress
        $result = Invoke-XdrRestMethod -Uri 'https://security.microsoft.com/apiproxy/mtp/huntingService/queryExecutor' -Method Post -Body $body -ErrorAction Stop
        if ($result.Results -isnot [array] -or $result.Results.Count -gt 20) { throw 'invalid_discovery' }
        $targets[$entry.Key] = @($result.Results)
    }
    [Console]::Out.WriteLine(($targets | ConvertTo-Json -Depth 4 -Compress))
} catch {
    $status = 'none'
    $exception = $_.Exception
    while ($null -ne $exception) {
        if ($null -ne $exception.Response -and $null -ne $exception.Response.StatusCode) { $status = [int]$exception.Response.StatusCode; break }
        $exception = $exception.InnerException
    }
    [Console]::Error.WriteLine("discovery phase=$phase status=$status")
    exit 1
}