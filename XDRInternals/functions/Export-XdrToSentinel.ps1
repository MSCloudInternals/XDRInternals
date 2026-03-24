function Export-XdrToSentinel {
    <#
    .SYNOPSIS
        Exports XDR data to a Microsoft Sentinel (Log Analytics) custom table.

    .DESCRIPTION
        Sends data to a Log Analytics workspace using the HTTP Data Collector API.
        Data appears in the workspace as a custom log table with the "_CL" suffix.

        Requires Set-XdrSentinelConnection to be called first with workspace credentials.

        Accepts pipeline input from any XDRInternals Get-* cmdlet or any PowerShell object array.
        Objects are serialized to JSON and posted in batches (max 30 MB per batch).

    .PARAMETER Data
        The data to export. Accepts pipeline input or an explicit array of objects.

    .PARAMETER LogType
        The custom log type name. This becomes the table name in Log Analytics with "_CL" appended.
        Example: "XdrSuppressionRules" becomes "XdrSuppressionRules_CL".
        Must contain only letters, numbers, and underscores, max 100 characters.

    .PARAMETER TimestampField
        Optional field name in the data that contains a timestamp. If specified,
        Log Analytics uses this as the TimeGenerated field instead of ingestion time.

    .PARAMETER BatchSize
        Maximum number of records per API call. Defaults to 500.

    .PARAMETER PassThru
        When specified, outputs the original data to the pipeline after exporting.

    .EXAMPLE
        Get-XdrSuppressionRule | Export-XdrToSentinel -LogType "XdrSuppressionRules"

        Exports all suppression rules to the XdrSuppressionRules_CL table.

    .EXAMPLE
        Get-XdrEndpointAdvancedFeatures | Export-XdrToSentinel -LogType "XdrAdvancedFeatures"

    .EXAMPLE
        Get-XdrAlert -Top 100 | Export-XdrToSentinel -LogType "XdrAlerts" -TimestampField "CreationTime" -PassThru | Format-Table

        Exports alerts and also passes them through for display.

    .EXAMPLE
        $devices = Get-XdrEndpointDevice
        Export-XdrToSentinel -Data $devices -LogType "XdrDevices"

    .OUTPUTS
        None by default. With -PassThru, outputs the original input objects.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Data,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9_]{1,100}$')]
        [string]$LogType,

        [string]$TimestampField,

        [int]$BatchSize = 500,

        [switch]$PassThru
    )

    begin {
        if (-not $script:SentinelWorkspaceId -or -not $script:SentinelSharedKey) {
            throw "Sentinel connection not configured. Run Set-XdrSentinelConnection first."
        }

        $collected = [System.Collections.Generic.List[object]]::new()
        $totalSent = 0
    }

    process {
        $collected.Add($Data)

        if ($collected.Count -ge $BatchSize) {
            $totalSent += Send-XdrSentinelBatch -Records $collected -LogType $LogType -TimestampField $TimestampField
            $collected.Clear()
        }

        if ($PassThru) { $Data }
    }

    end {
        if ($collected.Count -gt 0) {
            $totalSent += Send-XdrSentinelBatch -Records $collected -LogType $LogType -TimestampField $TimestampField
        }

        Write-Verbose "Exported $totalSent records to ${LogType}_CL"
    }
}

function Send-XdrSentinelBatch {
    <#
    .SYNOPSIS
        Internal function that posts a batch of records to Log Analytics HTTP Data Collector API.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]]$Records,

        [Parameter(Mandatory)]
        [string]$LogType,

        [string]$TimestampField
    )

    $workspaceId = $script:SentinelWorkspaceId
    $sharedKey = $script:SentinelSharedKey

    # Serialize to JSON
    $json = $Records | ConvertTo-Json -Depth 10 -Compress
    if ($Records.Count -eq 1) {
        # Wrap single object in array
        $json = "[$json]"
    }

    $body = [System.Text.Encoding]::UTF8.GetBytes($json)

    # Build the signature per https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
    $rfc1123Date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"

    $stringToSign = "$method`n$contentLength`n$contentType`nx-ms-date:$rfc1123Date`n$resource"
    $bytesToSign = [System.Text.Encoding]::UTF8.GetBytes($stringToSign)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $keyBytes)
    try {
        $signature = [Convert]::ToBase64String($hmac.ComputeHash($bytesToSign))
    }
    finally {
        $hmac.Dispose()
    }

    $authorization = "SharedKey ${workspaceId}:${signature}"

    $headers = @{
        "Authorization"        = $authorization
        "Log-Type"             = $LogType
        "x-ms-date"           = $rfc1123Date
    }
    if ($TimestampField) {
        $headers["time-generated-field"] = $TimestampField
    }

    $uri = "https://${workspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Post -Headers $headers -Body $body -ContentType $contentType -Verbose:$false
        if ($response.StatusCode -ne 200) {
            Write-Warning "Sentinel API returned status $($response.StatusCode) for $LogType batch ($($Records.Count) records)"
        }
        else {
            Write-Verbose "Sent $($Records.Count) records to ${LogType}_CL"
        }
    }
    catch {
        Write-Warning "Failed to send $($Records.Count) records to ${LogType}_CL: $($_.Exception.Message)"
        return 0
    }

    return $Records.Count
}
