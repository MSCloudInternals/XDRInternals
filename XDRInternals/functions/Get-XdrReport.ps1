function Get-XdrReport {
    <#
    .SYNOPSIS
        Retrieves Microsoft Defender portal report data.

    .DESCRIPTION
        Executes a discovered read operation from Get-XdrReportDefinition using the
        current portal session. Preserves response fields and envelopes, and caches
        requests separately by endpoint, parameters, body, and pagination mode for 30 minutes.
        Only cataloged report endpoints can be called. Some reports require additional licenses.

    .PARAMETER Name
        Exact report operation name from Get-XdrReportDefinition.

    .PARAMETER FromDate
        Beginning of the report time range. Defaults to 30 days before ToDate.

    .PARAMETER ToDate
        End of the report time range. Defaults to the latest half-hour boundary,
        so repeated default requests can reuse the 30-minute cache.

    .PARAMETER LookbackInDays
        Lookback period for reports using a relative date range. Defaults to 30 days.

    .PARAMETER Top
        Page size for report operations exposing a top parameter. Defaults to 200.

    .PARAMETER Parameters
        Overrides for query parameters exposed by the selected report definition.
        Values are URI-encoded. Unknown query parameters are rejected.

    .PARAMETER Body
        Overrides the JSON body of a cataloged read-only Post operation.

    .PARAMETER All
        Retrieves all OData pages, returning each page with its response envelope intact.

    .PARAMETER Force
        Bypasses the cached response and retrieves fresh report data.

    .PARAMETER OutFile
        Destination for a binary report download. Required for Download operations.
        Existing files are not overwritten, and binary downloads are not cached.

    .EXAMPLE
        Get-XdrReport -Name 'DeviceHealth.healthStatus'
        Retrieves the device health report for the default time range.

    .EXAMPLE
        Get-XdrReport -Name 'Firewall.firewallInbound.topComputers' -Force
        Retrieves fresh inbound firewall report data.

    .EXAMPLE
        Get-XdrReport -Name 'AttackSurfaceReduction.AsrDetections' -All
        Retrieves all detection pages, preserving their response metadata.

    .OUTPUTS
        Object
        Returns the report API response, or response pages when All is specified.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter()]
        [datetime]$FromDate = (Get-Date).AddDays(-30),

        [Parameter()]
        [datetime]$ToDate = (Get-Date),

        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$LookbackInDays = 30,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$Top = 200,

        [Parameter()]
        [hashtable]$Parameters = @{},

        [Parameter()]
        [hashtable]$Body,

        [Parameter()]
        [switch]$All,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [string]$OutFile
    )

    process {
        $definition = Get-XdrReportCatalog | Where-Object Name -eq $Name
        if (-not $definition) { throw "Unknown report '$Name'. Use Get-XdrReportDefinition to list supported reports." }
        if (-not $PSBoundParameters.ContainsKey('ToDate')) { $ToDate = $ToDate.Date.AddMinutes([math]::Floor($ToDate.TimeOfDay.TotalMinutes / 30) * 30) }
        if (-not $PSBoundParameters.ContainsKey('FromDate')) { $FromDate = $ToDate.AddDays(-30) }
        if ($FromDate -gt $ToDate) { throw 'FromDate must not be later than ToDate.' }
        foreach ($key in $Parameters.Keys) {
            if (-not $definition.Query.ContainsKey($key)) { throw "Unknown query parameter '$key' for report '$Name'." }
        }
        foreach ($key in $definition.RequiredParameters) {
            if (-not $Parameters.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$Parameters[$key])) { throw "Query parameter '$key' is required for report '$Name'." }
        }
        if ($PSBoundParameters.ContainsKey('Body') -and $definition.Method -ne 'Post') { throw 'Body is supported only for read-only Post report operations.' }
        if ($definition.Binary -and -not $OutFile) { throw 'OutFile is required for a binary report download.' }
        if ($OutFile -and -not $definition.Binary) { throw 'OutFile applies only to binary report downloads.' }
        if ($definition.Binary -and $All) { throw 'All is not supported for binary report downloads.' }
        Update-XdrConnectionSettings
        $tokens = @{
            '{FromDate}' = $FromDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
            '{ToDate}' = $ToDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
            '{LookbackInDays}' = [string]$LookbackInDays
            '{Top}' = [string]$Top
            '{TenantId}' = [string]$script:headers['x-tid']
        }
        $path = $definition.Path
        foreach ($token in $tokens.Keys) { $path = $path.Replace($token, $tokens[$token]) }
        $queryParts = foreach ($key in ($definition.Query.Keys | Sort-Object)) {
            if (-not $Parameters.ContainsKey($key) -and $null -eq $definition.Query[$key]) { continue }
            $value = if ($Parameters.ContainsKey($key)) { [string]$Parameters[$key] } else { [string]$definition.Query[$key] }
            foreach ($token in $tokens.Keys) { $value = $value.Replace($token, $tokens[$token]) }
            [uri]::EscapeDataString($key) + '=' + [uri]::EscapeDataString($value)
        }
        $Uri = 'https://security.microsoft.com' + $path
        if ($queryParts) { $Uri += '?' + ($queryParts -join '&') }
        if ($definition.ValidationPath) {
            $validationQuery = @($queryParts | Where-Object { $_ -notmatch '^(localeId|utcOffset)=' }) -join '&'
            $validationUri = 'https://security.microsoft.com' + $definition.ValidationPath + '?' + $validationQuery
            $validation = Invoke-XdrReportRequest -Uri $validationUri -Force:$Force
            if ($validation.Result -ne 'Success') {
                $reason = if ($validation.Result -in @('NoResults', 'TooManyResults')) { $validation.Result } else { 'InvalidValidationResult' }
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new("Report '$Name' cannot be downloaded: $reason. Select a different date range or report version."),
                    "XdrReport$reason", [System.Management.Automation.ErrorCategory]::InvalidOperation, $Name)
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }
        $request = @{ Uri = $Uri; Method = $definition.Method; All = $All; Force = $Force }
        if ($OutFile) { $request.OutFile = $OutFile }
        $requestBody = if ($PSBoundParameters.ContainsKey('Body')) { $Body } else { $definition.Body }
        if ($null -ne $requestBody) {
            $json = $requestBody | ConvertTo-Json -Depth 30 -Compress
            if (-not $PSBoundParameters.ContainsKey('Body')) {
                $json = $json.Replace('"{Top}"', [string]$Top)
                foreach ($token in $tokens.Keys) { $json = $json.Replace($token, $tokens[$token]) }
            }
            $request.Body = $json
        }
        Invoke-XdrReportRequest @request
    }
}