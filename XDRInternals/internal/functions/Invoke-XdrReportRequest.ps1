function Invoke-XdrReportRequest {
    <#
    .SYNOPSIS
        Retrieves and caches data from a Defender report endpoint.

    .DESCRIPTION
        Sends a report read request with the current Defender portal session.
        Separates cached responses by URI, HTTP method, and JSON request body.

    .PARAMETER Uri
        Defender portal API URI to retrieve.

    .PARAMETER Method
        HTTP method for the observed read operation, either Get or Post.

    .PARAMETER Body
        JSON request body for a read-only Post operation.

    .PARAMETER Force
        Bypasses the cached response.

    .PARAMETER All
        Retrieves additional OData pages, preserving each page's response envelope.

    .PARAMETER OutFile
        Destination for a binary report download. Does not overwrite existing files.

    .EXAMPLE
        Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/mdepdevicecontrol/m365/devicecontrolservice/Policies'
        Retrieves Device Control report policy names.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [uri]$Uri,

        [Parameter()]
        [ValidateSet('Get', 'Post')]
        [string]$Method = 'Get',

        [Parameter()]
        [string]$Body,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$All,

        [Parameter()]
        [string]$OutFile
    )

    if ($Uri.Scheme -ne 'https' -or $Uri.Host -ne 'security.microsoft.com' -or $Uri.Port -ne 443 -or
        -not ($Uri.AbsolutePath.StartsWith('/apiproxy/') -or $Uri.AbsolutePath -match '^/api/(Report(V2)?/GetReport(Definition|SummaryData|DetailData)/?|historicalsearch/GetList|reportschedule/GetList)$') -or $Uri.UserInfo) {
        throw 'Report requests must target the Defender portal API.'
    }
    if ($OutFile) {
        if ($All) { throw 'All is not supported for binary report downloads.' }
        $destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        if (Test-Path -LiteralPath $destination) { throw 'The report download destination already exists.' }
        $temporaryPath = Join-Path ([System.IO.Path]::GetDirectoryName($destination)) ('.xdr-report-' + [guid]::NewGuid().ToString('N') + '.tmp')
        $download = @{ Uri = $Uri.AbsoluteUri; Method = $Method; WebSession = $script:session; Headers = $script:headers; ErrorAction = 'Stop'; TimeoutSec = 240; MaximumRedirection = 0; OutFile = $temporaryPath }
        try {
            $null = Invoke-WebRequest @download
            [System.IO.File]::Move($temporaryPath, $destination)
        } catch {
            if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
            throw
        }
        return Get-Item -LiteralPath $destination
    }
    $requestHeaders = @{}
    foreach ($key in $script:headers.Keys) { $requestHeaders[$key] = $script:headers[$key] }
    if ($Uri.AbsolutePath.StartsWith('/apiproxy/mtp/tvm/')) {
        $requestHeaders['api-version'] = if ($Uri.AbsolutePath.Contains('/asrconfiguration/')) { '2.0' } else { '1.0' }
    }
    if ($Uri.AbsolutePath.StartsWith('/apiproxy/mtp/webThreatProtection/')) { $requestHeaders['X-ServiceType'] = 'MATP' }
    $cacheIdentity = [ordered]@{
        Authentication = if ($script:session) { $script:session.Cookies.GetCookies('https://security.microsoft.com')['sccauth'].Value } else { $null }
        Headers = [ordered]@{}
        Method = $Method
        Uri = $Uri.AbsoluteUri
        Body = $Body
        All = [bool]$All
    }
    foreach ($key in ($requestHeaders.Keys | Sort-Object)) {
        if ($key -ne 'X-XSRF-TOKEN') { $cacheIdentity.Headers[$key.ToLowerInvariant()] = $requestHeaders[$key] }
    }
    $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $hashAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($cacheIdentity | ConvertTo-Json -Depth 10 -Compress)))
        $cacheKey = 'XdrReport:' + [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    } finally {
        $hashAlgorithm.Dispose()
    }
    $cached = $null
    try {
        $cached = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
    } catch {
        Write-Verbose 'Report cache is unavailable.'
    }
    if (-not $Force -and $cached.NotValidAfter -gt (Get-Date)) {
        return $cached.Value
    }
    if ($Force) {
        Clear-XdrCache -CacheKey $cacheKey
    }
    $request = @{
        Uri                = $Uri.AbsoluteUri
        Method             = $Method
        ContentType        = 'application/json'
        WebSession         = $script:session
        Headers            = $requestHeaders
        ErrorAction        = 'Stop'
        TimeoutSec         = 120
        MaximumRedirection = 0
    }
    if ($Body) {
        $request.Body = $Body
    }
    if ($Uri.AbsolutePath.StartsWith('/apiproxy/di/Search/')) {
        $request.ContentType = 'multipart/form-data'
    }
    $pages = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    do {
        $pageIdentity = $request.Uri + '|' + $request.Headers['Continuation-Token']
        if (-not $visited.Add($pageIdentity)) {
            throw 'The report API returned a repeated continuation link.'
        }
        $result = Invoke-RestMethod @request
        $pages.Add($result)
        $nextLink = $result.'@odata.nextLink'
        $nextContext = if ($result.morePagesAvailable) { $result.pagingContext } else { $null }
        if ($All -and $result.morePagesAvailable -and [string]::IsNullOrWhiteSpace([string]$nextContext)) {
            throw 'The report API indicated more pages but returned no continuation token.'
        }
        if ($All -and $nextContext) { $request.Headers['Continuation-Token'] = [string]$nextContext }
        if ($All -and $nextLink) {
            $nextUri = [uri]::new([uri]$request.Uri, [string]$nextLink)
            if ($nextUri.Scheme -ne 'https' -or $nextUri.Host -ne $Uri.Host -or $nextUri.Port -ne 443 -or
                -not ($nextUri.AbsolutePath.StartsWith('/apiproxy/') -or $nextUri.AbsolutePath -match '^/api/(Report(V2)?/GetReport(Definition|SummaryData|DetailData)/?|historicalsearch/GetList|reportschedule/GetList)$') -or $nextUri.UserInfo) {
                throw 'The report API returned an unsafe continuation link.'
            }
            $request.Uri = $nextUri.AbsoluteUri
            $request.Method = 'Get'
            $request.Remove('Body')
        }
    } while ($All -and ($nextLink -or $nextContext))

    $value = if ($pages.Count -eq 1) { $pages[0] } else { $pages.ToArray() }
    Set-XdrCache -CacheKey $cacheKey -Value $value -TTLMinutes 30
    return $value
}