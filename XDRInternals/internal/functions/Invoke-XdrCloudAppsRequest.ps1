function Invoke-XdrCloudAppsRequest {
    <#
    .SYNOPSIS
        Invokes a Defender for Cloud Apps API request.

    .DESCRIPTION
        Internal helper that builds Cloud Apps apiproxy URLs, applies optional caching,
        unwraps common response envelopes, and assigns PSTypeNames to returned objects.

    .PARAMETER Path
        Absolute URL or apiproxy-relative API path.

    .PARAMETER Method
        HTTP method to use for the request.

    .PARAMETER Body
        Optional request body. Non-string values are converted to JSON.

    .PARAMETER TypeName
        PSTypeName to assign to returned objects.

    .PARAMETER CacheKey
        Optional cache key for cached responses.

    .PARAMETER TTLMinutes
        Cache lifetime in minutes.

    .PARAMETER Force
        Bypasses and clears a matching cached value.

    .PARAMETER Raw
        Returns the raw selected response instead of applying conversion or type names.

    .PARAMETER GridResponse
        Converts Cloud Apps grid responses with columns and rows into objects.

    .PARAMETER DataProperty
        Response property to unwrap before returning data.

    .EXAMPLE
        Invoke-XdrCloudAppsRequest -Path /mcas/cas/api/v1/settings/ -TypeName XdrCloudAppsConfigurationSettings

        Retrieves Cloud Apps settings and applies a type name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [ValidateSet('Get', 'Post', 'Put', 'Delete')]
        [string]$Method = 'Get',

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [string]$TypeName,

        [Parameter()]
        [string]$CacheKey,

        [Parameter()]
        [Int32]$TTLMinutes = 5,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$Raw,

        [Parameter()]
        [switch]$GridResponse,

        [Parameter()]
        [string]$DataProperty = 'data'
    )

    if (-not $Path.StartsWith('http', [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not $Path.StartsWith('/')) {
            $Path = "/$Path"
        }
        $Path = "https://security.microsoft.com/apiproxy$Path"
    }

    if ($CacheKey -and -not $Force) {
        $cachedValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if ($cachedValue -and $cachedValue.NotValidAfter -gt (Get-Date)) {
            $cachedResult = $cachedValue.Value
            if (-not $Raw -and $GridResponse) {
                return ConvertFrom-XdrCloudAppsResponse -InputObject $cachedResult -TypeName $TypeName
            }
            if (-not $Raw -and $TypeName) {
                return $cachedResult | Add-XdrCloudAppsTypeName -TypeName $TypeName
            }
            return $cachedResult
        }
    }

    if ($CacheKey -and $Force) {
        Clear-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
    }

    $requestParams = @{
        Uri         = $Path
        Method      = $Method
        ContentType = 'application/json'
        WebSession  = $script:session
        Headers     = $script:headers
        ErrorAction = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('Body')) {
        $requestParams.Body = if ($Body -is [string]) {
            $Body
        }
        else {
            $Body | ConvertTo-Json -Depth 20 -Compress
        }
    }

    try {
        $response = Invoke-RestMethod @requestParams
    }
    catch {
        $statusCode = $null
        $reasonPhrase = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $reasonPhrase = $_.Exception.Response.ReasonPhrase
        }

        $detail = $_.ErrorDetails.Message
        if ([string]::IsNullOrWhiteSpace($detail)) {
            $detail = $_.Exception.Message
        }
        elseif ($detail -match '<html|<!doctype|var __ADALLOM_CONSTS|Page not found') {
            $detail = 'The service returned an HTML portal error page.'
        }
        elseif ($detail.Length -gt 500) {
            $detail = $detail.Substring(0, 500) + '...'
        }

        $statusText = if ($statusCode) { "HTTP $statusCode $reasonPhrase" } else { 'request failure' }
        throw "Cloud Apps request failed: $Method $Path returned $statusText. $detail"
    }
    if ($response -is [string] -and -not [string]::IsNullOrWhiteSpace($response)) {
        try {
            $response = $response | ConvertFrom-Json
        }
        catch {
            return $response
        }
    }

    $result = if (-not $Raw -and $DataProperty -and $response.PSObject.Properties[$DataProperty]) {
        $response.$DataProperty
    }
    else {
        $response
    }

    if ($CacheKey -and $null -ne $result) {
        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes $TTLMinutes
    }

    if ($Raw) {
        return $result
    }

    if ($GridResponse) {
        return ConvertFrom-XdrCloudAppsResponse -InputObject $result -TypeName $TypeName
    }

    if ($TypeName) {
        return $result | Add-XdrCloudAppsTypeName -TypeName $TypeName
    }

    return $result
}
