function Protect-XdrHttpRequest {
    <#
    .SYNOPSIS
        Applies destination and redirect protections to sensitive HTTP requests.

    .DESCRIPTION
        Detects Defender session cookies, XSRF headers, and authorization headers in an outgoing
        request. Defender session requests are restricted to the exact security.microsoft.com HTTPS
        origin, and every sensitive request is configured not to follow redirects automatically.

    .PARAMETER Uri
        The destination URI supplied to the underlying PowerShell HTTP cmdlet.

    .PARAMETER WebSession
        The optional web request session whose Defender cookies are inspected.

    .PARAMETER Headers
        The optional request headers inspected for authorization or XSRF values.

    .PARAMETER Parameters
        A copy of the bound parameters that will be sent to the underlying HTTP cmdlet.

    .EXAMPLE
        Protect-XdrHttpRequest -Uri 'https://security.microsoft.com/api' -WebSession $session -Headers $headers -Parameters $parameters

        Validates the Defender destination and disables automatic redirects.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Uri,

        [AllowNull()]
        [object]$WebSession,

        [AllowNull()]
        [object]$Headers,

        [Parameter(Mandatory)]
        [hashtable]$Parameters
    )

    $headerNames = if ($null -ne $Headers -and $null -ne $Headers.Keys) {
        @($Headers.Keys | ForEach-Object { [string]$_ })
    } else {
        @()
    }
    $hasXsrfHeader = $headerNames -contains 'X-XSRF-TOKEN'
    $hasAuthorizationHeader = $headerNames -contains 'Authorization'
    $hasDefenderCookie = $false
    if ($null -ne $WebSession -and $null -ne $WebSession.Cookies) {
        try {
            $hasDefenderCookie = $null -ne $WebSession.Cookies.GetCookies(
                [uri]'https://security.microsoft.com/'
            )['sccauth']
        } catch {
            $hasDefenderCookie = $false
        }
    }

    if ($hasDefenderCookie -or $hasXsrfHeader) {
        $requestUri = [uri]$Uri
        if (-not $requestUri.IsAbsoluteUri -or
            $requestUri.Scheme -ne 'https' -or
            -not $requestUri.IsDefaultPort -or
            $requestUri.DnsSafeHost -ne 'security.microsoft.com' -or
            -not [string]::IsNullOrWhiteSpace($requestUri.UserInfo)) {
            throw 'Defender authentication state can only be sent to https://security.microsoft.com.'
        }
    }

    if ($hasDefenderCookie -or $hasXsrfHeader -or $hasAuthorizationHeader) {
        $Parameters['MaximumRedirection'] = 0
    }

    return $Parameters
}

function Invoke-RestMethod {
    <#
    .SYNOPSIS
        Invokes PowerShell REST requests with module-local authentication safeguards.

    .DESCRIPTION
        Proxies module-internal calls to Microsoft.PowerShell.Utility Invoke-RestMethod while
        applying Defender destination validation and fail-closed redirect handling to requests
        carrying authentication state.

    .PARAMETER Uri
        The request URI.

    .PARAMETER Method
        The HTTP method.

    .PARAMETER ContentType
        The request content type.

    .PARAMETER WebSession
        The optional web request session.

    .PARAMETER Headers
        The optional request headers.

    .PARAMETER Body
        The optional request body.

    .PARAMETER TimeoutSec
        The request timeout in seconds.

    .PARAMETER MaximumRedirection
        The maximum redirects for non-sensitive requests. Sensitive requests always use zero.

    .EXAMPLE
        Invoke-RestMethod -Uri 'https://security.microsoft.com/api' -WebSession $session -Headers $headers

        Invokes a Defender REST request without allowing automatic redirects.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Module-local security proxy delegates to the fully qualified built-in cmdlet.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Uri,

        [object]$Method,

        [string]$ContentType,

        [object]$WebSession,

        [object]$Headers,

        [AllowNull()]
        [object]$Body,

        [int]$TimeoutSec,

        [int]$MaximumRedirection
    )

    $invokeParameters = @{}
    foreach ($parameterName in $PSBoundParameters.Keys) {
        $invokeParameters[$parameterName] = $PSBoundParameters[$parameterName]
    }
    $invokeParameters = Protect-XdrHttpRequest -Uri $Uri -WebSession $WebSession -Headers $Headers -Parameters $invokeParameters
    Microsoft.PowerShell.Utility\Invoke-RestMethod @invokeParameters
}

function Invoke-WebRequest {
    <#
    .SYNOPSIS
        Invokes PowerShell web requests with module-local authentication safeguards.

    .DESCRIPTION
        Proxies module-internal calls to Microsoft.PowerShell.Utility Invoke-WebRequest while
        applying Defender destination validation and fail-closed redirect handling to requests
        carrying authentication state.

    .PARAMETER Uri
        The request URI.

    .PARAMETER Method
        The HTTP method.

    .PARAMETER ContentType
        The request content type.

    .PARAMETER WebSession
        The optional web request session.

    .PARAMETER Headers
        The optional request headers.

    .PARAMETER Body
        The optional request body.

    .PARAMETER TimeoutSec
        The request timeout in seconds.

    .PARAMETER MaximumRedirection
        The maximum redirects for non-sensitive requests. Sensitive requests always use zero.

    .PARAMETER UseBasicParsing
        Retained for compatibility with existing module calls.

    .PARAMETER SkipHttpErrorCheck
        Allows HTTP error responses to be returned instead of raised as errors.

    .PARAMETER InFile
        A file whose content is sent as the request body.

    .PARAMETER OutFile
        A file where the response body is written.

    .EXAMPLE
        Invoke-WebRequest -Uri 'https://security.microsoft.com/' -WebSession $session -Headers $headers

        Invokes a Defender web request without allowing automatic redirects.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Module-local security proxy delegates to the fully qualified built-in cmdlet.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Uri,

        [object]$Method,

        [string]$ContentType,

        [object]$WebSession,

        [object]$Headers,

        [AllowNull()]
        [object]$Body,

        [int]$TimeoutSec,

        [int]$MaximumRedirection,

        [switch]$UseBasicParsing,

        [switch]$SkipHttpErrorCheck,

        [string]$InFile,

        [string]$OutFile
    )

    $invokeParameters = @{}
    foreach ($parameterName in $PSBoundParameters.Keys) {
        $invokeParameters[$parameterName] = $PSBoundParameters[$parameterName]
    }
    $invokeParameters = Protect-XdrHttpRequest -Uri $Uri -WebSession $WebSession -Headers $Headers -Parameters $invokeParameters
    Microsoft.PowerShell.Utility\Invoke-WebRequest @invokeParameters
}
