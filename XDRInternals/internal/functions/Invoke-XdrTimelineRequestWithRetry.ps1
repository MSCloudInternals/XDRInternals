function Invoke-XdrTimelineRequestWithRetry {
    <#
    .SYNOPSIS
        Invokes timeline HTTP requests with retry and backoff behavior.

    .DESCRIPTION
        Wraps Invoke-RestMethod for timeline retrieval scenarios that need
        consistent timeout handling, retry classification, authentication
        renewal-aware retries, and exponential backoff for transient failures.

    .PARAMETER Uri
        Fully qualified request URI to call.

    .PARAMETER Method
        HTTP method used for the request.

    .PARAMETER Headers
        Request headers to include with the call.

    .PARAMETER WebSession
        Web session that carries the authenticated Defender portal cookies.

    .PARAMETER Body
        Optional request body for POST requests.

    .PARAMETER ContentType
        Content type header used when sending the request body.

    .PARAMETER MaxRetries
        Maximum number of attempts before the helper rethrows the last error.

    .PARAMETER RetryDelaySeconds
        Base retry delay used when the server does not return a Retry-After value.

    .PARAMETER TimeoutSeconds
        Per-request timeout passed to Invoke-RestMethod.

    .EXAMPLE
        Invoke-XdrTimelineRequestWithRetry -Uri $uri -Method Post -Body $body -Headers $headers -WebSession $script:session

        Sends a timeline API request and retries transient or rate-limited
        failures before surfacing the final error.
    #>
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        $WebSession,

        [Parameter()]
        [string]$Body,

        [Parameter()]
        [string]$ContentType = 'application/json',

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$MaxRetries = 3,

        [Parameter()]
        [ValidateRange(0, 300)]
        [int]$RetryDelaySeconds = 5,

        [Parameter()]
        [ValidateRange(10, 300)]
        [int]$TimeoutSeconds = 60
    )

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $invokeParams = @{
                Uri         = $Uri
                Method      = $Method
                ContentType = $ContentType
                TimeoutSec  = $TimeoutSeconds
                ErrorAction = 'Stop'
            }
            if ($Headers) { $invokeParams.Headers = $Headers }
            if ($WebSession) { $invokeParams.WebSession = $WebSession }
            if ($PSBoundParameters.ContainsKey('Body')) { $invokeParams.Body = $Body }

            return Invoke-RestMethod @invokeParams
        }
        catch {
            $statusCode = $null
            $retryAfterSeconds = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                try {
                    $retryAfterHeader = $_.Exception.Response.Headers.RetryAfter
                    if ($retryAfterHeader) {
                        if ($retryAfterHeader.Delta) {
                            $retryAfterSeconds = [math]::Ceiling($retryAfterHeader.Delta.TotalSeconds)
                        }
                        elseif ($retryAfterHeader.Date) {
                            $retryAfterSeconds = [math]::Max(0, [math]::Ceiling(($retryAfterHeader.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds))
                        }
                    }
                }
                catch {
                    $retryAfterSeconds = $null
                }
            }

            $failureClass = Get-XdrHttpFailureClass -ErrorRecord $_ -StatusCode $statusCode
            $isRetryable = $failureClass -in @('RateLimited', 'Transient', 'Timeout') -or ($failureClass -eq 'AuthExpired' -and $attempt -lt $MaxRetries)
            if (-not $isRetryable -or $attempt -ge $MaxRetries) {
                throw
            }

            $delay = if ($null -ne $retryAfterSeconds) {
                [int]$retryAfterSeconds
            }
            else {
                [math]::Min(30, [int]($RetryDelaySeconds * [math]::Pow(2, $attempt - 1)) + (Get-Random -Minimum 0 -Maximum 3))
            }

            if ($delay -gt 0) {
                Start-Sleep -Seconds $delay
            }
        }
    }
}
