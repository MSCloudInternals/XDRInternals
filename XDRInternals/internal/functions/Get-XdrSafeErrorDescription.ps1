function Get-XdrSafeErrorDescription {
    <#
    .SYNOPSIS
        Produces a bounded diagnostic description of an error.

    .DESCRIPTION
        Returns HTTP status information without response content. Other exception messages have URI
        queries and fragments removed, common secret fields redacted, line breaks collapsed, and
        output length capped before they are written to verbose, warning, or error streams.

    .PARAMETER ErrorRecord
        The error record or exception to describe safely.

    .EXAMPLE
        Get-XdrSafeErrorDescription -ErrorRecord $_

        Returns a diagnostic-safe summary suitable for an error message.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ErrorRecord
    )

    $exception = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ErrorRecord.Exception
    } elseif ($ErrorRecord -is [System.Exception]) {
        $ErrorRecord
    } elseif ($null -ne $ErrorRecord.PSObject.Properties['Exception']) {
        $ErrorRecord.Exception
    }

    if ($null -eq $exception) {
        return 'No safe error details were available.'
    }

    $response = $exception.PSObject.Properties['Response'].Value
    if ($null -ne $response -and $null -ne $response.PSObject.Properties['StatusCode'].Value) {
        return "HTTP status $([int]$response.StatusCode)"
    }

    $message = [string]$exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        return $exception.GetType().Name
    }

    $message = [regex]::Replace($message, '(?i)https?://[^\s<>"'']+', {
            param($match)
            Get-XdrSafeUriDescription -Uri $match.Value
        })
    $message = [regex]::Replace(
        $message,
        '(?i)\b(authorization\s*[:=]\s*(?:bearer|sharedkey)\s+)\S+',
        '$1<redacted>'
    )
    $message = [regex]::Replace(
        $message,
        '(?i)\b(access_token|refresh_token|id_token|assertion|client_secret|code|sig|signature|token|cookie)=([^&\s]+)',
        '$1=<redacted>'
    )
    $message = [regex]::Replace(
        $message,
        '(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,})?',
        '<redacted-token>'
    )
    $message = [regex]::Replace($message, '\s+', ' ').Trim()

    if ($message.Length -gt 300) {
        return $message.Substring(0, 300) + '...'
    }

    return $message
}
