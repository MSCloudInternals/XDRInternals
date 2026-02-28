function Get-XdrParsedErrorDetail {
    <#
    .SYNOPSIS
        Parses structured error details from an ErrorRecord.

    .DESCRIPTION
        Attempts to parse JSON content from ErrorDetails.Message first, then
        falls back to Exception.Message. Handles non-standard numeric literals
        returned by some services (Infinity, -Infinity, NaN).

    .PARAMETER ErrorRecord
        The ErrorRecord to parse.

    .EXAMPLE
        try {
            Invoke-RestMethod -Uri "https://example.test/api" -ErrorAction Stop
        } catch {
            $detail = Get-XdrParsedErrorDetail -ErrorRecord $_
        }
        Parses structured JSON error details from a caught error when available.

    .OUTPUTS
        Object
        Returns a deserialized object when parsing succeeds, otherwise $null.
    #>
    [OutputType([object])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $message = $null
    if ($ErrorRecord -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $message = "$($ErrorRecord.ErrorDetails.Message)"
    } elseif ($ErrorRecord -and $ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        $message = "$($ErrorRecord.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace($message)) {
        return $null
    }

    try {
        return ($message | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        $sanitized = $message -replace '(:\s*)Infinity(?=[,}\]])', '$1null'
        $sanitized = $sanitized -replace '(:\s*)-Infinity(?=[,}\]])', '$1null'
        $sanitized = $sanitized -replace '(:\s*)NaN(?=[,}\]])', '$1null'
        try {
            return ($sanitized | ConvertFrom-Json -ErrorAction Stop)
        } catch {
            return $null
        }
    }
}
