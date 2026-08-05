function New-XdrAuthenticationErrorRecord {
    <#
    .SYNOPSIS
        Creates a terminating PowerShell error from an XDR authentication failure.

    .DESCRIPTION
        Builds the stable error identifier, category, remediation, and secret-safe metadata for
        an authentication failure while chaining the original exception when one is available.

    .PARAMETER Failure
        The normalized failure returned by Get-XdrAuthenticationFailure.

    .PARAMETER ErrorRecord
        The original PowerShell error to preserve, or an existing structured authentication error to return unchanged.

    .PARAMETER TargetObject
        An optional safe target object associated with the failure.

    .EXAMPLE
        New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $_

        Creates a terminating record while preserving the caught exception.

    .OUTPUTS
        System.Management.Automation.ErrorRecord
    #>
    [OutputType([System.Management.Automation.ErrorRecord])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates and returns an in-memory ErrorRecord without changing external state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Failure,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [object]$TargetObject
    )

    $hasAuthenticationMetadata = (
        $ErrorRecord -and
        $ErrorRecord.Exception -and
        $ErrorRecord.Exception.Data -and
        $ErrorRecord.Exception.Data.Contains('XdrAuthenticationFailure')
    )
    if ($ErrorRecord -and ($ErrorRecord.FullyQualifiedErrorId -like 'XdrAuthentication.*' -or $hasAuthenticationMetadata)) {
        return $ErrorRecord
    }

    $innerException = if ($ErrorRecord) { $ErrorRecord.Exception } else { $null }
    $exception = [System.Security.Authentication.AuthenticationException]::new([string]$Failure.Message, $innerException)
    $metadata = [pscustomobject][ordered]@{
        Code                      = $Failure.Code
        ProviderCode              = $Failure.ProviderCode
        AuthenticationMethod      = $Failure.AuthenticationMethod
        Stage                     = $Failure.Stage
        StatusCode                = $Failure.StatusCode
        Retryable                 = $Failure.Retryable
        CorrelationId             = $Failure.CorrelationId
        TraceId                   = $Failure.TraceId
        RequestId                 = $Failure.RequestId
        ConditionalAccessScenario = $Failure.ConditionalAccessScenario
        SafeEvidence              = @($Failure.SafeEvidence)
    }
    $exception.Data['XdrAuthenticationFailure'] = $metadata

    $result = [System.Management.Automation.ErrorRecord]::new(
        $exception,
        "XdrAuthentication.$($Failure.Code)",
        $Failure.ErrorCategory,
        $TargetObject
    )
    $result.ErrorDetails = [System.Management.Automation.ErrorDetails]::new([string]$Failure.Message)
    $result.ErrorDetails.RecommendedAction = [string]$Failure.RecommendedAction
    return $result
}
