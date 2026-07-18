function New-XdrAuthenticationErrorRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates and returns an in-memory ErrorRecord without changing external state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Failure,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [object]$TargetObject
    )

    if ($ErrorRecord -and $ErrorRecord.FullyQualifiedErrorId -like 'XdrAuthentication.*') {
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
