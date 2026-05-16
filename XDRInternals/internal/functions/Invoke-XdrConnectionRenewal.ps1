function Invoke-XdrConnectionRenewal {
    <#
    .SYNOPSIS
        Refreshes the active XDR connection in parent scope.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Refreshes in-memory module authentication state only')]
    [CmdletBinding()]
    param()

    if ((Test-Path variable:script:XdrConnectionRenewalDescriptor) -and $script:XdrConnectionRenewalDescriptor) {
        $descriptor = $script:XdrConnectionRenewalDescriptor
        if ($descriptor.Mode -eq 'SoftwarePasskey') {
            $passkeyParams = @{
                KeyFilePath        = $descriptor.KeyFilePath
                KeyVaultApiVersion = $descriptor.KeyVaultApiVersion
                UserAgent          = $descriptor.UserAgent
            }
            if ($descriptor.KeyVaultTenantId) { $passkeyParams.KeyVaultTenantId = $descriptor.KeyVaultTenantId }
            if ($descriptor.KeyVaultClientId) { $passkeyParams.KeyVaultClientId = $descriptor.KeyVaultClientId }

            Write-Verbose 'Renewing XDR connection using the in-memory software passkey descriptor.'
            $estsAuth = Invoke-XdrPasskeyAuthentication @passkeyParams
            Connect-XdrAuthArtifactSet -EstsAuthCookieValue $estsAuth -TenantId $descriptor.TenantId -UserAgent $descriptor.UserAgent -FailureLabel 'Software passkey renewal' | Out-Null
            return
        }
    }

    Write-Verbose 'Renewing XDR connection by refreshing the active web session.'
    Update-XdrConnectionSettings
}
