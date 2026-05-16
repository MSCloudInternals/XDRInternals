function Invoke-XdrConnectionRenewal {
    <#
    .SYNOPSIS
        Refreshes the active XDR connection in parent scope.

    .DESCRIPTION
        Rebuilds the active XDR authentication context using the stored renewal
        descriptor when available. Software passkey sessions are renewed by
        obtaining a fresh ESTS authentication artifact; all other sessions reuse
        the current module session refresh path.

    .EXAMPLE
        Invoke-XdrConnectionRenewal

        Refreshes the active module authentication state so long-running
        operations can continue after an authentication timeout.
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
            $script:XdrConnectionRenewalDescriptor = $descriptor
            return
        }
    }

    Write-Verbose 'Renewing XDR connection by refreshing the active web session.'
    Clear-XdrCache -CacheKey 'XsrfToken' -ErrorAction SilentlyContinue
    Update-XdrConnectionSettings
}
