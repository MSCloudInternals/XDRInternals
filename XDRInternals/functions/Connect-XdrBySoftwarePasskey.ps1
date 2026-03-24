function Connect-XdrBySoftwarePasskey {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using a software passkey.

    .DESCRIPTION
        Performs passkey (FIDO2/WebAuthn) authentication against Microsoft Entra ID using a credential
        stored in a JSON file, then establishes an authenticated session to the Defender XDR portal.

        Two passkey types are supported, auto-detected from the credential file:

        **Local passkey** — the JSON file contains a privateKey field (PEM-encoded EC private key).
        No additional parameters are needed.

        **Azure Key Vault passkey** — the JSON file contains a keyVault object (vaultName, keyName).
        The private key never leaves the HSM. A Key Vault access token is obtained automatically
        by trying (in order):
          1. Az module: Get-AzAccessToken (if Az.Accounts is loaded and you are signed in)
          2. Azure CLI: az account get-access-token (if az is on PATH and you are signed in)
          3. IMDS managed identity: system-assigned (default) or user-assigned (-KeyVaultClientId)

        Requires PowerShell 7.0 or later for ECDsa PEM key support.

    .PARAMETER KeyFilePath
        Path to a JSON credential file. For local passkeys, the file must contain:
          credentialId, privateKey, relyingParty, url, userHandle, username

        For Key Vault passkeys, the file must contain:
          credentialId, keyVault.vaultName, keyVault.keyName, relyingParty, url, userHandle, username

    .PARAMETER TenantId
        The Defender XDR tenant ID to connect to. If not provided, the default tenant is used.
        This is passed to Connect-XdrByEstsCookie and does not affect Key Vault authentication.

    .PARAMETER KeyVaultTenantId
        Azure AD tenant ID used when scoping the Key Vault access token.
        Applicable when using Az module or Azure CLI for Key Vault authentication.
        Not required when using IMDS managed identity.

    .PARAMETER KeyVaultClientId
        Client ID of a user-assigned managed identity for Key Vault access via IMDS.
        When not provided and IMDS is used, the system-assigned managed identity is used.

    .PARAMETER KeyVaultApiVersion
        Azure Key Vault REST API version to use for the Sign operation. Defaults to '7.4'.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests. Defaults to Edge browser user agent.

    .EXAMPLE
        Connect-XdrBySoftwarePasskey -KeyFilePath ".github\secadmin.passkey"

        Authenticates using a local passkey stored in a JSON file.

    .EXAMPLE
        Connect-XdrBySoftwarePasskey -KeyFilePath ".\kv-passkey.json" -TenantId "847b5907-ca15-40f4-b171-eb18619dbfab"

        Authenticates using an Azure Key Vault passkey and connects to a specific XDR tenant.
        Key Vault access is obtained automatically via Az module or Azure CLI.

    .EXAMPLE
        Connect-AzAccount
        Connect-XdrBySoftwarePasskey -KeyFilePath ".\kv-passkey.json" -KeyVaultTenantId "847b5907-ca15-40f4-b171-eb18619dbfab"

        Signs in to Azure first, then authenticates with a Key Vault passkey scoped to that tenant.

    .EXAMPLE
        Connect-XdrBySoftwarePasskey -KeyFilePath ".\kv-passkey.json" -KeyVaultClientId "12345678-abcd-efgh-ijkl-123456789012"

        Authenticates using a Key Vault passkey with a user-assigned managed identity (IMDS).
        For use from Azure resources (VMs, Azure Functions, etc.).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$KeyFilePath,

        [string]$TenantId,

        [string]$KeyVaultTenantId,
        [string]$KeyVaultClientId,
        [string]$KeyVaultApiVersion = '7.4',

        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    process {
        Write-Host "Authenticating with software passkey: $KeyFilePath"

        $passkeyParams = @{
            KeyFilePath        = $KeyFilePath
            KeyVaultApiVersion = $KeyVaultApiVersion
            UserAgent          = $UserAgent
        }
        if ($KeyVaultTenantId) { $passkeyParams.KeyVaultTenantId = $KeyVaultTenantId }
        if ($KeyVaultClientId) { $passkeyParams.KeyVaultClientId = $KeyVaultClientId }

        $estsAuth = Invoke-XdrPasskeyAuthentication @passkeyParams

        $connectParams = @{
            EstsAuthCookieValue = $estsAuth
            UserAgent           = $UserAgent
        }
        if ($TenantId) { $connectParams.TenantId = $TenantId }

        Connect-XdrByEstsCookie @connectParams
    }
}
