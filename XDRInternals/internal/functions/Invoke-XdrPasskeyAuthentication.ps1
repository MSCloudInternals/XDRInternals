#region Private Helper Functions

function ConvertTo-XdrBase64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function ConvertFrom-XdrBase64Url {
    param([string]$Base64Url)
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    $padding = (4 - ($base64.Length % 4)) % 4
    $base64 += '=' * $padding
    return [Convert]::FromBase64String($base64)
}

function ConvertFrom-XdrUuidToBase64Url {
    param([string]$Uuid)
    if ($Uuid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        return $Uuid
    }
    Write-Verbose "Converting UUID format credential ID to base64url"
    $hexString = $Uuid.Replace('-', '')
    $rawBytes = [byte[]]::new($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $rawBytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    $base64 = [Convert]::ToBase64String($rawBytes)
    return $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function ConvertFrom-XdrIeeeToDer {
    param([byte[]]$IeeeSignature)
    if ($IeeeSignature.Length -ne 64) {
        throw "Invalid IEEE P1363 signature length: $($IeeeSignature.Length). Expected 64 bytes for ES256."
    }
    $r = $IeeeSignature[0..31]
    $s = $IeeeSignature[32..63]
    while ($r.Length -gt 1 -and $r[0] -eq 0) { $r = $r[1..($r.Length - 1)] }
    while ($s.Length -gt 1 -and $s[0] -eq 0) { $s = $s[1..($s.Length - 1)] }
    if ($r[0] -ge 0x80) { $r = @(0) + $r }
    if ($s[0] -ge 0x80) { $s = @(0) + $s }
    $der = @(0x30, ($r.Length + $s.Length + 4), 0x02, $r.Length) + $r + @(0x02, $s.Length) + $s
    return [byte[]]$der
}

function ConvertTo-XdrPEMPrivateKey {
    param([string]$PrivateKey)
    if ($PrivateKey.Trim() -match "^-----BEGIN PRIVATE KEY-----") {
        return $PrivateKey
    }
    $cleanKey = $PrivateKey.Trim() -replace "`r|`n|\s", ""
    $cleanKey = $cleanKey -replace "-", "+" -replace "_", "/"
    $wrappedKey = ""
    for ($i = 0; $i -lt $cleanKey.Length; $i += 64) {
        if ($i + 64 -lt $cleanKey.Length) {
            $wrappedKey += $cleanKey.Substring($i, 64) + "`n"
        } else {
            $wrappedKey += $cleanKey.Substring($i)
        }
    }
    return "-----BEGIN PRIVATE KEY-----`n$wrappedKey`n-----END PRIVATE KEY-----"
}

function New-XdrPasskeyAuthenticatorData {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper for passkey data construction, not a state-changing cmdlet')]
    param(
        [Parameter(Mandatory)][string]$RpId,
        [int]$SignCount = 0,
        [byte]$Flags = 0x05
    )
    $rpIdBytes = [System.Text.Encoding]::UTF8.GetBytes($RpId)
    $rpIdHash = [System.Security.Cryptography.SHA256]::HashData($rpIdBytes)
    $cntBytes = [BitConverter]::GetBytes([int]$SignCount)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($cntBytes) }
    $authData = [byte[]]::new(37)
    [Array]::Copy($rpIdHash, 0, $authData, 0, 32)
    $authData[32] = $Flags
    [Array]::Copy($cntBytes, 0, $authData, 33, 4)
    return $authData
}

function New-XdrPasskeySignature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper for passkey signature generation, not a state-changing cmdlet')]
    param(
        [Parameter(Mandatory)][string]$Challenge,
        [Parameter(Mandatory)][string]$Origin,
        [Parameter(Mandatory)][byte[]]$AuthDataBytes,
        [string]$PrivateKeyPem,
        $KeyVaultInfo,
        [string]$KeyVaultToken,
        [string]$KeyVaultApiVersion = '7.4'
    )
    $clientData = [ordered]@{
        challenge   = $Challenge
        crossOrigin = $false
        origin      = $Origin
        type        = "webauthn.get"
    }
    $clientJson = $clientData | ConvertTo-Json -Compress -Depth 10
    $clientBytes = [System.Text.Encoding]::UTF8.GetBytes($clientJson)
    $clientHash = [System.Security.Cryptography.SHA256]::HashData($clientBytes)
    $dataToSign = $AuthDataBytes + $clientHash
    $dataHash = [System.Security.Cryptography.SHA256]::HashData($dataToSign)
    Write-Verbose "Data to sign: $($dataToSign.Length) bytes, pre-hashed to $($dataHash.Length) bytes"

    if ($KeyVaultInfo -and $KeyVaultToken) {
        Write-Verbose "Signing with Azure Key Vault ($($KeyVaultInfo.vaultName)/$($KeyVaultInfo.keyName), api-version=$KeyVaultApiVersion)"
        $dataBase64Url = ConvertTo-XdrBase64Url -Bytes $dataHash
        $signUri = "https://$($KeyVaultInfo.vaultName).vault.azure.net/keys/$($KeyVaultInfo.keyName)/sign?api-version=$KeyVaultApiVersion"
        $kvHeaders = @{ "Authorization" = "Bearer $KeyVaultToken"; "Content-Type" = "application/json" }
        $body = @{ alg = "ES256"; value = $dataBase64Url } | ConvertTo-Json

        $maxRetries = 3
        $retryDelay = 1000
        $sigBytes = $null
        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                Write-Verbose "Key Vault sign attempt $attempt of $maxRetries..."
                $result = Invoke-RestMethod -Uri $signUri -Method POST -Headers $kvHeaders -Body $body -ErrorAction Stop
                if (-not $result.value) { throw "Key Vault returned empty signature" }
                $ieeeSignature = ConvertFrom-XdrBase64Url -Base64Url $result.value
                if ($ieeeSignature.Length -ne 64) {
                    Write-Warning "Unexpected IEEE signature length: $($ieeeSignature.Length) bytes (expected 64)"
                }
                $sigBytes = ConvertFrom-XdrIeeeToDer -IeeeSignature $ieeeSignature
                Write-Verbose "Key Vault signing succeeded (DER: $($sigBytes.Length) bytes)"
                break
            } catch {
                Write-Warning "Key Vault sign attempt $attempt failed: $($_.Exception.Message)"
                if ($attempt -lt $maxRetries) {
                    Start-Sleep -Milliseconds $retryDelay
                    $retryDelay *= 2
                } else {
                    throw "Key Vault signing failed after $maxRetries attempts: $($_.Exception.Message)"
                }
            }
        }
        if (-not $sigBytes) { throw "Key Vault signing failed: no signature generated" }
    } else {
        Write-Verbose "Signing with local private key"
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        try {
            $ecdsa.ImportFromPem($PrivateKeyPem)
            $sigBytes = $ecdsa.SignHash($dataHash, [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        } finally {
            $ecdsa.Dispose()
        }
        Write-Verbose "Local signing succeeded (DER: $($sigBytes.Length) bytes)"
    }

    return @{ Signature = $sigBytes; ClientData = $clientBytes }
}

function Get-XdrKeyVaultAccessToken {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    param(
        [string]$KeyVaultTenantId,
        [string]$KeyVaultClientId
    )

    $resource = "https://vault.azure.net"
    $modeDescription = if ($KeyVaultClientId) { "user-assigned managed identity (client_id: $KeyVaultClientId)" } else { "system-assigned managed identity" }

    # 1. Try Az module (Az.Accounts)
    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        Write-Verbose "Az.Accounts module detected, attempting Get-AzAccessToken..."
        try {
            $azParams = @{ ResourceUrl = $resource }
            if ($KeyVaultTenantId) { $azParams.TenantId = $KeyVaultTenantId }
            $azToken = Get-AzAccessToken @azParams -ErrorAction Stop
            $tokenValue = if ($azToken.Token -is [System.Security.SecureString]) {
                [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($azToken.Token)
                )
            } else {
                $azToken.Token
            }
            Write-Verbose "Successfully obtained Key Vault token via Az module"
            return $tokenValue
        } catch {
            Write-Verbose "Az module token failed (not logged in or expired): $($_.Exception.Message)"
        }
    } else {
        Write-Verbose "Az.Accounts module not loaded, skipping"
    }

    # 2. Try Azure CLI
    if (Get-Command az -ErrorAction SilentlyContinue) {
        Write-Verbose "Azure CLI detected, attempting az account get-access-token..."
        try {
            $azCliArgs = @("account", "get-access-token", "--resource", $resource, "--output", "json")
            if ($KeyVaultTenantId) { $azCliArgs += @("--tenant", $KeyVaultTenantId) }
            $azCliOutput = & az @azCliArgs 2>&1
            if ($LASTEXITCODE -eq 0) {
                $azCliToken = ($azCliOutput | Out-String) | ConvertFrom-Json
                Write-Verbose "Successfully obtained Key Vault token via Azure CLI"
                return $azCliToken.accessToken
            } else {
                Write-Verbose "Azure CLI token failed (not logged in): $azCliOutput"
            }
        } catch {
            Write-Verbose "Azure CLI token attempt failed: $($_.Exception.Message)"
        }
    } else {
        Write-Verbose "Azure CLI (az) not found on PATH, skipping"
    }

    # 3. Try IMDS (managed identity)
    # Not providing -KeyVaultClientId uses system-assigned MI.
    # Providing -KeyVaultClientId uses user-assigned MI with that client ID.
    Write-Verbose "Attempting IMDS managed identity ($modeDescription)..."
    try {
        $imdsUrl = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([uri]::EscapeDataString($resource))"
        if ($KeyVaultClientId) {
            $imdsUrl += "&client_id=$([uri]::EscapeDataString($KeyVaultClientId))"
        }
        $imdsResponse = Invoke-RestMethod -Uri $imdsUrl -Headers @{ Metadata = "true" } -TimeoutSec 3 -ErrorAction Stop
        Write-Verbose "Successfully obtained Key Vault token via IMDS ($modeDescription)"
        return $imdsResponse.access_token
    } catch {
        Write-Verbose "IMDS token failed (not running in Azure or no managed identity): $($_.Exception.Message)"
    }

    # All methods failed
    throw @"
Could not obtain an Azure Key Vault access token. Ensure one of the following:
  * Run Connect-AzAccount (Az.Accounts module) before calling this cmdlet
  * Sign in with Azure CLI: az login
  * Run this cmdlet from an Azure resource with a managed identity assigned
  * Provide -KeyVaultClientId for a user-assigned managed identity
"@
}

#endregion

# JSON credential file format:
#
# Local passkey (private key embedded in file):
# {
#   "credentialId":  "<base64url or UUID>",       Required: FIDO2 credential ID
#   "privateKey":    "-----BEGIN PRIVATE KEY...",  Required: EC private key in PEM format
#   "userHandle":    "<base64url>",                Required: FIDO2 user handle
#   "username":      "user@domain.com",            Required: user principal name
#   "relyingParty":  "login.microsoft.com",        Optional: defaults to login.microsoft.com
#   "url":           "https://login.microsoft.com" Optional: authentication server URL
# }
#
# Azure Key Vault passkey (private key secured in HSM):
# {
#   "credentialId":  "<base64url or UUID>",        Required: FIDO2 credential ID
#   "keyVault": {                                  Required: replaces privateKey
#     "vaultName": "kv-name",                      Required: Azure Key Vault name
#     "keyName":   "key-name",                     Required: key name within the vault
#     "keyId":     "https://..."                   Optional: full key ID URL (informational)
#   },
#   "userHandle":    "<base64url>",                Required: FIDO2 user handle
#   "username":      "user@domain.com",            Required: user principal name
#   "relyingParty":  "login.microsoft.com",        Optional: defaults to login.microsoft.com
#   "url":           "https://login.microsoft.com" Optional: authentication server URL
# }
#
# Legacy field aliases accepted:  userName -> username,  rpId -> relyingParty,
#   methodId -> credentialId,  keyValue -> privateKey,  counter -> signCount

function Invoke-XdrPasskeyAuthentication {
    <#
    .SYNOPSIS
        Performs FIDO2 passkey authentication against Entra ID and returns the ESTSAUTH cookie value.

    .DESCRIPTION
        Implements the FIDO2 WebAuthn authentication flow against Microsoft Entra ID using a software
        passkey credential. Supports both local passkeys (PEM private key in JSON) and Azure Key Vault
        backed passkeys (private key secured in HSM, referenced by vault/key name in JSON).

        For Key Vault passkeys, a Bearer token for vault.azure.net is obtained automatically via
        (in order): Az module (Get-AzAccessToken), Azure CLI (az account get-access-token), or IMDS
        managed identity. Providing -KeyVaultClientId selects user-assigned managed identity for IMDS;
        omitting it uses system-assigned managed identity.

        This is an internal function used by Connect-XdrBySoftwarePasskey.
        Requires PowerShell 7.0 or later for ECDsa PEM key support.

    .PARAMETER KeyFilePath
        Path to a JSON credential file. See the schema comment above this function for valid formats.

    .PARAMETER KeyVaultTenantId
        Azure AD tenant ID to scope the Key Vault access token. Used with Az module or Azure CLI.
        Not required when using IMDS managed identity.

    .PARAMETER KeyVaultClientId
        Client ID of a user-assigned managed identity for Key Vault access via IMDS.
        When not provided and IMDS is used, the system-assigned managed identity is used instead.

    .PARAMETER KeyVaultApiVersion
        Azure Key Vault REST API version to use for the Sign operation. Defaults to '7.4'.
        Update this if a newer stable API version is available and required.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests.

    .EXAMPLE
        $estsAuth = Invoke-XdrPasskeyAuthentication -KeyFilePath ".github\secadmin.passkey"
        Connect-XdrByEstsCookie -EstsAuthCookieValue $estsAuth

        Performs passkey authentication with a local key and uses the result to connect.

    .OUTPUTS
        String — the ESTSAUTH cookie value suitable for passing to Connect-XdrByEstsCookie.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyFilePath,

        [string]$KeyVaultTenantId,
        [string]$KeyVaultClientId,
        [string]$KeyVaultApiVersion = '7.4',
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    #region Validate PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "Passkey authentication requires PowerShell 7 or later (for ECDsa PEM support). Current version: $($PSVersionTable.PSVersion)"
    }
    #endregion

    #region Load credential file
    if (-not (Test-Path $KeyFilePath)) {
        throw "Credential file not found: $KeyFilePath"
    }
    Write-Verbose "Loading credential file: $KeyFilePath"
    try {
        $keyData = Get-Content $KeyFilePath -Raw | ConvertFrom-Json
    } catch {
        throw "Invalid JSON in credential file '$KeyFilePath': $($_.Exception.Message)"
    }

    $targetUser = if ($null -ne $keyData.username) { $keyData.username } else { $keyData.userName }
    if (-not $targetUser) { throw "Credential file is missing 'username' or 'userName' field" }

    $rpId = $keyData.relyingParty
    if ($null -eq $rpId) { $rpId = $keyData.rpId }
    if ($null -eq $rpId) { $rpId = "login.microsoft.com" }

    $rawUrl = if ($null -ne $keyData.url) { $keyData.url } else { "https://$rpId" }
    $origin = "https://$([uri]$rawUrl | Select-Object -ExpandProperty Host)"

    $userHandle = $keyData.userHandle
    if (-not $userHandle) { throw "Credential file is missing 'userHandle' field" }
    $userHandle = $userHandle.TrimEnd('=') -replace '\+', '-' -replace '/', '_'

    $credentialId = if ($null -ne $keyData.credentialId) { $keyData.credentialId } else { $keyData.methodId }
    if (-not $credentialId) { throw "Credential file is missing 'credentialId' field" }
    $credentialId = ($credentialId.TrimEnd('=') -replace '\+', '-' -replace '/', '_') | ForEach-Object { ConvertFrom-XdrUuidToBase64Url $_ }

    Write-Verbose "User: $targetUser | RP ID: $rpId | Origin: $origin"
    Write-Verbose "Credential ID: $($credentialId.Substring(0, [Math]::Min(20, $credentialId.Length)))..."
    #endregion

    #region Determine signing mode and prepare credentials
    $useKeyVault = $null -ne $keyData.keyVault
    $kvInfo = $null
    $kvToken = $null
    $privateKeyPem = $null

    $signCount = $keyData.signCount
    if ($null -eq $signCount) { $signCount = $keyData.counter }
    if ($null -eq $signCount) { $signCount = 0 }
    $signCount = [int]$signCount

    if ($useKeyVault) {
        Write-Verbose "Key Vault passkey detected (vault: $($keyData.keyVault.vaultName), key: $($keyData.keyVault.keyName))"
        $kvInfo = @{
            vaultName = $keyData.keyVault.vaultName
            keyName   = $keyData.keyVault.keyName
            keyId     = $keyData.keyVault.keyId
        }
        Write-Verbose "Obtaining Key Vault access token..."
        $kvToken = Get-XdrKeyVaultAccessToken -KeyVaultTenantId $KeyVaultTenantId -KeyVaultClientId $KeyVaultClientId
        Write-Verbose "Key Vault access token obtained"
    } else {
        Write-Verbose "Local passkey detected"
        $privateKeySource = if ($null -ne $keyData.privateKey) { $keyData.privateKey } else { $keyData.keyValue }
        if (-not $privateKeySource) { throw "Credential file is missing 'privateKey' field (required for local passkeys)" }
        try {
            $privateKeyPem = ConvertTo-XdrPEMPrivateKey -PrivateKey $privateKeySource
        } catch {
            throw "Failed to parse private key from credential file: $($_.Exception.Message)"
        }
    }
    #endregion

    #region Establish session and initiate FIDO2 authentication flow
    $authUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize" +
               "?response_type=code" +
               "&redirect_uri=msauth.com.msauth.unsignedapp://auth" +
               "&scope=https://graph.microsoft.com/.default" +
               "&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" +
               "&sso_reload=true" +
               "&login_hint=$([uri]::EscapeDataString($targetUser))"

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent

    Write-Verbose "Initiating authentication flow for $targetUser..."
    $initialResponse = Invoke-WebRequest -UseBasicParsing -Uri $authUrl -Method Get -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false

    if (-not ($initialResponse.Content -match '{(.*)}')) {
        throw "Unexpected response from Entra ID authentication endpoint. The auth URL may have changed or the account is not configured for FIDO2."
    }
    $sessionInfo = $Matches[0] | ConvertFrom-Json

    if (-not $sessionInfo.oGetCredTypeResult.Credentials.HasFido -or -not $sessionInfo.sFidoChallenge) {
        $hasFido = $sessionInfo.oGetCredTypeResult.Credentials.HasFido
        $hasChallenge = [bool]$sessionInfo.sFidoChallenge
        throw "Passkey authentication not available for '$targetUser'. HasFido: $hasFido, Challenge present: $hasChallenge. Verify the account has a passkey registered."
    }

    $serverChallenge = [System.Text.Encoding]::ASCII.GetBytes($sessionInfo.sFidoChallenge)
    Write-Verbose "Passkey challenge received"
    #endregion

    #region Generate passkey assertion
    Write-Verbose "Generating passkey authenticator data and signature..."
    $authData = New-XdrPasskeyAuthenticatorData -RpId $rpId -SignCount $signCount

    $cryptoParams = @{
        Challenge          = ConvertTo-XdrBase64Url -Bytes $serverChallenge
        Origin             = $origin
        AuthDataBytes      = $authData
        KeyVaultApiVersion = $KeyVaultApiVersion
    }
    if ($useKeyVault) {
        $cryptoParams.KeyVaultInfo  = $kvInfo
        $cryptoParams.KeyVaultToken = $kvToken
    } else {
        $cryptoParams.PrivateKeyPem = $privateKeyPem
    }

    try {
        $crypto = New-XdrPasskeySignature @cryptoParams
    } catch {
        throw "Passkey assertion generation failed: $($_.Exception.Message)"
    }

    $fidoPayload = [ordered]@{
        id                = $credentialId
        clientDataJSON    = ConvertTo-XdrBase64Url -Bytes $crypto.ClientData
        authenticatorData = ConvertTo-XdrBase64Url -Bytes $authData
        signature         = ConvertTo-XdrBase64Url -Bytes $crypto.Signature
        userHandle        = $userHandle
    }
    $credentialsJson = $sessionInfo.oGetCredTypeResult.Credentials.FidoParams.AllowList -join ','
    Write-Verbose "Passkey assertion generated successfully"
    #endregion

    #region Submit pre-verification request
    Write-Verbose "Submitting pre-verification request..."
    $verifyUrl = "https://login.microsoft.com/common/fido/get?uiflavor=Web"
    $bodyVerify = @{
        allowedIdentities = 2
        canary            = $sessionInfo.sFT
        ServerChallenge   = $sessionInfo.sFT
        postBackUrl       = $sessionInfo.urlPost
        postBackUrlAad    = $sessionInfo.urlPostAad
        postBackUrlMsa    = $sessionInfo.urlPostMsa
        cancelUrl         = $sessionInfo.urlRefresh
        resumeUrl         = $sessionInfo.urlResume
        correlationId     = $sessionInfo.correlationId
        credentialsJson   = $credentialsJson
        ctx               = $sessionInfo.sCtx
        username          = $targetUser
        loginCanary       = $sessionInfo.canary
    }
    try {
        $respVerify = Invoke-WebRequest -UseBasicParsing -Uri $verifyUrl -Method Post -Body $bodyVerify -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false
        if ($respVerify.StatusCode -ge 400) {
            throw "Pre-verification failed with HTTP $($respVerify.StatusCode)"
        }
        if (-not ($respVerify.Content -match '{(.*)}')) {
            throw "Unexpected response format from pre-verification endpoint"
        }
        $responseInfo = $Matches[0] | ConvertFrom-Json
        Write-Verbose "Pre-verification completed"
    } catch {
        throw "Pre-verification request failed: $($_.Exception.Message)"
    }
    #endregion

    #region Submit passkey assertion
    $loginUri = "https://login.microsoftonline.com/common/login"
    $payload = @{
        type         = 23
        ps           = 23
        assertion    = ($fidoPayload | ConvertTo-Json -Compress -Depth 10)
        lmcCanary    = $responseInfo.sCrossDomainCanary
        hpgrequestid = $responseInfo.sessionId
        ctx          = $responseInfo.sCtx
        canary       = $responseInfo.canary
        flowToken    = $responseInfo.sFT
    }

    Write-Verbose "Submitting passkey assertion..."
    $null = Invoke-WebRequest -UseBasicParsing -Uri $loginUri -Method Post -Body $payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false

    if ($useKeyVault) { Start-Sleep -Milliseconds 500 }

    # SSO reload
    $loginUri = "https://login.microsoftonline.com/common/login?sso_reload=true"
    $payload.flowToken = $sessionInfo.oGetCredTypeResult.FlowToken

    Write-Verbose "Submitting SSO reload..."
    $respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $loginUri -Method Post -Body $payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false

    if ($useKeyVault) { Start-Sleep -Milliseconds 500 }
    #endregion

    #region Handle interrupt pages (CmsiInterrupt, KmsiInterrupt, ConvergedSignIn)
    $debug = $null
    if ($respFinalize.Content -match '{(.*)}') {
        try { $debug = $Matches[0] | ConvertFrom-Json } catch { $debug = $null }
    }

    $interruptHandlers = @{
        "CmsiInterrupt" = @{
            Uri    = "https://login.microsoftonline.com/appverify"
            Method = "Post"
            Body   = { @{
                ContinueAuth    = "true"
                i19             = Get-Random -Minimum 1000 -Maximum 9999
                canary          = $debug.canary
                iscsrfspeedbump = "false"
                flowToken       = $debug.sFT
                hpgrequestid    = $debug.correlationId
                ctx             = $debug.sCtx
            } }
        }
        "KmsiInterrupt" = @{
            Uri    = "https://login.microsoftonline.com/kmsi"
            Method = "Post"
            Body   = { @{
                LoginOptions = 1
                type         = 28
                ctx          = $debug.sCtx
                hpgrequestid = $debug.correlationId
                flowToken    = $debug.sFT
                canary       = $debug.canary
                i19          = 4130
            } }
        }
        "ConvergedSignIn" = @{
            Uri    = { $sessionId = if ($null -ne $debug.arrSessions -and $null -ne $debug.arrSessions[0].id) { $debug.arrSessions[0].id } else { $debug.sessionId }; "$($debug.urlLogin)&sessionid=$sessionId" }
            Method = "Get"
        }
    }

    $loopCount = 0
    $lastPageId = $null
    $authFailed = $false

    while ($debug -and $debug.pgid -in $interruptHandlers.Keys) {
        $currentPageId = $debug.pgid
        if ($currentPageId -eq $lastPageId -or ++$loopCount -gt 10) {
            $authFailed = $true
            Write-Verbose "Stuck in interrupt loop (lastPageId: $lastPageId, currentPageId: $currentPageId, loopCount: $loopCount)"
            break
        }
        $lastPageId = $currentPageId
        $handler = $interruptHandlers[$currentPageId]
        Write-Verbose "Handling interrupt: $currentPageId"

        $reqParams = @{
            Uri                = if ($handler.Uri -is [scriptblock]) { & $handler.Uri } else { $handler.Uri }
            Method             = $handler.Method
            WebSession         = $session
            UseBasicParsing    = $true
            SkipHttpErrorCheck = $true
            MaximumRedirection = 10
            Verbose            = $false
        }
        if ($handler.Body) { $reqParams.Body = & $handler.Body }

        $respFinalize = Invoke-WebRequest @reqParams
        Start-Sleep -Milliseconds 300

        $debug = $null
        if ($respFinalize.Content -match '{(.*)}') {
            try {
                $debug = $Matches[0] | ConvertFrom-Json
                if (-not $debug.pgid) { break }  # No page ID means interrupts are done
            } catch {
                break
            }
        } else {
            break
        }
    }

    if ($authFailed) {
        $hint = if ($useKeyVault) {
            "Key Vault signature validation failed. Verify Key Vault permissions (Crypto User / Sign), key name, and vault name."
        } else {
            "Passkey signature validation failed. Verify the credential ID and private key in the credential file."
        }
        throw "Authentication failed during passkey validation. $hint"
    }
    #endregion

    if ($useKeyVault) { Start-Sleep -Milliseconds 500 }

    #region Verify and return ESTSAUTH cookie
    $allCookies = $session.Cookies.GetCookies("https://login.microsoftonline.com")
    Write-Verbose "Cookies present: $($allCookies.Name -join ', ')"

    $estsCookies = $allCookies | Where-Object Name -Like "ESTS*"
    if (-not $estsCookies) {
        throw "Authentication flow completed but no ESTS authentication cookie was obtained. The passkey credentials may be invalid or expired."
    }

    # Pick the longest cookie (ESTSAUTHPERSISTENT is preferred when available)
    $bestCookie = @(
        $allCookies | Where-Object Name -EQ "ESTSAUTH"
        $allCookies | Where-Object Name -EQ "ESTSAUTHPERSISTENT"
        $allCookies | Where-Object Name -EQ "ESTSAUTHLIGHT"
    ) | Where-Object { $_ } | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1

    Write-Verbose "Obtained $($bestCookie.Name) cookie (length: $($bestCookie.Value.Length))"
    return $bestCookie.Value
    #endregion
}
