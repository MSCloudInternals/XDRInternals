function Get-XdrWebResponseLocation {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        $Response
    )

    if ($null -eq $Response) {
        return $null
    }

    if ($Response.Headers -and $Response.Headers.Location) {
        return [string]$Response.Headers.Location
    }

    if ($Response.BaseResponse -and $Response.BaseResponse.Headers -and $Response.BaseResponse.Headers['Location']) {
        return [string]$Response.BaseResponse.Headers['Location']
    }

    return $null
}

function Invoke-XdrRedirectCaptureWebRequest {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Post')]
        [string]$Method,

        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        $Body,

        $Headers,

        [string]$ContentType
    )

    $requestParams = @{
        Uri                = $Uri
        Method             = $Method
        UseBasicParsing    = $true
        SkipHttpErrorCheck = $true
        MaximumRedirection = 0
        Verbose            = $false
        ErrorAction        = 'SilentlyContinue'
    }

    if ($PSBoundParameters.ContainsKey('Session')) {
        $requestParams['WebSession'] = $Session
    }

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $requestParams['Body'] = $Body
    }

    if ($PSBoundParameters.ContainsKey('Headers') -and $null -ne $Headers) {
        $requestParams['Headers'] = $Headers
    }

    if ($PSBoundParameters.ContainsKey('ContentType') -and -not [string]::IsNullOrWhiteSpace($ContentType)) {
        $requestParams['ContentType'] = $ContentType
    }

    $redirectErrors = @()
    $response = Invoke-WebRequest @requestParams -ErrorVariable +redirectErrors
    if ($null -ne $response) {
        return $response
    }

    foreach ($errorRecord in $redirectErrors) {
        $redirectResponse = if ($errorRecord.Exception) { $errorRecord.Exception.Response } else { $null }
        if ($null -ne $redirectResponse -and (Get-XdrWebResponseLocation -Response $redirectResponse)) {
            return $redirectResponse
        }

        if ($errorRecord.Exception -and $errorRecord.Exception.Message -match 'maximum redirection count has been exceeded') {
            Write-Verbose "Captured redirect response from $Method $Uri after PowerShell reported the redirection limit."
            continue
        }

        throw $errorRecord
    }

    throw "Web request to '$Uri' did not return a usable response."
}

function ConvertFrom-XdrUriParameterString {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [string]$ParameterString
    )

    $values = @{}
    if ([string]::IsNullOrWhiteSpace($ParameterString)) {
        return $values
    }

    foreach ($pair in $ParameterString.TrimStart('?', '#') -split '&') {
        if ([string]::IsNullOrWhiteSpace($pair)) {
            continue
        }

        $parts = $pair -split '=', 2
        $name = [uri]::UnescapeDataString(($parts[0] -replace '\+', ' '))
        $value = if ($parts.Count -gt 1) {
            [uri]::UnescapeDataString(($parts[1] -replace '\+', ' '))
        }
        else {
            ''
        }

        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $values[$name] = $value
        }
    }

    return $values
}

function Get-XdrEstsAuthorityTenant {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string]$TenantId,

        [string]$ResourceDisplayName = 'Microsoft Entra'
    )

    $authorityTenant = $TenantId
    if ([string]::IsNullOrWhiteSpace($authorityTenant)) {
        try {
            $cachedTenantId = Get-XdrCache -CacheKey 'XdrTenantId' -ErrorAction SilentlyContinue
            if ($cachedTenantId -and -not [string]::IsNullOrWhiteSpace($cachedTenantId.Value)) {
                $authorityTenant = [string]$cachedTenantId.Value
            }
        }
        catch {
            Write-Verbose "Could not read the cached tenant ID while preparing token acquisition for ${ResourceDisplayName}: $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($authorityTenant)) {
        return 'organizations'
    }

    return $authorityTenant
}

function Invoke-XdrEstsAuthTokenRequest {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [string]$Scope,

        [string]$TenantId,

        [string]$ResourceDisplayName = $Scope
    )

    $estsCookies = @($Session.Cookies.GetCookies('https://login.microsoftonline.com') | Where-Object Name -Like 'ESTS*')
    if ($estsCookies.Count -eq 0) {
        Write-Verbose "No ESTS cookies are available in the current web session, skipping silent token acquisition for $ResourceDisplayName"
        return $null
    }

    $authorityTenant = Get-XdrEstsAuthorityTenant -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName

    $clientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    $redirectUri = 'msauth.com.msauth.unsignedapp://auth'
    $authorizeUri = "https://login.microsoftonline.com/$authorityTenant/oauth2/v2.0/authorize" +
        "?response_type=code" +
        "&client_id=$clientId" +
        "&redirect_uri=$([uri]::EscapeDataString($redirectUri))" +
        "&response_mode=query" +
        "&scope=$([uri]::EscapeDataString($Scope))" +
        "&prompt=none" +
        "&sso_reload=true"

    try {
        $currentResponse = Invoke-XdrRedirectCaptureWebRequest -Uri $authorizeUri -Method Get -Session $Session
        $callbackUri = $null

        for ($redirectCount = 0; $redirectCount -lt 10 -and $null -ne $currentResponse; $redirectCount++) {
            $location = Get-XdrWebResponseLocation -Response $currentResponse
            if (-not $location) {
                break
            }

            $baseUri = if ($currentResponse.BaseResponse -and $currentResponse.BaseResponse.ResponseUri) {
                $currentResponse.BaseResponse.ResponseUri
            }
            else {
                [uri]'https://login.microsoftonline.com/'
            }

            $nextUri = [uri]::new($baseUri, $location)
            if ($nextUri.Scheme -notin @('http', 'https')) {
                $callbackUri = $nextUri
                break
            }

            $currentResponse = Invoke-XdrRedirectCaptureWebRequest -Uri $nextUri.AbsoluteUri -Method Get -Session $Session
        }

        if (-not $callbackUri) {
            Write-Verbose "Silent token acquisition for $ResourceDisplayName did not reach the native callback URI."
            return $null
        }

        $callbackParameters = ConvertFrom-XdrUriParameterString -ParameterString $callbackUri.Query
        if ($callbackParameters.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($callbackUri.Fragment)) {
            $callbackParameters = ConvertFrom-XdrUriParameterString -ParameterString $callbackUri.Fragment
        }

        if ($callbackParameters.ContainsKey('error')) {
            Write-Verbose "Silent token acquisition failed for ${ResourceDisplayName}: $($callbackParameters['error']) $($callbackParameters['error_description'])"
            return $null
        }

        if (-not $callbackParameters.ContainsKey('code')) {
            Write-Verbose "Silent token acquisition for $ResourceDisplayName did not return an authorization code."
            return $null
        }

        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$authorityTenant/oauth2/v2.0/token" `
            -Method Post `
            -Body @{
                client_id    = $clientId
                grant_type   = 'authorization_code'
                code         = $callbackParameters['code']
                redirect_uri = $redirectUri
                scope        = $Scope
            } `
            -ContentType 'application/x-www-form-urlencoded' `
            -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
            throw "The token endpoint did not return an access token."
        }

        Write-Verbose "Successfully obtained $ResourceDisplayName token via the existing Entra web session"
        return $tokenResponse.access_token
    }
    catch {
        Write-Verbose "Silent token acquisition failed for ${ResourceDisplayName}: $($_.Exception.Message)"
    }
}

function Invoke-XdrEstsCliBridgeTokenRequest {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [string]$Resource,

        [string]$TenantId,

        [string]$ResourceDisplayName = $Resource
    )

    $estsCookies = @($Session.Cookies.GetCookies('https://login.microsoftonline.com') | Where-Object Name -Like 'ESTS*')
    if ($estsCookies.Count -eq 0) {
        Write-Verbose "No ESTS cookies are available in the current web session, skipping Azure CLI-style token bridging for $ResourceDisplayName"
        return $null
    }

    $authorityTenant = Get-XdrEstsAuthorityTenant -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
    $clientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    $redirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
    $redirectUriValue = [uri]$redirectUri
    $bridgeResource = 'https://management.core.windows.net/'
    $authorizeUri = "https://login.microsoftonline.com/$authorityTenant/oauth2/authorize" +
        "?response_type=code" +
        "&client_id=$clientId" +
        "&redirect_uri=$([uri]::EscapeDataString($redirectUri))" +
        "&resource=$([uri]::EscapeDataString($bridgeResource))" +
        "&prompt=none" +
        "&sso_reload=true"

    try {
        $currentResponse = Invoke-XdrRedirectCaptureWebRequest -Uri $authorizeUri -Method Get -Session $Session
        $callbackUri = $null

        for ($redirectCount = 0; $redirectCount -lt 10 -and $null -ne $currentResponse; $redirectCount++) {
            $location = Get-XdrWebResponseLocation -Response $currentResponse
            if (-not $location) {
                break
            }

            $baseUri = if ($currentResponse.BaseResponse -and $currentResponse.BaseResponse.ResponseUri) {
                $currentResponse.BaseResponse.ResponseUri
            }
            else {
                [uri]'https://login.microsoftonline.com/'
            }

            $nextUri = [uri]::new($baseUri, $location)
            if (
                $nextUri.Scheme -notin @('http', 'https') -or
                $nextUri.GetLeftPart([System.UriPartial]::Path).TrimEnd('/') -eq $redirectUriValue.GetLeftPart([System.UriPartial]::Path).TrimEnd('/')
            ) {
                $callbackUri = $nextUri
                break
            }

            $currentResponse = Invoke-XdrRedirectCaptureWebRequest -Uri $nextUri.AbsoluteUri -Method Get -Session $Session
        }

        if (-not $callbackUri) {
            Write-Verbose "Azure CLI-style token bridging for $ResourceDisplayName did not reach the native callback URI."
            return $null
        }

        $callbackParameters = ConvertFrom-XdrUriParameterString -ParameterString $callbackUri.Query
        if ($callbackParameters.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($callbackUri.Fragment)) {
            $callbackParameters = ConvertFrom-XdrUriParameterString -ParameterString $callbackUri.Fragment
        }

        if ($callbackParameters.ContainsKey('error')) {
            Write-Verbose "Azure CLI-style token bridging failed for ${ResourceDisplayName}: $($callbackParameters['error']) $($callbackParameters['error_description'])"
            return $null
        }

        if (-not $callbackParameters.ContainsKey('code')) {
            Write-Verbose "Azure CLI-style token bridging for $ResourceDisplayName did not return an authorization code."
            return $null
        }

        $bridgeTokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$authorityTenant/oauth2/token" `
            -Method Post `
            -Body @{
                client_id    = $clientId
                grant_type   = 'authorization_code'
                code         = $callbackParameters['code']
                redirect_uri = $redirectUri
                resource     = $bridgeResource
            } `
            -ContentType 'application/x-www-form-urlencoded' `
            -ErrorAction Stop

        $resourceTokenResponse = $bridgeTokenResponse
        if ($Resource.TrimEnd('/') -ne $bridgeResource.TrimEnd('/')) {
            if ([string]::IsNullOrWhiteSpace($bridgeTokenResponse.refresh_token)) {
                Write-Verbose "Azure CLI-style token bridging for $ResourceDisplayName did not return a refresh token."
                return $null
            }

            $resourceTokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$authorityTenant/oauth2/token" `
                -Method Post `
                -Body @{
                    client_id     = $clientId
                    grant_type    = 'refresh_token'
                    refresh_token = $bridgeTokenResponse.refresh_token
                    resource      = $Resource
                } `
                -ContentType 'application/x-www-form-urlencoded' `
                -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($resourceTokenResponse.access_token)) {
            throw "The token endpoint did not return an access token."
        }

        Write-Verbose "Successfully obtained $ResourceDisplayName token via the existing Entra web session and Azure CLI-style token bridge"
        return $resourceTokenResponse.access_token
    }
    catch {
        Write-Verbose "Azure CLI-style token bridging failed for ${ResourceDisplayName}: $($_.Exception.Message)"
    }
}

function Test-XdrPreferCliBridgeForResource {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [string]$Resource,

        [string]$Scope
    )

    if (-not [string]::IsNullOrWhiteSpace($Resource) -and $Resource.TrimEnd('/') -ieq 'https://api.kusto.windows.net') {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace($Scope) -and $Scope -match '^https://[^/]+\.kusto\.windows\.net/\.default$') {
        return $true
    }

    return $false
}

function Invoke-XdrAzAccessTokenRequest {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Resource,

        [string]$TenantId,

        [string]$ResourceDisplayName = $Resource
    )

    if (-not (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue)) {
        Write-Verbose "Az.Accounts module not loaded, skipping token acquisition for $ResourceDisplayName"
        return $null
    }

    Write-Verbose "Az.Accounts module detected, attempting Get-AzAccessToken for $ResourceDisplayName..."
    try {
        $azParams = @{ ResourceUrl = $Resource }
        if ($TenantId) {
            $azParams.TenantId = $TenantId
        }

        $azToken = Get-AzAccessToken @azParams -ErrorAction Stop
        $tokenValue = if ($azToken.Token -is [System.Security.SecureString]) {
            [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($azToken.Token)
            )
        }
        else {
            $azToken.Token
        }

        Write-Verbose "Successfully obtained $ResourceDisplayName token via Az.Accounts"
        return $tokenValue
    }
    catch {
        Write-Verbose "Az.Accounts token attempt failed for ${ResourceDisplayName}: $($_.Exception.Message)"
    }
}

function Invoke-XdrAzureCliAccessTokenRequest {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Resource,

        [string]$TenantId,

        [string]$ResourceDisplayName = $Resource
    )

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Verbose "Azure CLI (az) not found on PATH, skipping token acquisition for $ResourceDisplayName"
        return $null
    }

    Write-Verbose "Azure CLI detected, attempting az account get-access-token for $ResourceDisplayName..."
    try {
        $azCliArgs = @("account", "get-access-token", "--resource", $Resource, "--output", "json")
        if ($TenantId) {
            $azCliArgs += @("--tenant", $TenantId)
        }

        $azCliOutput = & az @azCliArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            $azCliToken = ($azCliOutput | Out-String) | ConvertFrom-Json
            Write-Verbose "Successfully obtained $ResourceDisplayName token via Azure CLI"
            return $azCliToken.accessToken
        }

        Write-Verbose "Azure CLI token attempt failed for ${ResourceDisplayName}: $azCliOutput"
    }
    catch {
        Write-Verbose "Azure CLI token attempt failed for ${ResourceDisplayName}: $($_.Exception.Message)"
    }
}

function Invoke-XdrLocalAzureAccessTokenRequest {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Resource,

        [string]$TenantId,

        [string]$ResourceDisplayName = $Resource
    )

    $azAccountToken = Invoke-XdrAzAccessTokenRequest -Resource $Resource -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
    if (-not [string]::IsNullOrWhiteSpace($azAccountToken)) {
        return $azAccountToken
    }

    $azCliToken = Invoke-XdrAzureCliAccessTokenRequest -Resource $Resource -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
    if (-not [string]::IsNullOrWhiteSpace($azCliToken)) {
        return $azCliToken
    }
}

function Get-XdrAzureAccessToken {
    <#
    .SYNOPSIS
        Gets an Azure access token for a resource using the available local auth context.

    .DESCRIPTION
        Attempts to get a bearer token using, in order:
        1. Explicitly supplied access token
        2. Az.Accounts or Azure CLI for Azure Data Explorer resources
        3. The existing Entra web session (`ESTSAUTH` / `ESTS*`) when available
        4. An Azure CLI-style ESTS token bridge when the direct silent flow needs user confirmation
        5. Az.Accounts (`Get-AzAccessToken`) or Azure CLI (`az account get-access-token`)
        6. IMDS managed identity

        An explicit access token can also be supplied to bypass acquisition.

    .PARAMETER Resource
        The Azure resource URI to request a token for.

    .PARAMETER TenantId
        Optional tenant ID used when requesting a token through Az.Accounts or Azure CLI.

    .PARAMETER ManagedIdentityClientId
        Optional user-assigned managed identity client ID for IMDS token acquisition.

    .PARAMETER AccessToken
        Optional access token value to return directly.

    .PARAMETER ResourceDisplayName
        Friendly name used in verbose and error messages.

    .PARAMETER Scope
        Optional OAuth scope to use when attempting silent acquisition from the current Entra
        web session. When omitted and Resource is a URI, `<resource>/.default` is used.

    .EXAMPLE
        Get-XdrAzureAccessToken -Resource "https://api.kusto.windows.net" -ResourceDisplayName "Azure Data Explorer"

        Gets an Azure Data Explorer access token by using the current Az.Accounts, Azure CLI,
        or managed identity context.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Resource,

        [string]$TenantId,

        [string]$ManagedIdentityClientId,

        [string]$AccessToken,

        [string]$ResourceDisplayName = $Resource,

        [string]$Scope
    )

    if (-not [string]::IsNullOrWhiteSpace($AccessToken)) {
        Write-Verbose "Using explicitly provided access token for $ResourceDisplayName"
        return $AccessToken
    }

    $silentScope = $null
    if (-not [string]::IsNullOrWhiteSpace($Scope)) {
        $silentScope = $Scope.Trim()
    }
    elseif ($Resource -match '^https?://') {
        try {
            $normalizedResource = ([uri]$Resource).GetLeftPart([System.UriPartial]::Authority).TrimEnd('/')
            $silentScope = "$normalizedResource/.default"
        }
        catch {
            Write-Verbose "Could not derive a silent OAuth scope from resource '$Resource'."
        }
    }

    $preferLocalAzureAuth = Test-XdrPreferCliBridgeForResource -Resource $Resource -Scope $silentScope
    if ($preferLocalAzureAuth) {
        $localAzureToken = Invoke-XdrLocalAzureAccessTokenRequest -Resource $Resource -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
        if (-not [string]::IsNullOrWhiteSpace($localAzureToken)) {
            return $localAzureToken
        }

        Write-Verbose "No local Azure auth token was available for $ResourceDisplayName; trying the existing Entra web session."
    }

    if ($script:session) {
        $preferCliBridge = Test-XdrPreferCliBridgeForResource -Resource $Resource -Scope $silentScope
        if ($preferCliBridge) {
            $cliBridgeToken = Invoke-XdrEstsCliBridgeTokenRequest -Session $script:session -Resource $Resource -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
            if (-not [string]::IsNullOrWhiteSpace($cliBridgeToken)) {
                return $cliBridgeToken
            }

            Write-Verbose "Skipping direct silent Entra session token acquisition for $ResourceDisplayName because Azure CLI-style token bridging is preferred for this resource."
        }
        elseif (-not [string]::IsNullOrWhiteSpace($silentScope)) {
            $sessionToken = Invoke-XdrEstsAuthTokenRequest -Session $script:session -Scope $silentScope -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
            if (-not [string]::IsNullOrWhiteSpace($sessionToken)) {
                return $sessionToken
            }
        }
        else {
            Write-Verbose "Skipping direct silent Entra session token acquisition for $ResourceDisplayName because no OAuth scope was available."
        }

        if (-not $preferCliBridge) {
            $cliBridgeToken = Invoke-XdrEstsCliBridgeTokenRequest -Session $script:session -Resource $Resource -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
            if (-not [string]::IsNullOrWhiteSpace($cliBridgeToken)) {
                return $cliBridgeToken
            }
        }
    }
    else {
        Write-Verbose "No existing Entra web session detected, skipping silent token acquisition for $ResourceDisplayName"
    }

    $modeDescription = if ($ManagedIdentityClientId) {
        "user-assigned managed identity (client_id: $ManagedIdentityClientId)"
    } else {
        "system-assigned managed identity"
    }

    if (-not $preferLocalAzureAuth) {
        $localAzureToken = Invoke-XdrLocalAzureAccessTokenRequest -Resource $Resource -TenantId $TenantId -ResourceDisplayName $ResourceDisplayName
        if (-not [string]::IsNullOrWhiteSpace($localAzureToken)) {
            return $localAzureToken
        }
    }

    Write-Verbose "Attempting IMDS managed identity for $ResourceDisplayName using $modeDescription..."
    try {
        $imdsUrl = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([uri]::EscapeDataString($Resource))"
        if ($ManagedIdentityClientId) {
            $imdsUrl += "&client_id=$([uri]::EscapeDataString($ManagedIdentityClientId))"
        }

        $imdsResponse = Invoke-RestMethod -Uri $imdsUrl -Headers @{ Metadata = "true" } -TimeoutSec 3 -ErrorAction Stop
        Write-Verbose "Successfully obtained $ResourceDisplayName token via IMDS ($modeDescription)"
        return $imdsResponse.access_token
    }
    catch {
        Write-Verbose "IMDS token attempt failed for ${ResourceDisplayName}: $($_.Exception.Message)"
    }

    throw @"
Could not obtain an Azure access token for $ResourceDisplayName. Ensure one of the following:
  * Run Connect-AzAccount (Az.Accounts module) before calling this cmdlet
  * Sign in with Azure CLI: az login
  * Run this cmdlet from an Azure resource with a managed identity assigned
  * Provide -ManagedIdentityClientId for a user-assigned managed identity
  * Provide -AccessToken explicitly if you are handling auth outside this module
"@
}
