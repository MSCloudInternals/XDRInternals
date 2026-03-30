function Resolve-XdrBrowserPathFromCandidateSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if ($candidate.CommandName) {
            $command = Get-Command $candidate.CommandName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($command) {
                return [pscustomobject]@{
                    Path = $command.Source
                    Name = $candidate.Name
                }
            }
        }

        if ($candidate.FilePath -and (Test-Path -LiteralPath $candidate.FilePath)) {
            return [pscustomobject]@{
                Path = $candidate.FilePath
                Name = $candidate.Name
            }
        }
    }

    return $null
}

function Resolve-XdrWindowsBrowserPath {
    [CmdletBinding()]
    param()

    $match = Resolve-XdrBrowserPathFromCandidateSet -Candidates @(
        [pscustomobject]@{ Name = 'Microsoft Edge'; CommandName = 'msedge.exe' }
        [pscustomobject]@{ Name = 'Google Chrome'; CommandName = 'chrome.exe' }
        [pscustomobject]@{ Name = 'Brave Browser'; CommandName = 'brave.exe' }
        [pscustomobject]@{ Name = 'Chromium'; CommandName = 'chromium.exe' }
        [pscustomobject]@{ Name = 'Microsoft Edge'; FilePath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' }
        [pscustomobject]@{ Name = 'Microsoft Edge'; FilePath = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' }
        [pscustomobject]@{ Name = 'Google Chrome'; FilePath = 'C:\Program Files\Google\Chrome\Application\chrome.exe' }
        [pscustomobject]@{ Name = 'Google Chrome'; FilePath = 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe' }
        [pscustomobject]@{ Name = 'Brave Browser'; FilePath = 'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe' }
        [pscustomobject]@{ Name = 'Brave Browser'; FilePath = 'C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe' }
    )

    if ($match) {
        return $match
    }

    throw 'No supported Chromium-based browser was found on Windows. Install Microsoft Edge, Google Chrome, Brave, or specify -BrowserPath.'
}

function Get-XdrMacOSBrowserCandidateSet {
    [OutputType([object[]])]
    [CmdletBinding()]
    param()

    $candidateSet = @(
        [pscustomobject]@{ Name = 'Microsoft Edge'; CommandName = 'msedge' }
        [pscustomobject]@{ Name = 'Google Chrome'; CommandName = 'google-chrome' }
        [pscustomobject]@{ Name = 'Brave Browser'; CommandName = 'brave-browser' }
        [pscustomobject]@{ Name = 'Brave Browser'; CommandName = 'brave' }
        [pscustomobject]@{ Name = 'Chromium'; CommandName = 'chromium' }
    )

    foreach ($applicationRoot in @('/Applications', (Join-Path $HOME 'Applications'))) {
        $candidateSet += @(
            [pscustomobject]@{ Name = 'Microsoft Edge'; FilePath = (Join-Path $applicationRoot 'Microsoft Edge.app/Contents/MacOS/Microsoft Edge') }
            [pscustomobject]@{ Name = 'Google Chrome'; FilePath = (Join-Path $applicationRoot 'Google Chrome.app/Contents/MacOS/Google Chrome') }
            [pscustomobject]@{ Name = 'Brave Browser'; FilePath = (Join-Path $applicationRoot 'Brave Browser.app/Contents/MacOS/Brave Browser') }
            [pscustomobject]@{ Name = 'Chromium'; FilePath = (Join-Path $applicationRoot 'Chromium.app/Contents/MacOS/Chromium') }
        )
    }

    return $candidateSet
}

function Resolve-XdrMacOSBrowserPath {
    [CmdletBinding()]
    param()

    $match = Resolve-XdrBrowserPathFromCandidateSet -Candidates (Get-XdrMacOSBrowserCandidateSet)

    if ($match) {
        return $match
    }

    throw 'No supported Chromium-based browser was found on macOS. Install Microsoft Edge, Google Chrome, Brave, Chromium, or specify -BrowserPath.'
}

function Resolve-XdrMacOSAppBundleExecutablePath {
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BundlePath
    )

    $resolvedBundlePath = (Resolve-Path -LiteralPath $BundlePath).ProviderPath
    $bundleName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedBundlePath)
    $macOsPath = Join-Path $resolvedBundlePath 'Contents/MacOS'

    if (-not (Test-Path -LiteralPath $macOsPath -PathType Container)) {
        throw "Browser application bundle '$BundlePath' does not contain a Contents/MacOS executable directory."
    }

    $candidateExecutables = @(Get-ChildItem -LiteralPath $macOsPath -File -ErrorAction Stop)
    if (-not $candidateExecutables) {
        throw "Browser application bundle '$BundlePath' does not contain an executable in Contents/MacOS."
    }

    $preferredExecutable = @(
        $candidateExecutables | Where-Object { $_.Name -eq $bundleName }
        $candidateExecutables
    ) | Where-Object { $_ } | Select-Object -First 1

    return [pscustomobject]@{
        Path = $preferredExecutable.FullName
        Name = $bundleName
    }
}

function Resolve-XdrLinuxBrowserPath {
    [CmdletBinding()]
    param()

    $match = Resolve-XdrBrowserPathFromCandidateSet -Candidates @(
        [pscustomobject]@{ Name = 'Microsoft Edge'; CommandName = 'microsoft-edge' }
        [pscustomobject]@{ Name = 'Microsoft Edge'; CommandName = 'microsoft-edge-stable' }
        [pscustomobject]@{ Name = 'Google Chrome'; CommandName = 'google-chrome' }
        [pscustomobject]@{ Name = 'Google Chrome'; CommandName = 'google-chrome-stable' }
        [pscustomobject]@{ Name = 'Brave Browser'; CommandName = 'brave-browser' }
        [pscustomobject]@{ Name = 'Chromium'; CommandName = 'chromium' }
        [pscustomobject]@{ Name = 'Chromium'; CommandName = 'chromium-browser' }
        [pscustomobject]@{ Name = 'Microsoft Edge'; FilePath = '/usr/bin/microsoft-edge' }
        [pscustomobject]@{ Name = 'Microsoft Edge'; FilePath = '/usr/bin/microsoft-edge-stable' }
        [pscustomobject]@{ Name = 'Google Chrome'; FilePath = '/usr/bin/google-chrome' }
        [pscustomobject]@{ Name = 'Google Chrome'; FilePath = '/usr/bin/google-chrome-stable' }
        [pscustomobject]@{ Name = 'Brave Browser'; FilePath = '/usr/bin/brave-browser' }
        [pscustomobject]@{ Name = 'Chromium'; FilePath = '/usr/bin/chromium' }
        [pscustomobject]@{ Name = 'Chromium'; FilePath = '/usr/bin/chromium-browser' }
    )

    if ($match) {
        return $match
    }

    throw 'No supported Chromium-based browser was found on Linux. Install Microsoft Edge, Google Chrome, Brave, Chromium, or specify -BrowserPath.'
}

function Resolve-XdrBrowserPath {
    [CmdletBinding()]
    param(
        [string]$BrowserPath
    )

    if ($BrowserPath) {
        if ($IsMacOS -and $BrowserPath -like '*.app' -and (Test-Path -LiteralPath $BrowserPath -PathType Container)) {
            return Resolve-XdrMacOSAppBundleExecutablePath -BundlePath $BrowserPath
        }

        if (Test-Path -LiteralPath $BrowserPath -PathType Leaf) {
            return [pscustomobject]@{
                Path = (Resolve-Path -LiteralPath $BrowserPath).ProviderPath
                Name = [System.IO.Path]::GetFileNameWithoutExtension($BrowserPath)
            }
        }

        $command = Get-Command $BrowserPath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) {
            return [pscustomobject]@{
                Path = $command.Source
                Name = $command.Name
            }
        }

        throw "Browser executable '$BrowserPath' was not found. Specify a valid path or command name."
    }

    if ($IsWindows) {
        return Resolve-XdrWindowsBrowserPath
    }

    if ($IsMacOS) {
        return Resolve-XdrMacOSBrowserPath
    }

    if ($IsLinux) {
        return Resolve-XdrLinuxBrowserPath
    }

    throw 'Connect-XdrByBrowser is not supported on this operating system.'
}

function Get-XdrBrowserDefaultProfilePath {
    [CmdletBinding()]
    param()

    if ($IsWindows) {
        return Join-Path $env:LOCALAPPDATA 'XdrInternals\BrowserProfile'
    }

    if ($IsMacOS) {
        return Join-Path $HOME 'Library/Application Support/XdrInternals/BrowserProfile'
    }

    if ($IsLinux) {
        return Join-Path $HOME '.config/XdrInternals/browser-profile'
    }

    throw 'Connect-XdrByBrowser is not supported on this operating system.'
}

function Initialize-XdrBrowserProfile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that prepares the dedicated browser profile.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProfilePath
    )

    if (-not (Test-Path -LiteralPath $ProfilePath)) {
        $null = New-Item -ItemType Directory -Path $ProfilePath -Force
    }

    if (-not $IsWindows) {
        return
    }

    $defaultProfilePath = Join-Path $ProfilePath 'Default'
    if (-not (Test-Path -LiteralPath $defaultProfilePath)) {
        $null = New-Item -ItemType Directory -Path $defaultProfilePath -Force
    }

    $preferencesPath = Join-Path $defaultProfilePath 'Preferences'
    if (Test-Path -LiteralPath $preferencesPath) {
        return
    }

    @{
        sync    = @{ requested = $false }
        signin  = @{ allowed = $true }
        browser = @{ has_seen_welcome_page = $true }
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $preferencesPath -Encoding UTF8
}

function Resolve-XdrBrowserProfileConfiguration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that prepares browser profile state.')]
    [CmdletBinding()]
    param(
        [string]$ProfilePath,

        [switch]$ResetProfile,

        [switch]$PrivateSession
    )

    if ($PrivateSession -and $ProfilePath) {
        throw 'Do not combine -PrivateSession with -ProfilePath. Private session uses a temporary profile automatically.'
    }

    if ($PrivateSession) {
        $temporaryProfilePath = Join-Path ([System.IO.Path]::GetTempPath()) ('xdr-browser-signin-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $temporaryProfilePath -Force

        return [pscustomobject]@{
            ProfilePath          = $temporaryProfilePath
            UsePrivateSession    = $true
            CleanupProfileOnExit = $true
        }
    }

    $resolvedProfilePath = if ($ProfilePath) { $ProfilePath } else { Get-XdrBrowserDefaultProfilePath }
    if ($ResetProfile -and (Test-Path -LiteralPath $resolvedProfilePath)) {
        Remove-Item -Path $resolvedProfilePath -Recurse -Force -ErrorAction Stop
    }

    Initialize-XdrBrowserProfile -ProfilePath $resolvedProfilePath

    return [pscustomobject]@{
        ProfilePath          = $resolvedProfilePath
        UsePrivateSession    = $false
        CleanupProfileOnExit = $false
    }
}

function Get-XdrBrowserInteractiveStartUrl {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string]$Username,

        [string]$TenantId
    )

    $tenantSegment = if ($TenantId) { $TenantId } else { 'organizations' }
    $clientId = '80ccca67-54bd-44ab-8625-4b79c4dc7775'
    $redirectUri = [uri]::EscapeDataString('https://security.microsoft.com/')
    $nonce = [guid]::NewGuid().ToString()
    $prompt = if ($Username) { 'login' } else { 'select_account' }

    $startUrl = "https://login.microsoftonline.com/$tenantSegment/oauth2/v2.0/authorize?" +
    "client_id=$clientId" +
    "&response_type=id_token" +
    "&redirect_uri=$redirectUri" +
    "&scope=openid%20profile" +
    "&response_mode=fragment" +
    "&prompt=$prompt" +
    "&nonce=$nonce"

    if ($Username) {
        $startUrl += "&login_hint=$([uri]::EscapeDataString($Username))"
    }

    return $startUrl
}

function Get-XdrBrowserPrivateModeArgument {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Browser
    )

    $browserName = [string]$Browser.Name
    $browserPath = [string]$Browser.Path

    if ($browserName -like '*Edge*' -or $browserPath -match '(?i)msedge') {
        return '--inprivate'
    }

    return '--incognito'
}

function Get-XdrBrowserLaunchArgumentList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Browser,

        [Parameter(Mandatory)]
        [bool]$UsePrivateSession,

        [Parameter(Mandatory)]
        [int]$DebugPort,

        [Parameter(Mandatory)]
        [string]$ProfileDirectory,

        [Parameter(Mandatory)]
        [string]$StartUrl,

        [string]$UserAgent
    )

    $arguments = @(
        "--remote-debugging-port=$DebugPort",
        "--user-data-dir=$ProfileDirectory",
        '--new-window',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-default-apps',
        $StartUrl
    )

    # Investigate the brief post-auth Edge account picker flash later. The WebToBrowserSignIn disable-features experiment did not provide a reliable improvement, so it is not enabled by default.

    if ($UsePrivateSession) {
        $arguments = @((Get-XdrBrowserPrivateModeArgument -Browser $Browser)) + $arguments
    }

    if ($UserAgent) {
        $arguments = @("--user-agent=$UserAgent") + $arguments
    }

    return $arguments
}

function Format-XdrProcessArgumentList {
    [OutputType([string[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    $formattedArguments = foreach ($argument in $ArgumentList) {
        if ($argument -match '^(--[^=]+=)(.*)$') {
            $argumentPrefix = $Matches[1]
            $argumentValue = $Matches[2]

            if ($argumentValue -match '[\s"]') {
                $escapedValue = $argumentValue.Replace('"', '\"')
                $argumentPrefix + '"' + $escapedValue + '"'
                continue
            }

            $argument
            continue
        }

        if ($argument -match '[\s"]') {
            $escapedArgument = $argument.Replace('"', '\"')
            '"' + $escapedArgument + '"'
            continue
        }

        $argument
    }

    return $formattedArguments
}

function Start-XdrBrowserProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that launches the browser process for authentication.')]
    [OutputType([System.Diagnostics.Process])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BrowserPath,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [switch]$SuppressBrowserOutput
    )

    $formattedArgumentList = Format-XdrProcessArgumentList -ArgumentList $ArgumentList

    if ($SuppressBrowserOutput -and -not $IsWindows) {
        $redirectConfiguration = New-XdrBrowserProcessRedirectConfiguration
        $process = Start-Process -FilePath $BrowserPath -ArgumentList $formattedArgumentList -PassThru -RedirectStandardOutput $redirectConfiguration.StandardOutputPath -RedirectStandardError $redirectConfiguration.StandardErrorPath
        $null = $process | Add-Member -NotePropertyName StandardOutputPath -NotePropertyValue $redirectConfiguration.StandardOutputPath -PassThru
        $null = $process | Add-Member -NotePropertyName StandardErrorPath -NotePropertyValue $redirectConfiguration.StandardErrorPath -PassThru
        return $process
    }

    return Start-Process -FilePath $BrowserPath -ArgumentList $formattedArgumentList -PassThru
}

function New-XdrBrowserProcessRedirectConfiguration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that allocates temporary redirect file paths for browser process output.')]
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param()

    $temporaryPath = [System.IO.Path]::GetTempPath()

    return [pscustomobject]@{
        StandardOutputPath = [System.IO.Path]::Combine($temporaryPath, ('xdr-browser-stdout-' + [guid]::NewGuid().ToString('N') + '.log'))
        StandardErrorPath  = [System.IO.Path]::Combine($temporaryPath, ('xdr-browser-stderr-' + [guid]::NewGuid().ToString('N') + '.log'))
    }
}

function Remove-XdrBrowserProcessRedirectFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that cleans up temporary redirect files created for browser process output.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Private helper operates on the redirect file set attached to a process object.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Process
    )

    $redirectPaths = @()

    if ($Process.PSObject.Properties['StandardOutputPath']) {
        $redirectPaths += [string]$Process.StandardOutputPath
    }

    if ($Process.PSObject.Properties['StandardErrorPath']) {
        $redirectPaths += [string]$Process.StandardErrorPath
    }

    foreach ($redirectPath in ($redirectPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        Remove-Item -LiteralPath $redirectPath -Force -ErrorAction SilentlyContinue
    }
}

function Test-XdrBrowserProcessOutputSuppression {
    [OutputType([bool])]
    [CmdletBinding()]
    param()

    return (-not $IsWindows) -and ($VerbosePreference -ne [System.Management.Automation.ActionPreference]::Continue)
}

function Test-XdrBrowserAuthenticationCompletion {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [string]$SccAuthCookieValue,

        [object]$EstsCookie,

        [Nullable[datetime]]$FirstEstsCookieObservedAt,

        [datetime]$Deadline,

        [int]$PortalCookieGracePeriodSeconds = 45
    )

    if ($SccAuthCookieValue) {
        return $true
    }

    if (-not $EstsCookie) {
        return $false
    }

    if (-not $FirstEstsCookieObservedAt) {
        return $false
    }

    $portalCookieGraceDeadline = ([datetime]$FirstEstsCookieObservedAt).AddSeconds($PortalCookieGracePeriodSeconds)
    if ($portalCookieGraceDeadline -gt $Deadline) {
        $portalCookieGraceDeadline = $Deadline
    }

    return (Get-Date) -ge $portalCookieGraceDeadline
}

function Get-XdrBrowserFreeTcpPort {
    [CmdletBinding()]
    param()

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Get-XdrBrowserCdpVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port,

        [int]$TimeoutSeconds = 20
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $versionUri = "http://127.0.0.1:$Port/json/version"

    do {
        try {
            return Invoke-RestMethod -Uri $versionUri -Method Get -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 500
        }
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for the browser DevTools endpoint on port $Port."
}

function Get-XdrBrowserTargetList {
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    $targetUri = "http://127.0.0.1:$Port/json/list"
    $targets = Invoke-RestMethod -Uri $targetUri -Method Get -ErrorAction Stop
    return @($targets | Where-Object { $_ })
}

function Get-XdrBrowserPreferredWebSocketUrl {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port,

        [string]$FallbackWebSocketUrl
    )

    try {
        $targets = @(Get-XdrBrowserTargetList -Port $Port)
    } catch {
        return $FallbackWebSocketUrl
    }

    $preferredTarget = @(
        $targets | Where-Object { $_.type -eq 'page' -and $_.url -like 'https://security.microsoft.com/*' -and $_.webSocketDebuggerUrl }
        $targets | Where-Object { $_.type -eq 'page' -and $_.url -like 'https://login.microsoftonline.com/*' -and $_.webSocketDebuggerUrl }
        $targets | Where-Object { $_.type -eq 'page' -and $_.webSocketDebuggerUrl }
    ) | Where-Object { $_ } | Select-Object -First 1

    if ($preferredTarget) {
        return [string]$preferredTarget.webSocketDebuggerUrl
    }

    return $FallbackWebSocketUrl
}

function Get-XdrBrowserPreferredTargetContext {
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port,

        [string]$FallbackWebSocketUrl
    )

    try {
        $targets = @(Get-XdrBrowserTargetList -Port $Port)
    } catch {
        return [pscustomobject]@{
            Url          = $null
            Title        = $null
            Type         = $null
            WebSocketUrl = $FallbackWebSocketUrl
        }
    }

    $preferredTarget = @(
        $targets | Where-Object { $_.type -eq 'page' -and $_.url -like 'https://security.microsoft.com/*' -and $_.webSocketDebuggerUrl }
        $targets | Where-Object { $_.type -eq 'page' -and $_.url -like 'https://login.microsoftonline.com/*' -and $_.webSocketDebuggerUrl }
        $targets | Where-Object { $_.type -eq 'page' -and $_.webSocketDebuggerUrl }
    ) | Where-Object { $_ } | Select-Object -First 1

    if (-not $preferredTarget) {
        return [pscustomobject]@{
            Url          = $null
            Title        = $null
            Type         = $null
            WebSocketUrl = $FallbackWebSocketUrl
        }
    }

    return [pscustomobject]@{
        Url          = [string]$preferredTarget.url
        Title        = [string]$preferredTarget.title
        Type         = [string]$preferredTarget.type
        WebSocketUrl = [string]$preferredTarget.webSocketDebuggerUrl
    }
}

function Format-XdrBrowserTargetDescription {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string]$Url,

        [string]$Title
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($Title)) {
        return $Url
    }

    return "$Title [$Url]"
}

function Invoke-XdrBrowserCdpCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WebSocketUrl,

        [Parameter(Mandatory)]
        [string]$Method,

        [hashtable]$Params
    )

    $webSocket = [System.Net.WebSockets.ClientWebSocket]::new()
    $cancellation = [System.Threading.CancellationTokenSource]::new()

    try {
        $webSocket.ConnectAsync($WebSocketUrl, $cancellation.Token).GetAwaiter().GetResult()

        $requestId = [System.Math]::Abs([guid]::NewGuid().GetHashCode())
        $payload = @{ id = $requestId; method = $Method }
        if ($Params) {
            $payload.params = $Params
        }

        $message = $payload | ConvertTo-Json -Compress -Depth 10
        $sendBuffer = [System.Text.Encoding]::UTF8.GetBytes($message)
        $webSocket.SendAsync(
            [System.ArraySegment[byte]]::new($sendBuffer),
            [System.Net.WebSockets.WebSocketMessageType]::Text,
            $true,
            $cancellation.Token
        ).GetAwaiter().GetResult()

        $receiveBuffer = [byte[]]::new(65536)

        while ($true) {
            $builder = [System.Text.StringBuilder]::new()
            do {
                $result = $webSocket.ReceiveAsync(
                    [System.ArraySegment[byte]]::new($receiveBuffer),
                    $cancellation.Token
                ).GetAwaiter().GetResult()

                if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                    throw 'The browser DevTools endpoint closed the WebSocket connection unexpectedly.'
                }

                $null = $builder.Append([System.Text.Encoding]::UTF8.GetString($receiveBuffer, 0, $result.Count))
            } while (-not $result.EndOfMessage)

            $response = $builder.ToString() | ConvertFrom-Json -Depth 20
            if ($response.id -ne $requestId) {
                continue
            }

            if ($null -ne $response.error) {
                throw "Browser DevTools command '$Method' failed: $($response.error.message)"
            }

            return $response.result
        }
    } finally {
        $webSocket.Dispose()
        $cancellation.Dispose()
    }
}

function Get-XdrBrowserCookieJar {
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WebSocketUrl
    )

    $cookieResult = $null

    foreach ($method in @('Network.getAllCookies', 'Network.getCookies', 'Storage.getCookies')) {
        try {
            $result = Invoke-XdrBrowserCdpCommand -WebSocketUrl $WebSocketUrl -Method $method
        } catch {
            continue
        }

        $cookieResult = @(
            @($result) | Where-Object {
                $_ -and $_.PSObject.Properties['cookies']
            }
        ) | Select-Object -Last 1

        if ($cookieResult) {
            break
        }
    }

    if ($null -eq $cookieResult -or $null -eq $cookieResult.cookies) {
        return @()
    }

    return @($cookieResult.cookies)
}

function Get-XdrBestBrowserEstsCookie {
    [CmdletBinding()]
    param(
        [object[]]$Cookies
    )

    if ($null -eq $Cookies -or $Cookies.Count -eq 0) {
        return $null
    }

    $estsCookies = @($Cookies | Where-Object { $_.name -like 'ESTS*' -and $_.value })
    if (-not $estsCookies) {
        return $null
    }

    $preferenceRank = @{
        ESTSAUTH           = 0
        ESTSAUTHPERSISTENT = 1
        ESTSAUTHLIGHT      = 2
    }

    return $estsCookies |
        Sort-Object -Property @(
            @{ Expression = { if ($preferenceRank.ContainsKey([string]$_.name)) { $preferenceRank[[string]$_.name] } else { 99 } } },
            @{ Expression = { $_.value.Length }; Descending = $true }
        ) |
        Select-Object -First 1
}

function Get-XdrBrowserCookieValue {
    [CmdletBinding()]
    param(
        [object[]]$Cookies,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$DomainLike
    )

    if ($null -eq $Cookies -or $Cookies.Count -eq 0) {
        return $null
    }

    $cookieMatches = @(
        $Cookies | Where-Object {
            $_.name -eq $Name -and
            $_.value -and
            (-not $DomainLike -or [string]$_.domain -like $DomainLike)
        }
    )

    if (-not $cookieMatches) {
        return $null
    }

    return ($cookieMatches | Select-Object -First 1).value
}

function Invoke-XdrBrowserAuthentication {
    <#
    .SYNOPSIS
        Launches a browser-driven sign-in flow and returns captured authentication artifacts.

    .DESCRIPTION
        This helper launches a dedicated Chromium-based browser profile, waits for the user to
        complete the sign-in, and reads the resulting cookies through the local DevTools protocol.

        When the Defender portal session cookies are already present, those are returned so the
        caller can connect directly with Set-XdrConnectionSettings. ESTS cookies are also captured
        when available as a fallback bootstrap path.

        This is an internal function used by Connect-XdrByBrowser.

    .PARAMETER Username
        Optional username to display to the user while they complete the sign-in.

    .PARAMETER TenantId
        Optional tenant identifier to scope the Entra authorize prompt.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the browser sign-in to complete.

    .PARAMETER BrowserPath
        Optional browser executable path or command name.

    .PARAMETER ProfilePath
        Optional dedicated browser profile path.

    .PARAMETER ResetProfile
        Clears the dedicated browser profile before launching the sign-in flow.

    .PARAMETER PrivateSession
        Uses a temporary private/incognito browser session instead of the default dedicated profile.

    .PARAMETER UserAgent
        Optional User-Agent override for the launched browser.

    .OUTPUTS
        PSCustomObject containing browser authentication artifacts.

    .EXAMPLE
        $cookie = Invoke-XdrBrowserAuthentication -Username 'admin@contoso.com'

        Launches a supported browser, waits for sign-in to complete, and returns the captured browser authentication artifacts.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [string]$Username,

        [string]$TenantId,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300,

        [string]$BrowserPath,

        [string]$ProfilePath,

        [switch]$ResetProfile,

        [switch]$PrivateSession,

        [string]$UserAgent
    )

    $browser = Resolve-XdrBrowserPath -BrowserPath $BrowserPath
    $debugPort = Get-XdrBrowserFreeTcpPort
    $profileConfiguration = Resolve-XdrBrowserProfileConfiguration -ProfilePath $ProfilePath -ResetProfile:$ResetProfile -PrivateSession:$PrivateSession
    $profileDirectory = $profileConfiguration.ProfilePath

    $browserProcess = $null

    try {
        $startUrl = Get-XdrBrowserInteractiveStartUrl -Username $Username -TenantId $TenantId
        $arguments = Get-XdrBrowserLaunchArgumentList -Browser $browser -UsePrivateSession:$profileConfiguration.UsePrivateSession -DebugPort $debugPort -ProfileDirectory $profileDirectory -StartUrl $startUrl -UserAgent $UserAgent

        Write-Host "Launching $($browser.Name) for browser sign-in..."
        if ($profileConfiguration.UsePrivateSession) {
            Write-Host 'Using a temporary private browser session.'
        } else {
            Write-Host "Using dedicated browser profile: $profileDirectory"
        }
        if ($Username) {
            Write-Host "Complete the sign-in in the browser with account: $Username"
        } else {
            Write-Host 'Complete the sign-in in the browser with the target account.'
        }

        $browserProcess = Start-XdrBrowserProcess -BrowserPath $browser.Path -ArgumentList $arguments -SuppressBrowserOutput:(Test-XdrBrowserProcessOutputSuppression)
        $versionInfo = Get-XdrBrowserCdpVersion -Port $debugPort -TimeoutSeconds 20

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $selectedEstsCookie = $null
        $selectedSccAuth = $null
        $selectedXsrfToken = $null
        $firstEstsCookieObservedAt = $null
        $lastObservedTargetDescription = $null

        do {
            Start-Sleep -Seconds 2

            if ($browserProcess) {
                $browserProcess.Refresh()
                if ($browserProcess.HasExited) {
                    $message = 'The browser window was closed before the browser sign-in completed.'
                    if ($lastObservedTargetDescription) {
                        $message += " Last observed browser page: $lastObservedTargetDescription"
                    }

                    throw $message
                }
            }

            try {
                $targetContext = Get-XdrBrowserPreferredTargetContext -Port $debugPort -FallbackWebSocketUrl $versionInfo.webSocketDebuggerUrl
                $currentTargetDescription = Format-XdrBrowserTargetDescription -Url $targetContext.Url -Title $targetContext.Title
                if ($currentTargetDescription -and $currentTargetDescription -ne $lastObservedTargetDescription) {
                    $lastObservedTargetDescription = $currentTargetDescription
                    Write-Verbose "Observed browser page: $currentTargetDescription"
                }

                $cookies = @(Get-XdrBrowserCookieJar -WebSocketUrl $targetContext.WebSocketUrl)
            } catch {
                Write-Verbose "Cookie polling failed: $($_.Exception.Message)"
                continue
            }

            $selectedEstsCookie = Get-XdrBestBrowserEstsCookie -Cookies $cookies
            $selectedSccAuth = Get-XdrBrowserCookieValue -Cookies $cookies -Name 'sccauth' -DomainLike 'security.microsoft.com'
            $selectedXsrfToken = Get-XdrBrowserCookieValue -Cookies $cookies -Name 'XSRF-TOKEN' -DomainLike 'security.microsoft.com'

            if ($selectedEstsCookie -and -not $firstEstsCookieObservedAt) {
                $firstEstsCookieObservedAt = Get-Date
                Write-Verbose 'Captured ESTS authentication cookie. Waiting for Defender portal cookies to appear before falling back to ESTS bootstrap.'
            }

            if (Test-XdrBrowserAuthenticationCompletion -SccAuthCookieValue $selectedSccAuth -EstsCookie $selectedEstsCookie -FirstEstsCookieObservedAt $firstEstsCookieObservedAt -Deadline $deadline) {
                break
            }
        } while ((Get-Date) -lt $deadline)

        if (-not $selectedSccAuth -and -not $selectedEstsCookie) {
            $message = 'Browser sign-in did not produce Defender portal or ESTS authentication cookies before the timeout expired.'
            if ($lastObservedTargetDescription) {
                $message += " Last observed browser page: $lastObservedTargetDescription"
            }

            throw $message
        }

        if ($selectedSccAuth) {
            Write-Verbose 'Captured Defender portal session cookies from the signed-in browser session.'
        } elseif ($selectedEstsCookie) {
            Write-Verbose 'Captured ESTS authentication cookie before the Defender XDR portal cookie appeared. Continuing with ESTS cookie bootstrap.'
        }

        return [pscustomobject]@{
            EstsAuthCookieValue = if ($selectedEstsCookie) { $selectedEstsCookie.value } else { $null }
            SccAuthCookieValue  = $selectedSccAuth
            XsrfToken           = $selectedXsrfToken
        }
    } finally {
        if ($browserProcess) {
            $browserProcess.Refresh()
            if (-not $browserProcess.HasExited) {
                Stop-Process -Id $browserProcess.Id -Force -ErrorAction SilentlyContinue
                $browserProcess.WaitForExit(1000)
            }

            Remove-XdrBrowserProcessRedirectFiles -Process $browserProcess
        }

        if ($profileConfiguration.CleanupProfileOnExit) {
            Start-Sleep -Milliseconds 500
            Remove-Item -Path $profileDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
