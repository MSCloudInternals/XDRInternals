function Get-XdrSsoDefaultProfilePath {
    [CmdletBinding()]
    param()

    if ($IsWindows) {
        return Join-Path $env:LOCALAPPDATA 'XdrInternals\SsoEdgeProfile'
    }

    if ($IsMacOS) {
        return Join-Path $HOME 'Library/Application Support/XdrInternals/SsoBrowserProfile'
    }

    if ($IsLinux) {
        return Join-Path $HOME '.config/XdrInternals/sso-browser-profile'
    }

    throw 'Connect-XdrBySSO is not supported on this operating system.'
}

function Start-XdrSsoBrowserProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that launches the dedicated SSO browser process.')]
    [OutputType([System.Diagnostics.Process])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BrowserPath,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList,

        [switch]$Visible
    )

    $formattedArgumentList = Format-XdrProcessArgumentList -ArgumentList $ArgumentList

    if ($Visible -or -not $IsWindows) {
        return Start-Process -FilePath $BrowserPath -ArgumentList $formattedArgumentList -PassThru
    }

    return Start-Process -FilePath $BrowserPath -ArgumentList $formattedArgumentList -PassThru -WindowStyle Hidden -RedirectStandardError 'NUL'
}

function Initialize-XdrSsoProfile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that prepares the dedicated SSO browser profile.')]
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

function Get-XdrSsoLaunchArgumentList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProfilePath,

        [Parameter(Mandatory)]
        [int]$DebugPort,

        [Parameter(Mandatory)]
        [string]$StartUrl,

        [switch]$Visible,

        [string]$UserAgent
    )

    $arguments = @(
        "--remote-debugging-port=$DebugPort",
        '--remote-allow-origins=*',
        "--user-data-dir=$ProfilePath",
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-default-apps',
        '--disable-features=msEdgeSyncConsent,EdgeSync,msEdgeWelcomePage,msEdgeSidebarV2'
    )

    if (-not $Visible) {
        $arguments = @(
            '--headless=new',
            '--log-level=3',
            '--disable-gpu',
            '--disable-extensions',
            '--disable-sync',
            '--disable-background-networking',
            '--disable-component-update'
        ) + $arguments
    }

    if ($UserAgent) {
        $arguments = @("--user-agent=$UserAgent") + $arguments
    }

    return $arguments + @($StartUrl)
}

function New-XdrSsoCookieWebSession {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that creates an in-memory web session wrapper around captured cookies.')]
    [OutputType([Microsoft.PowerShell.Commands.WebRequestSession])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SccAuthCookieValue,

        [string]$XsrfToken,

        [string]$UserAgent
    )

    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    if ($UserAgent) {
        $session.UserAgent = $UserAgent
    }

    $session.Cookies.Add((New-Object System.Net.Cookie('sccauth', $SccAuthCookieValue, '/', 'security.microsoft.com')))
    if ($XsrfToken) {
        $session.Cookies.Add((New-Object System.Net.Cookie('XSRF-TOKEN', $XsrfToken, '/', 'security.microsoft.com')))
    }

    return $session
}

function Get-XdrSsoXsrfToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SccAuthCookieValue,

        [string]$TenantId,

        [string]$UserAgent
    )

    $session = New-XdrSsoCookieWebSession -SccAuthCookieValue $SccAuthCookieValue -UserAgent $UserAgent
    $securityPortalUri = if ($TenantId) {
        "https://security.microsoft.com/?tid=$TenantId"
    } else {
        'https://security.microsoft.com/'
    }

    $null = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $securityPortalUri -Verbose:$false
    return $session.Cookies.GetCookies('https://security.microsoft.com')['xsrf-token'].Value
}

function Get-XdrSsoTenantList {
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SccAuthCookieValue,

        [string]$XsrfToken,

        [string]$TenantId,

        [string]$UserAgent
    )

    $resolvedXsrfToken = $XsrfToken
    if (-not $resolvedXsrfToken) {
        $resolvedXsrfToken = Get-XdrSsoXsrfToken -SccAuthCookieValue $SccAuthCookieValue -TenantId $TenantId -UserAgent $UserAgent
    }

    $session = New-XdrSsoCookieWebSession -SccAuthCookieValue $SccAuthCookieValue -XsrfToken $resolvedXsrfToken -UserAgent $UserAgent
    $headers = @{ mtoproxyurl = 'MTO' }
    if ($resolvedXsrfToken) {
        $headers['X-XSRF-TOKEN'] = [System.Net.WebUtility]::UrlDecode($resolvedXsrfToken)
    }

    $tenantPicker = Invoke-RestMethod -Uri 'https://security.microsoft.com/apiproxy/mtoapi/tenants/TenantPicker' -ContentType 'application/json' -WebSession $session -Headers $headers -ErrorAction Stop
    return @($tenantPicker.tenantInfoList)
}

function Resolve-XdrSsoTenantSelection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [object[]]$Tenants,

        [string]$RequestedTenant,

        [switch]$SkipTenantSelection
    )

    if ($RequestedTenant) {
        $match = @(
            $Tenants | Where-Object { $_.tenantId -eq $RequestedTenant }
        ) | Where-Object { $_ } | Select-Object -First 1

        if ($match) {
            return [pscustomobject]@{
                TenantId   = $match.tenantId
                TenantName = $match.name
            }
        }

        return [pscustomobject]@{
            TenantId   = $RequestedTenant
            TenantName = $null
        }
    }

    if (-not $Tenants -or $Tenants.Count -eq 0) {
        return $null
    }

    if ($SkipTenantSelection -or $Tenants.Count -eq 1) {
        $selectedTenant = @($Tenants | Where-Object { $_.selected -eq $true } | Select-Object -First 1)
        if (-not $selectedTenant) {
            $selectedTenant = @($Tenants | Select-Object -First 1)
        }

        return [pscustomobject]@{
            TenantId   = $selectedTenant[0].tenantId
            TenantName = $selectedTenant[0].name
        }
    }

    Write-Host 'Available tenants:'
    for ($i = 0; $i -lt $Tenants.Count; $i++) {
        Write-Host "  [$($i + 1)] $($Tenants[$i].name) ($($Tenants[$i].tenantId))"
    }

    while ($true) {
        $selection = Read-Host "Select tenant [1-$($Tenants.Count)]"
        $index = 0
        if ([int]::TryParse($selection, [ref]$index) -and $index -ge 1 -and $index -le $Tenants.Count) {
            return [pscustomobject]@{
                TenantId   = $Tenants[$index - 1].tenantId
                TenantName = $Tenants[$index - 1].name
            }
        }

        Write-Host 'Invalid selection. Try again.'
    }
}

function Invoke-XdrSsoAuthentication {
    <#
    .SYNOPSIS
        Performs browser-based SSO authentication and returns Defender portal authentication artifacts.

    .DESCRIPTION
        Starts a dedicated browser profile, lets the operating system and browser perform silent
        sign-in when possible, and extracts Defender portal cookies through the browser DevTools
        protocol. This is intended for Windows-first SSO scenarios, but can also reuse existing
        browser session state on macOS and Linux when a supported Chromium-based browser is available.

    .PARAMETER TenantId
        Optional tenant ID (GUID) used to select the final tenant after sign-in.

    .PARAMETER Visible
        Shows the browser window instead of using a headless launch.

    .PARAMETER SkipTenantSelection
        Automatically uses the selected tenant or the first tenant when multiple tenants are available.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for browser sign-in and cookie capture.

    .PARAMETER BrowserPath
        Optional browser executable path or command name.

    .PARAMETER ProfilePath
        Optional persistent browser profile path used for SSO.

    .PARAMETER UserAgent
        Optional User-Agent override for the launched browser.

    .OUTPUTS
        PSCustomObject containing browser authentication artifacts and resolved tenant information.

    .EXAMPLE
        Invoke-XdrSsoAuthentication

        Attempts silent browser SSO using the default dedicated profile and returns the captured
        Defender portal authentication artifacts.

    .EXAMPLE
        Invoke-XdrSsoAuthentication -Visible -SkipTenantSelection

        Shows the browser window while the SSO flow completes and automatically selects the active tenant.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TenantId,

        [switch]$Visible,

        [switch]$SkipTenantSelection,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 180,

        [string]$BrowserPath,

        [string]$ProfilePath,

        [string]$UserAgent
    )

    if (-not ($IsWindows -or $IsMacOS -or $IsLinux)) {
        throw 'Connect-XdrBySSO is not supported on this operating system.'
    }

    $browser = Resolve-XdrBrowserPath -BrowserPath $BrowserPath
    $resolvedProfilePath = if ($ProfilePath) { $ProfilePath } else { Get-XdrSsoDefaultProfilePath }
    Initialize-XdrSsoProfile -ProfilePath $resolvedProfilePath

    $debugPort = Get-XdrBrowserFreeTcpPort
    $startUrl = 'https://security.microsoft.com/'
    $arguments = Get-XdrSsoLaunchArgumentList -ProfilePath $resolvedProfilePath -DebugPort $debugPort -StartUrl $startUrl -Visible:$Visible -UserAgent $UserAgent
    $browserProcess = $null

    try {
        Write-Host "Launching $($browser.Name) for SSO sign-in..."
        if ($Visible) {
            Write-Host 'A browser window will open. Silent sign-in should occur automatically if the browser profile and device state allow it.'
        } else {
            Write-Host 'Attempting silent browser SSO in headless mode...'
        }

        $browserProcess = Start-XdrSsoBrowserProcess -BrowserPath $browser.Path -ArgumentList $arguments -Visible:$Visible

        $versionInfo = Get-XdrBrowserCdpVersion -Port $debugPort -TimeoutSeconds 20
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $estsAuthCookieValue = $null
        $sccAuthCookieValue = $null
        $xsrfToken = $null
        $firstEstsCookieObservedAt = $null
        $lastObservedTargetDescription = $null

        do {
            Start-Sleep -Seconds 2

            if ($browserProcess) {
                $browserProcess.Refresh()
                if ($browserProcess.HasExited) {
                    if ($Visible) {
                        $message = 'The browser window closed before SSO authentication completed.'
                        if ($lastObservedTargetDescription) {
                            $message += " Last observed browser page: $lastObservedTargetDescription"
                        }

                        throw $message
                    }

                    $message = 'The browser exited before SSO authentication completed. Retry with -Visible to observe the flow on this device.'
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
            $estsAuthCookieValue = if ($selectedEstsCookie) { $selectedEstsCookie.value } else { $null }

            $sccAuthCookieValue = Get-XdrBrowserCookieValue -Cookies $cookies -Name 'sccauth' -DomainLike 'security.microsoft.com'
            $xsrfToken = Get-XdrBrowserCookieValue -Cookies $cookies -Name 'XSRF-TOKEN' -DomainLike 'security.microsoft.com'

            if ($selectedEstsCookie -and -not $firstEstsCookieObservedAt) {
                $firstEstsCookieObservedAt = Get-Date
                Write-Verbose 'Captured ESTS authentication cookie. Waiting for Defender portal cookies to appear before falling back to ESTS bootstrap.'
            }

            if (Test-XdrBrowserAuthenticationCompletion -SccAuthCookieValue $sccAuthCookieValue -EstsCookie $selectedEstsCookie -FirstEstsCookieObservedAt $firstEstsCookieObservedAt -Deadline $deadline) {
                break
            }
        } while ((Get-Date) -lt $deadline)

        if (-not $sccAuthCookieValue -and -not $estsAuthCookieValue) {
            $message = 'SSO authentication did not produce Defender portal or ESTS cookies before the timeout expired.'
            if ($lastObservedTargetDescription) {
                $message += " Last observed browser page: $lastObservedTargetDescription"
            }

            throw $message
        }

        $selectedTenant = $null
        if ($sccAuthCookieValue) {
            try {
                if (-not $xsrfToken) {
                    $xsrfToken = Get-XdrSsoXsrfToken -SccAuthCookieValue $sccAuthCookieValue -TenantId $TenantId -UserAgent $UserAgent
                }

                $tenants = Get-XdrSsoTenantList -SccAuthCookieValue $sccAuthCookieValue -XsrfToken $xsrfToken -TenantId $TenantId -UserAgent $UserAgent
                $selectedTenant = Resolve-XdrSsoTenantSelection -Tenants $tenants -RequestedTenant $TenantId -SkipTenantSelection:$SkipTenantSelection
            } catch {
                Write-Verbose "Tenant selection skipped: $($_.Exception.Message)"
            }
        }

        return [pscustomobject]@{
            EstsAuthCookieValue = $estsAuthCookieValue
            SccAuthCookieValue  = $sccAuthCookieValue
            XsrfToken           = $xsrfToken
            SelectedTenantId    = if ($selectedTenant) { $selectedTenant.TenantId } else { $TenantId }
            SelectedTenantName  = if ($selectedTenant) { $selectedTenant.TenantName } else { $null }
            ProfilePath         = $resolvedProfilePath
        }
    } finally {
        if ($browserProcess) {
            $browserProcess.Refresh()
            if (-not $browserProcess.HasExited) {
                Stop-Process -Id $browserProcess.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
