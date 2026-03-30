function Connect-XdrByCredential {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using username, password, and optional TOTP MFA.

    .DESCRIPTION
        Performs a full Entra ID web login flow programmatically (no browser required),
        handling password submission and MFA challenges, then establishes an authenticated
        session to the Defender XDR portal.

        Supported MFA methods:
          - PhoneAppOTP: Authenticator app TOTP code (computed automatically from -TotpSecret)
          - PhoneAppNotification: Push notification (polls for user approval, displays number match)
          - OneWaySMS: SMS code (prompts user to enter code from phone)

        The authentication chain is:
          1. Submit credentials to Entra ID web login endpoints
          2. Handle MFA via SAS (Server Authentication State) endpoints
          3. Extract ESTSAUTH cookie from the completed login
          4. Pass ESTSAUTH cookie to Connect-XdrByEstsCookie to get sccauth + XSRF-TOKEN

        Note: This method may be blocked by Conditional Access policies that require
        device compliance or a specific client application. It will work with MFA-only policies.

    .PARAMETER Credential
        A PSCredential object containing username and password. When provided, -Username and
        -Password are ignored. If no parameters are provided at all, you will be prompted
        interactively for credentials.

    .PARAMETER Username
        The user principal name (e.g., admin@contoso.com). Not needed if -Credential is used.

    .PARAMETER Password
        The password as a SecureString. Not needed if -Credential is used.
        If you have a plain string, convert it:
          $pw = ConvertTo-SecureString "MyPassword" -AsPlainText -Force

    .PARAMETER TotpSecret
        Base32-encoded TOTP secret for automatic MFA code generation.
        This is the secret from the QR code when setting up Microsoft Authenticator
        (otpauth://totp/...?secret=JBSWY3DPEHPK3PXP).
        If not provided and MFA is required, the function will attempt push notification
        or prompt for a code.

    .PARAMETER MfaMethod
        Preferred MFA method. Valid values: PhoneAppOTP, PhoneAppNotification, OneWaySMS.
        If not specified, the function auto-selects PhoneAppOTP only when -TotpSecret is provided
        and that method is actually offered. When multiple supported inline methods are available,
        you are prompted to choose.

    .PARAMETER TenantId
        The Defender XDR tenant ID to connect to. If not provided, the default tenant is used.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests. Defaults to a browser-compatible Edge user agent.

    .EXAMPLE
        Connect-XdrByCredential

        Prompts interactively for username and password, then authenticates.
        If MFA is required, push notification or SMS prompt will be used.

    .EXAMPLE
        Connect-XdrByCredential -TotpSecret "JBSWY3DPEHPK3PXP"

        Prompts interactively for username and password, then handles MFA automatically via TOTP.

    .EXAMPLE
        Connect-XdrByCredential -Credential (Get-Credential) -TotpSecret "JBSWY3DPEHPK3PXP"

        Uses the Get-Credential dialog for username/password, then auto-completes TOTP MFA.

    .EXAMPLE
        $pw = ConvertTo-SecureString "MyPassword" -AsPlainText -Force
        Connect-XdrByCredential -Username "admin@contoso.com" -Password $pw -TotpSecret "JBSWY3DPEHPK3PXP"

        Fully non-interactive: all credentials and MFA passed as parameters.

    .EXAMPLE
        Connect-XdrByCredential -Credential (Get-Credential) -TotpSecret "JBSWY3DPEHPK3PXP" -TenantId "8612f621-73ca-4c12-973c-0da732bc44c2"

        Authenticates and connects to a specific XDR tenant.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param (
        [Parameter(ParameterSetName = 'Credential')]
        [PSCredential]$Credential,

        [Parameter(ParameterSetName = 'Explicit')]
        [string]$Username,

        [Parameter(ParameterSetName = 'Explicit')]
        [SecureString]$Password,

        [string]$TotpSecret,

        [ValidateSet('PhoneAppOTP', 'PhoneAppNotification', 'OneWaySMS')]
        [string]$MfaMethod,

        [string]$TenantId,

        [string]$UserAgent = (Get-XdrDefaultUserAgent)
    )

    process {
        # Resolve credentials from whichever input method was used.
        # Prompt only for values the caller did not supply.
        if ($PSCmdlet.ParameterSetName -eq 'Credential' -and $Credential) {
            $resolvedUsername = $Credential.UserName
            $resolvedPassword = $Credential.Password
        } elseif ($PSCmdlet.ParameterSetName -eq 'Explicit') {
            $resolvedUsername = $Username
            $resolvedPassword = $Password

            if (-not $resolvedUsername -and -not $resolvedPassword) {
                Write-Host "Enter credentials for Defender XDR authentication:"
                $cred = Get-Credential -Message "Enter your Entra ID credentials for Defender XDR"
                if (-not $cred) {
                    throw "No credentials provided."
                }

                $resolvedUsername = $cred.UserName
                $resolvedPassword = $cred.Password
            } else {
                if (-not $resolvedUsername) {
                    $resolvedUsername = Read-Host "Username"
                }
                if (-not $resolvedPassword) {
                    $resolvedPassword = Read-Host -AsSecureString "Password for $resolvedUsername"
                }
            }
        } else {
            Write-Host "Enter credentials for Defender XDR authentication:"
            $cred = Get-Credential -Message "Enter your Entra ID credentials for Defender XDR"
            if (-not $cred) {
                throw "No credentials provided."
            }
            $resolvedUsername = $cred.UserName
            $resolvedPassword = $cred.Password
        }

        if (-not $resolvedUsername) {
            throw "No username provided."
        }
        if (-not $resolvedPassword) {
            throw "No password provided."
        }

        Write-Host "Authenticating as $resolvedUsername with credential flow..."

        $credParams = @{
            Username  = $resolvedUsername
            Password  = $resolvedPassword
            UserAgent = $UserAgent
        }
        if ($TotpSecret) { $credParams.TotpSecret = $TotpSecret }
        if ($MfaMethod) { $credParams.MfaMethod = $MfaMethod }

        $estsAuth = Invoke-XdrCredentialAuthentication @credParams

        if (-not $estsAuth) {
            throw "Credential authentication failed - no ESTS cookie was returned."
        }

        Connect-XdrAuthArtifactSet -EstsAuthCookieValue $estsAuth -TenantId $TenantId -UserAgent $UserAgent -FailureLabel 'Credential authentication'
    }
}
