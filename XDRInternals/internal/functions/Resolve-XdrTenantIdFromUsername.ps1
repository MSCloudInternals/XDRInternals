function Resolve-XdrTenantIdFromUsername {
    <#
    .SYNOPSIS
        Resolves an Entra tenant ID from a username.

    .DESCRIPTION
        Uses Entra user realm discovery to determine the most appropriate domain for the supplied
        username, then queries that domain's OpenID configuration and extracts the tenant GUID from
        the issuer or endpoint metadata.

        This helper is intended for authentication flows that need a tenant-specific authority but
        only have a username available.

    .PARAMETER Username
        The user principal name (e.g., admin@contoso.com).

    .PARAMETER UserAgent
        User-Agent string for HTTP requests.

    .OUTPUTS
        String - the resolved tenant GUID.

    .EXAMPLE
        Resolve-XdrTenantIdFromUsername -Username 'admin@contoso.com'

        Resolves the Entra tenant GUID for the supplied username.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [string]$UserAgent = (Get-XdrDefaultUserAgent)
    )

    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($UserAgent)) {
        $headers['User-Agent'] = $UserAgent
    }

    $usernameDomain = $null
    $usernameParts = $Username -split '@', 2
    if ($usernameParts.Count -eq 2 -and -not [string]::IsNullOrWhiteSpace($usernameParts[1])) {
        $usernameDomain = $usernameParts[1]
    }

    if (-not $usernameDomain) {
        throw "Could not determine a username domain from '$Username'. Specify -TenantId explicitly."
    }

    $discoveryDomain = $usernameDomain
    $userRealmUri = 'https://login.microsoftonline.com/common/userrealm/?user={0}&api-version=2.1' -f [uri]::EscapeDataString($Username)

    try {
        $userRealm = Invoke-RestMethod -Uri $userRealmUri -Method Get -Headers $headers -ErrorAction Stop -Verbose:$false
        if ($userRealm -and -not [string]::IsNullOrWhiteSpace($userRealm.DomainName)) {
            $discoveryDomain = [string]$userRealm.DomainName
        }
    } catch {
        Write-Verbose "User realm discovery failed for $Username. Falling back to the username domain."
    }

    $oidcDiscoveryUri = 'https://login.microsoftonline.com/{0}/v2.0/.well-known/openid-configuration' -f [uri]::EscapeDataString($discoveryDomain)

    try {
        $oidcConfig = Invoke-RestMethod -Uri $oidcDiscoveryUri -Method Get -Headers $headers -ErrorAction Stop -Verbose:$false
    } catch {
        throw "Could not resolve tenant ID for '$Username' using OpenID discovery for domain '$discoveryDomain'. Specify -TenantId explicitly."
    }

    foreach ($value in @($oidcConfig.issuer, $oidcConfig.authorization_endpoint, $oidcConfig.token_endpoint)) {
        if (-not [string]::IsNullOrWhiteSpace($value) -and $value -match 'https://login\.microsoftonline\.com/([0-9a-fA-F-]{36})(?:/|$)') {
            return $Matches[1]
        }
    }

    throw "OpenID discovery for '$discoveryDomain' did not expose a GUID tenant ID. Specify -TenantId explicitly."
}