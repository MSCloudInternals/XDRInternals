function Get-XdrIdentityHeaders {
    <#
    .SYNOPSIS
        Builds request headers for MDI identity API calls.

    .DESCRIPTION
        Clones the current XDR session headers and appends the additional headers
        required by MDI identity APIs. Tenant headers are added from cache when
        available.

    .PARAMETER Package
        Header value for m-package.

    .PARAMETER Type
        Header value for m-type.

    .PARAMETER Name
        Header value for m-name.

    .PARAMETER ComponentName
        Header value for m-componentName.

    .PARAMETER ClientPage
        Header value for x-clientpage.

    .PARAMETER AcceptLanguage
        Header value for accept-language.

    .PARAMETER IncludeTenantId
        If true, adds tenant-id (and x-tid when missing) from cached tenant context.

    .EXAMPLE
        Get-XdrIdentityHeaders

        Returns default MDI identity headers merged with current XDR session headers.

    .EXAMPLE
        Get-XdrIdentityHeaders -Package 'identities' -Name 'TimelinePage' -ClientPage 'timeline@msec-identities'

        Returns headers customized for an identity timeline request.

    .OUTPUTS
        Hashtable
    #>
    [OutputType([System.Collections.Hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Headers is a collection of HTTP header values.')]
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Package = 'identities',

        [Parameter()]
        [string]$Type = 'Page',

        [Parameter()]
        [string]$Name = 'UserPageRouteResolver[identities]',

        [Parameter()]
        [string]$ComponentName = 'UserPageRouteResolver',

        [Parameter()]
        [string]$ClientPage = 'user@msec-identities',

        [Parameter()]
        [string]$AcceptLanguage = 'en-us',

        [Parameter()]
        [bool]$IncludeTenantId = $true
    )

    process {
        if (-not (Test-Path variable:script:headers) -or $null -eq $script:headers) {
            throw 'XDR connection headers are not initialized. Run Set-XdrConnectionSettings first.'
        }

        $mdiHeaders = @{}
        foreach ($key in $script:headers.Keys) {
            $mdiHeaders[$key] = $script:headers[$key]
        }

        if ($IncludeTenantId) {
            $tenantId = $null
            $tenantIdCache = Get-XdrCache -CacheKey 'XdrTenantId' -ErrorAction SilentlyContinue
            if ($null -ne $tenantIdCache) {
                if ($tenantIdCache -is [string]) {
                    $tenantId = $tenantIdCache
                } elseif ($tenantIdCache.PSObject.Properties['Value']) {
                    $tenantId = [string]$tenantIdCache.Value
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($tenantId)) {
                $mdiHeaders['tenant-id'] = $tenantId
                if (-not $mdiHeaders.ContainsKey('x-tid')) {
                    $mdiHeaders['x-tid'] = $tenantId
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($AcceptLanguage)) {
            $mdiHeaders['accept-language'] = $AcceptLanguage
        }
        if (-not [string]::IsNullOrWhiteSpace($Package)) {
            $mdiHeaders['m-package'] = $Package
        }
        if (-not [string]::IsNullOrWhiteSpace($Type)) {
            $mdiHeaders['m-type'] = $Type
        }
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            $mdiHeaders['m-name'] = $Name
        }
        if (-not [string]::IsNullOrWhiteSpace($ComponentName)) {
            $mdiHeaders['m-componentName'] = $ComponentName
        }
        if (-not [string]::IsNullOrWhiteSpace($ClientPage)) {
            $mdiHeaders['x-clientpage'] = $ClientPage
        }

        return $mdiHeaders
    }
}


