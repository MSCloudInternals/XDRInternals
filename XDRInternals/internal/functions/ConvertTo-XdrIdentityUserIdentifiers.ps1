function ConvertTo-XdrIdentityUserIdentifiers {
    <#
    .SYNOPSIS
        Converts user identity data to the userIdentifiers payload.

    .DESCRIPTION
        Converts either a resolved user object or direct identifier inputs into the
        userIdentifiers object required by Microsoft Defender for Identity APIs.
        Only populated identifier properties are emitted.

    .PARAMETER AadId
        The Entra (Azure AD) object ID of the user.

    .PARAMETER Upn
        The user principal name of the user.

    .PARAMETER Sid
        The Security Identifier (SID) of the user.

    .PARAMETER RadiusUserId
        The RADIUS user ID in format "User_{tenantId}_{userId}".

    .PARAMETER AccountName
        The account name of the user.

    .PARAMETER AccountDomain
        The account domain of the user.

    .PARAMETER TenantId
        The tenant ID associated with the user.

    .PARAMETER ResolvedUser
        The resolved user object returned by Get-XdrIdentityUser or identity resolve APIs.
        Supports objects containing either `ids` or `results.ids`.

    .EXAMPLE
        ConvertTo-XdrIdentityUserIdentifiers -AadId 'a2307c5a-76df-4513-b575-0537842c1d8b'

        Builds a userIdentifiers payload using a direct Entra object ID.

    .EXAMPLE
        $user = Get-XdrIdentityUser -Upn 'user@contoso.com'
        ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $user

        Builds a userIdentifiers payload from a resolved identity user object.

    .OUTPUTS
        Hashtable
        Returns a userIdentifiers hashtable suitable for identity API requests.
    #>
    [OutputType([System.Collections.Hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Identifiers is a collection of identity properties, plural is intentional')]
    [CmdletBinding(DefaultParameterSetName = 'ByResolvedUser')]
    param(
        [Parameter(ParameterSetName = 'ByIdentifier')]
        [string]$AadId,

        [Parameter(ParameterSetName = 'ByIdentifier')]
        [string]$Upn,

        [Parameter(ParameterSetName = 'ByIdentifier')]
        [string]$Sid,

        [Parameter(ParameterSetName = 'ByIdentifier')]
        [string]$RadiusUserId,

        [Parameter(ParameterSetName = 'ByIdentifier')]
        [string]$AccountName,

        [Parameter(ParameterSetName = 'ByIdentifier')]
        [string]$AccountDomain,

        [Parameter(ParameterSetName = 'ByIdentifier')]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = 'ByResolvedUser', ValueFromPipeline)]
        [PSObject]$ResolvedUser
    )

    process {
        $candidateMap = @{}

        if ($PSCmdlet.ParameterSetName -eq 'ByResolvedUser') {
            # Prefer ids on the object, then nested results.ids response shape.
            $ids = if ($null -ne $ResolvedUser.ids) {
                $ResolvedUser.ids
            } elseif ($null -ne $ResolvedUser.results -and $null -ne $ResolvedUser.results.ids) {
                $ResolvedUser.results.ids
            } else {
                $ResolvedUser
            }

            $complexId = $null
            if ($null -ne $ids.complexId) {
                $complexId = @{}
                if ($null -ne $ids.complexId.id -and (-not ($ids.complexId.id -is [string]) -or -not [string]::IsNullOrWhiteSpace($ids.complexId.id))) {
                    $complexId['id'] = $ids.complexId.id
                }
                if ($null -ne $ids.complexId.saas) {
                    $complexId['saas'] = $ids.complexId.saas
                }
                if ($null -ne $ids.complexId.inst) {
                    $complexId['inst'] = $ids.complexId.inst
                }
                if ($complexId.Count -eq 0) {
                    $complexId = $null
                }
            }

            $candidateMap = @{
                thirdPartyProviderAccountId = $ids.thirdPartyProviderAccountId
                thirdPartyIdentityProvider  = $ids.thirdPartyIdentityProvider
                complexId                   = $complexId
                ad                          = $ids.ad
                aad                         = $ids.aad
                sid                         = $ids.sid
                cloudSid                    = $ids.cloudSid
                accountName                 = $ids.accountName
                accountDomain               = $ids.accountDomain
                sentinelUpn                 = $ids.sentinelUpn
                upn                         = $ids.upn
                armId                       = $ids.armId
                armIds                      = $ids.armIds
                sentinelWorkspaceId         = $ids.sentinelWorkspaceId
                radiusUserId                = $ids.radiusUserId
                tenantId                    = if ($ids.tenantId) { $ids.tenantId } elseif ($ResolvedUser.TenantId) { $ResolvedUser.TenantId } else { $null }
            }
        } else {
            if (-not [string]::IsNullOrWhiteSpace($AadId)) {
                $candidateMap['aad'] = $AadId
                $candidateMap['complexId'] = @{
                    id   = $AadId
                    saas = 11161
                    inst = 0
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($Upn)) {
                $candidateMap['upn'] = $Upn
            }

            if (-not [string]::IsNullOrWhiteSpace($Sid)) {
                $candidateMap['sid'] = $Sid
                $candidateMap['cloudSid'] = $Sid
            }

            if (-not [string]::IsNullOrWhiteSpace($RadiusUserId)) {
                $candidateMap['radiusUserId'] = $RadiusUserId
            }

            if (-not [string]::IsNullOrWhiteSpace($AccountName)) {
                $candidateMap['accountName'] = $AccountName
            }

            if (-not [string]::IsNullOrWhiteSpace($AccountDomain)) {
                $candidateMap['accountDomain'] = $AccountDomain
            }

            if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
                $candidateMap['tenantId'] = $TenantId
            }
        }

        $userIdentifiers = @{}
        foreach ($entry in $candidateMap.GetEnumerator()) {
            $value = $entry.Value

            if ($null -eq $value) {
                continue
            }

            if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) {
                continue
            }

            if ($value -is [array]) {
                if ($value.Count -eq 0) {
                    continue
                }
                $userIdentifiers[$entry.Key] = $value
                continue
            }

            if ($value -is [System.Collections.IDictionary] -and $value.Count -eq 0) {
                continue
            }

            $userIdentifiers[$entry.Key] = $value
        }

        if ($userIdentifiers.Count -eq 0) {
            throw 'No usable identity user identifiers were found.'
        }

        return $userIdentifiers
    }
}

