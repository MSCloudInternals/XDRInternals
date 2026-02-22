function Get-XdrIdentityUser {
    <#
    .SYNOPSIS
        Retrieves detailed user identity information from Microsoft Defender for Identity.

    .DESCRIPTION
        Gets comprehensive user identity information by resolving identifiers across multiple
        workloads including Microsoft Graph, RADIUS, MCAS, MTP, MDI, and Sentinel.
        
        This cmdlet calls the user/resolve API to get full identity details including:
        - All user identifiers (AAD ID, SID, UPN, radiusUserId, complexId, armId)
        - User profile information (displayName, email, phone, department, jobTitle)
        - Security information (riskLevel, status, PIM roles)
        - Activity timestamps (firstSeen, lastSeen, created)
        
        The returned object can be piped to Get-XdrIdentityUserTimeline for timeline retrieval.

    .PARAMETER AadId
        The Azure AD object ID of the user.

    .PARAMETER Upn
        The User Principal Name (email address) of the user.

    .PARAMETER Sid
        The Security Identifier (SID) of the user.

    .PARAMETER RadiusUserId
        The RADIUS user ID in format "User_{tenantId}_{userId}".

    .PARAMETER Accounts
        Include cloud app accounts associated with the user (calls accounts API).

    .PARAMETER ActivityPeriod
        Include actual activity period from all workloads (calls activityPeriod API).
        Returns more accurate firstSeen/lastSeen than the base resolve response.

    .PARAMETER DevicesCount
        Include device counts (interactive, non-interactive) for the user.

    .PARAMETER Manager
        Include manager information if available.

    .PARAMETER Force
        Bypass cache and force a fresh API call.

    .EXAMPLE
        Get-XdrIdentityUser -Upn "nathan@contoso.com"
        
        Retrieves user identity information by UPN.

    .EXAMPLE
        Get-XdrIdentityUser -AadId "a2307c5a-76df-4513-b575-0537842c1d8b"
        
        Retrieves user identity information by Azure AD object ID.

    .EXAMPLE
        Get-XdrIdentityUser -Upn "nathan@contoso.com" -Accounts -ActivityPeriod
        
        Retrieves user identity with cloud app accounts and activity period details.

    .EXAMPLE
        Get-XdrIdentityUser -Upn "nathan@contoso.com" | Get-XdrIdentityUserTimeline -LastNDays 7
        
        Retrieves user identity and pipes to timeline cmdlet.

    .OUTPUTS
        XdrIdentityUser
        Returns a typed user identity object containing resolved identifiers and profile data.
        
    .NOTES
        The returned object contains an 'ids' property with all resolved identifiers that can
        be used with other identity cmdlets.
    #>
    [OutputType('XdrIdentityUser')]
    [CmdletBinding(DefaultParameterSetName = 'ByUpn')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByAadId', ValueFromPipelineByPropertyName)]
        [Alias('aad', 'ObjectId')]
        [string]$AadId,
        
        [Parameter(Mandatory, ParameterSetName = 'ByUpn', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('UserPrincipalName', 'Email')]
        [string]$Upn,
        
        [Parameter(Mandatory, ParameterSetName = 'BySid', ValueFromPipelineByPropertyName)]
        [string]$Sid,
        
        [Parameter(Mandatory, ParameterSetName = 'ByRadiusUserId', ValueFromPipelineByPropertyName)]
        [string]$RadiusUserId,
        
        [Parameter()]
        [switch]$Accounts,
        
        [Parameter()]
        [switch]$ActivityPeriod,
        
        [Parameter()]
        [switch]$DevicesCount,
        
        [Parameter()]
        [switch]$Manager,
        
        [Parameter()]
        [switch]$Force
    )
    
    begin {
        Update-XdrConnectionSettings

        # Build headers with tenant-id and m-* headers required for MDI APIs
        $tenantIdCache = Get-XdrCache -CacheKey "XdrTenantId" -ErrorAction SilentlyContinue
        $tenantId = if ($tenantIdCache) { $tenantIdCache.Value } else { $null }
        
        $mdiHeaders = @{}
        foreach ($key in $script:headers.Keys) {
            $mdiHeaders[$key] = $script:headers[$key]
        }
        if ($tenantId) {
            $mdiHeaders["tenant-id"] = $tenantId
        }
        # Additional headers required by MDI identity API
        $mdiHeaders["accept-language"] = "en-us"
        $mdiHeaders["m-package"] = "identities"
        $mdiHeaders["m-type"] = "Page"
        $mdiHeaders["m-name"] = "UserPageRouteResolver[identities]"
        $mdiHeaders["m-componentName"] = "UserPageRouteResolver"
        $mdiHeaders["x-clientpage"] = "user@msec-identities"
        
        # Available workloads for resolve API
        $workloads = @("graph", "radius", "mcas", "mtp", "mdi", "sentinel")
    }
    
    process {
        # Build userIdentifiers based on parameter set
        $userIdentifiers = @{}
        
        switch ($PSCmdlet.ParameterSetName) {
            'ByAadId' {
                $userIdentifiers['aad'] = $AadId
                $cacheKey = "XdrIdentityUser_aad_$AadId"
            }
            'ByUpn' {
                $userIdentifiers['upn'] = $Upn
                $cacheKey = "XdrIdentityUser_upn_$Upn"
            }
            'BySid' {
                $userIdentifiers['sid'] = $Sid
                $cacheKey = "XdrIdentityUser_sid_$Sid"
            }
            'ByRadiusUserId' {
                $userIdentifiers['radiusUserId'] = $RadiusUserId
                $cacheKey = "XdrIdentityUser_radius_$RadiusUserId"
            }
        }
        
        # Check cache unless Force is specified
        if (-not $Force) {
            $cached = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
            if ($cached -and $cached.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Returning cached user identity for $cacheKey"
                $user = $cached.Value
                
                # If enrichment switches are specified, we still need to call those APIs
                if (-not ($Accounts -or $ActivityPeriod -or $DevicesCount -or $Manager)) {
                    return $user
                }
            }
        }
        
        # Call the resolve API
        $resolveUri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/user/resolve"
        $resolveBody = @{
            workloads       = $workloads
            userIdentifiers = $userIdentifiers
        }
        
        Write-Verbose "Resolving user identity via $resolveUri"
        Write-Verbose "Request body: $($resolveBody | ConvertTo-Json -Depth 5 -Compress)"
        
        try {
            $response = Invoke-RestMethod -Uri $resolveUri `
                -Method POST `
                -ContentType "application/json" `
                -Body ($resolveBody | ConvertTo-Json -Depth 10) `
                -WebSession $script:session `
                -Headers $mdiHeaders `
                -ErrorAction Stop
            
            if (-not $response -or -not $response.results) {
                Write-Warning "User resolve API returned empty response for identifier: $($userIdentifiers | ConvertTo-Json -Compress)"
                return
            }
            
            # Build the user object from results
            $user = $response.results
            
            # Add top-level errors and workloads info
            $user | Add-Member -NotePropertyName 'resolveErrors' -NotePropertyValue $response.errors -Force
            $user | Add-Member -NotePropertyName 'resolveWorkloads' -NotePropertyValue $response.workloads -Force
            
            # Add PSTypeName for formatting
            $user.PSObject.TypeNames.Insert(0, 'XdrIdentityUser')
            
        } catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            
            Write-Error "Failed to resolve user identity. Status: $statusCode. Error: $_"
            return
        }
        
        # Get the full userIdentifiers for enrichment API calls
        $fullIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $user
        
        # Enrichment: Accounts
        if ($Accounts) {
            Write-Verbose "Fetching cloud app accounts..."
            $accountsUri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/accounts"
            $accountsBody = @{
                userIdentifiers = $fullIdentifiers
            }
            
            try {
                $accountsResponse = Invoke-RestMethod -Uri $accountsUri `
                    -Method POST `
                    -ContentType "application/json" `
                    -Body ($accountsBody | ConvertTo-Json -Depth 10) `
                    -WebSession $script:session `
                    -Headers $mdiHeaders `
                    -ErrorAction Stop
                
                $user | Add-Member -NotePropertyName 'accounts' -NotePropertyValue $accountsResponse.results -Force
                $user | Add-Member -NotePropertyName 'accountsWorkloads' -NotePropertyValue $accountsResponse.workloads -Force
            } catch {
                Write-Warning "Failed to retrieve accounts: $_"
                $user | Add-Member -NotePropertyName 'accounts' -NotePropertyValue @() -Force
            }
        }
        
        # Enrichment: Activity Period
        if ($ActivityPeriod) {
            Write-Verbose "Fetching activity period..."
            $activityUri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/user/activityPeriod"
            $activityBody = @{
                CurrentFirstSeen = $user.firstSeen
                CurrentLastSeen  = $user.lastSeen
                UserIdentifiers  = $fullIdentifiers
            }
            
            try {
                $activityResponse = Invoke-RestMethod -Uri $activityUri `
                    -Method POST `
                    -ContentType "application/json" `
                    -Body ($activityBody | ConvertTo-Json -Depth 10) `
                    -WebSession $script:session `
                    -Headers $mdiHeaders `
                    -ErrorAction Stop
                
                $user | Add-Member -NotePropertyName 'activityPeriod' -NotePropertyValue $activityResponse.results -Force
                $user | Add-Member -NotePropertyName 'activityPeriodWorkloads' -NotePropertyValue $activityResponse.workloads -Force
                
                # Update firstSeen/lastSeen with more accurate values
                if ($activityResponse.results.firstSeen) {
                    $user.firstSeen = $activityResponse.results.firstSeen
                }
                if ($activityResponse.results.lastSeen) {
                    $user.lastSeen = $activityResponse.results.lastSeen
                }
            } catch {
                Write-Warning "Failed to retrieve activity period: $_"
            }
        }
        
        # Enrichment: Devices Count
        if ($DevicesCount) {
            Write-Verbose "Fetching devices count..."
            $devicesUri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/devices/count"
            $devicesBody = @{
                userIdentifiers      = $fullIdentifiers
                adServiceAccountType = $user.adServiceAccountType
                filters              = @{}
                limit                = 1000
            }
            
            try {
                $devicesResponse = Invoke-RestMethod -Uri $devicesUri `
                    -Method POST `
                    -ContentType "application/json" `
                    -Body ($devicesBody | ConvertTo-Json -Depth 10) `
                    -WebSession $script:session `
                    -Headers $mdiHeaders `
                    -ErrorAction Stop
                
                $user | Add-Member -NotePropertyName 'devicesCount' -NotePropertyValue $devicesResponse.results -Force
            } catch {
                Write-Warning "Failed to retrieve devices count: $_"
            }
        }
        
        # Enrichment: Manager
        if ($Manager) {
            Write-Verbose "Fetching manager information..."
            $managerUri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/manager?managerAd=$($user.managerId)&userAad=$($user.ids.aad)"
            
            try {
                $managerResponse = Invoke-RestMethod -Uri $managerUri `
                    -Method GET `
                    -ContentType "application/json" `
                    -WebSession $script:session `
                    -Headers $mdiHeaders `
                    -ErrorAction Stop
                
                if ($managerResponse.results -and $managerResponse.results.displayName) {
                    $user | Add-Member -NotePropertyName 'managerInfo' -NotePropertyValue $managerResponse.results -Force
                } else {
                    $user | Add-Member -NotePropertyName 'managerInfo' -NotePropertyValue $null -Force
                }
            } catch {
                Write-Warning "Failed to retrieve manager: $_"
                $user | Add-Member -NotePropertyName 'managerInfo' -NotePropertyValue $null -Force
            }
        }
        
        # Cache the result (10 minute TTL)
        Set-XdrCache -CacheKey $cacheKey -Value $user -TTLMinutes 10
        
        return $user
    }
}
