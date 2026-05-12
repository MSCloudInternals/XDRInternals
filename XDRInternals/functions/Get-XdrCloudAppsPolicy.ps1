function Get-XdrCloudAppsPolicy {
    <#
    .SYNOPSIS
        Retrieves policies from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        The Get-XdrCloudAppsPolicy cmdlet retrieves policies from Microsoft Defender for Cloud Apps.
        Policies help control and govern cloud application usage and data protection within your
        organization. You can filter, sort, and paginate the results using the available parameters.

        Use -Type to retrieve specific policy types (ConditionalAccess, File, InformationProtection,
        OAuth, ShadowIT, Template, ThreatDetection). Use -Metadata with -Type to get filter and field
        definitions for that policy type. Use -Setting to retrieve policy settings.

        For File and OAuth policies, additional options are available:
        - Use -PolicyId with -Type to retrieve a specific policy by ID
        - Use -Action with -Type File or -Type OAuth to get available actions
        - Use -PolicyLimit with -Type File to get file policy limits

    .PARAMETER Type
        The type of policies to retrieve. Valid values are:
        - ConditionalAccess: Policies controlling access based on conditions
        - File: File policies for data protection
        - InformationProtection: Policies protecting sensitive data
        - OAuth: OAuth app policies for third-party app governance
        - ShadowIT: Policies detecting unsanctioned cloud app usage
        - Template: Pre-configured policy templates
        - ThreatDetection: Policies identifying security threats

    .PARAMETER PolicyId
        The unique identifier of a specific policy to retrieve.
        If -Type is specified, retrieves from that policy type's endpoint.
        If -Type is not specified, attempts to discover the policy type automatically.

    .PARAMETER Metadata
        When specified with -Type, retrieves metadata including available filters, fields,
        and configuration options instead of the policies themselves.

    .PARAMETER Action
        When specified with -Type File or -Type OAuth, retrieves available actions
        that can be configured for those policy types.

    .PARAMETER PolicyLimit
        When specified with -Type File, retrieves file policy limits and constraints.

    .PARAMETER Setting
        When specified, retrieves policy settings configuration.

    .PARAMETER Limit
        The maximum number of policies to return. Default is 20.

    .PARAMETER Skip
        The number of policies to skip for pagination. Default is 0.

    .PARAMETER SortField
        The field to sort results by. Default is "severity".

    .PARAMETER SortDirection
        The sort direction. Valid values are "asc" or "desc". Default is "desc".

    .PARAMETER Filters
        A hashtable of filters to apply to the policies query.

    .PARAMETER Force
        Bypasses the cache and retrieves fresh data from the API.

    .EXAMPLE
        Get-XdrCloudAppsPolicy

        Retrieves all policies sorted by severity (highest first).

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type ConditionalAccess

        Retrieves conditional access policies.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type File

        Retrieves file policies.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type OAuth

        Retrieves OAuth app policies.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type File -PolicyId "abc123"

        Retrieves a specific file policy by ID.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -PolicyId "abc123"

        Retrieves a policy by ID, automatically discovering the policy type.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type ThreatDetection -Metadata

        Retrieves metadata for threat detection policies including available filters.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type OAuth -Metadata

        Retrieves metadata for OAuth policies including available filters.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type File -Action

        Retrieves available actions for file policies.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type OAuth -Action

        Retrieves available actions for OAuth policies.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type File -PolicyLimit

        Retrieves file policy limits and constraints.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type ShadowIT -Limit 50 -SortField "name" -SortDirection "asc"

        Retrieves 50 Shadow IT policies sorted by name ascending.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Type Template

        Retrieves policy templates.

    .EXAMPLE
        $filters = @{ "enabled" = @{ "eq" = @($true) } }
        Get-XdrCloudAppsPolicy -Type InformationProtection -Filters $filters

        Retrieves enabled information protection policies.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Setting

        Retrieves policy settings configuration.

    .EXAMPLE
        Get-XdrCloudAppsPolicy -Force

        Forces a fresh retrieval of all policies, bypassing the cache.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Typed', Mandatory = $true)]
        [Parameter(ParameterSetName = 'TypedMetadata', Mandatory = $true)]
        [Parameter(ParameterSetName = 'TypedAction', Mandatory = $true)]
        [Parameter(ParameterSetName = 'TypedPolicyLimit', Mandatory = $true)]
        [Parameter(ParameterSetName = 'TypedPolicyId', Mandatory = $true)]
        [ValidateSet("ConditionalAccess", "File", "InformationProtection", "OAuth", "ShadowIT", "Template", "ThreatDetection")]
        [string]$Type,

        [Parameter(ParameterSetName = 'TypedPolicyId', Mandatory = $true)]
        [Parameter(ParameterSetName = 'PolicyIdOnly', Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("_id", "Id")]
        [string]$PolicyId,

        [Parameter(ParameterSetName = 'TypedMetadata', Mandatory = $true)]
        [switch]$Metadata,

        [Parameter(ParameterSetName = 'TypedAction', Mandatory = $true)]
        [switch]$Action,

        [Parameter(ParameterSetName = 'TypedPolicyLimit', Mandatory = $true)]
        [switch]$PolicyLimit,

        [Parameter(ParameterSetName = 'Setting', Mandatory = $true)]
        [switch]$Setting,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Typed')]
        [ValidateRange(1, 5000)]
        [int]$Limit = 20,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Typed')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Typed')]
        [string]$SortField = "severity",

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Typed')]
        [ValidateSet("asc", "desc")]
        [string]$SortDirection = "desc",

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Typed')]
        [hashtable]$Filters = @{},

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        # Define URL mappings for policy types
        $typeUrlMap = @{
            "ConditionalAccess"     = "conditional_access"
            "File"                  = "file"
            "InformationProtection" = "information_protection"
            "OAuth"                 = "oauth"
            "ShadowIT"              = "shadow_it"
            "Template"              = "policy_templates_inmemo"
            "ThreatDetection"       = "threat_detection"
        }
    }

    process {
        # Handle Setting request
        if ($Setting) {
            $CacheKey = "XdrCloudAppsPolicySetting"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached policy settings"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/settings/"
            Write-Verbose "Retrieving policy settings from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                return $result
            } catch {
                Write-Error "Failed to retrieve policy settings: $_"
            }
            return
        }

        # Handle Action request for File or OAuth
        if ($Action) {
            if ($Type -eq "File") {
                $CacheKey = "XdrCloudAppsFilePolicyAction"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policy/file/actions/"
            } elseif ($Type -eq "OAuth") {
                $CacheKey = "XdrCloudAppsOAuthPolicyAction"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policy/app_permissions/actions/"
            } else {
                Write-Error "-Action is only supported with -Type File or -Type OAuth"
                return
            }

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached $Type policy actions"
                    return $cache.Value
                }
            }

            Write-Verbose "Retrieving $Type policy actions from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                return $result
            } catch {
                Write-Error "Failed to retrieve $Type policy actions: $_"
            }
            return
        }

        # Handle PolicyLimit request for File policies
        if ($PolicyLimit) {
            if ($Type -ne "File") {
                Write-Error "-PolicyLimit is only supported with -Type File"
                return
            }

            $CacheKey = "XdrCloudAppsFilePolicyLimit"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached file policy limits"
                    return $cache.Value
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policy/file/get_limit/"
            Write-Verbose "Retrieving file policy limits from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                return $result
            } catch {
                Write-Error "Failed to retrieve file policy limits: $_"
            }
            return
        }

        # Handle PolicyId request (with or without Type)
        if ($PSBoundParameters.ContainsKey('PolicyId')) {
            if ($PSBoundParameters.ContainsKey('Type')) {
                # Type is specified, use the correct endpoint directly
                if ($Type -eq "File") {
                    $CacheKey = "XdrCloudAppsFilePolicy_$PolicyId"
                    $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policy/file/$PolicyId/"
                    $typeName = "XdrCloudAppsPolicyFile"
                } else {
                    Write-Error "-PolicyId with -Type is currently only supported for File policies. For other types, omit -Type to use auto-discovery."
                    return
                }

                if (-not $Force) {
                    $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                    if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                        Write-Verbose "Returning cached $Type policy for PolicyId: $PolicyId"
                        return $cache.Value
                    }
                }

                Write-Verbose "Retrieving $Type policy from $Uri"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        if ($result -is [array]) {
                            foreach ($item in $result) {
                                $item.PSObject.TypeNames.Insert(0, $typeName)
                            }
                        } else {
                            $result.PSObject.TypeNames.Insert(0, $typeName)
                        }
                    }

                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                    return $result
                } catch {
                    Write-Error "Failed to retrieve $Type policy '$PolicyId': $_"
                }
                return
            } else {
                # Auto-discovery mode: try File endpoint first, then others
                $discoveryEndpoints = @(
                    @{ Type = "File"; Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policy/file/$PolicyId/"; TypeName = "XdrCloudAppsPolicyFile" }
                )

                foreach ($endpoint in $discoveryEndpoints) {
                    Write-Verbose "Attempting to discover policy $PolicyId as $($endpoint.Type) type"
                    try {
                        $response = Invoke-RestMethod -Uri $endpoint.Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers -ErrorAction Stop
                        $result = if ($null -ne $response.data) { $response.data } else { $response }
                        if ($null -ne $result) {
                            if ($result -is [array]) {
                                foreach ($item in $result) {
                                    $item.PSObject.TypeNames.Insert(0, $endpoint.TypeName)
                                }
                            } else {
                                $result.PSObject.TypeNames.Insert(0, $endpoint.TypeName)
                            }
                            Write-Verbose "Found policy $PolicyId as $($endpoint.Type) type"
                            return $result
                        }
                    } catch {
                        Write-Verbose "Policy $PolicyId not found as $($endpoint.Type) type, trying next..."
                        continue
                    }
                }

                Write-Error "Policy '$PolicyId' not found. Specify -Type to narrow the search or verify the PolicyId is correct."
                return
            }
        }

        # Handle Metadata request for typed policies
        if ($Metadata) {
            if ($Type -eq "File") {
                throw 'File policy metadata is not exposed by the live Cloud Apps API. Use Get-XdrCloudAppsPolicy -Type File for file policy data, or -Type File -Action / -PolicyLimit for supported file policy metadata surfaces.'
            }

            $CacheKey = "XdrCloudAppsPolicy${Type}Metadata"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached $Type policy metadata"
                    return $cache.Value
                }
            }

            $urlSegment = $typeUrlMap[$Type]

            # Different URL patterns for different types
            if ($Type -eq "Template") {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/${urlSegment}/metadata/"
            } elseif ($Type -eq "OAuth") {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policies/oauth/metadata/"
            } else {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policies/${urlSegment}/metadata/"
            }

            Write-Verbose "Retrieving $Type policy metadata from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                return $result
            } catch {
                Write-Error "Failed to retrieve $Type policy metadata: $_"
            }
            return
        }

        $effectiveFilters = @{}
        foreach ($filterKey in $Filters.Keys) {
            $effectiveFilters[$filterKey] = $Filters[$filterKey]
        }

        # Default: List policies (with or without Type filter)
        if ($PSBoundParameters.ContainsKey('Type')) {
            $urlSegment = $typeUrlMap[$Type]
            $typeName = "XdrCloudAppsPolicy$Type"

            if ($Type -eq "Template") {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/${urlSegment}/"
            } elseif ($Type -eq "OAuth") {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policies/oauth/"
            } elseif ($Type -eq "File") {
                # File policies use the general policies endpoint with type filter
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policies/"
                # Add file type filter (uses 'type' filter with string value 'FILE')
                if (-not $effectiveFilters.ContainsKey('type')) {
                    $effectiveFilters['type'] = @{ 'eq' = @('FILE') }
                }
            } else {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policies/${urlSegment}/"
            }
        } else {
            $typeName = "XdrCloudAppsPolicy"
            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/policies/"
        }

        # Create cache key based on parameters
        $filterHash = if ($effectiveFilters.Count -gt 0) { ($effectiveFilters | ConvertTo-Json -Compress) } else { "none" }
        $CacheKey = "${typeName}_${Limit}_${Skip}_${SortField}_${SortDirection}_${filterHash}"

        if (-not $Force) {
            $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Returning cached policies"
                return $cache.Value
            }
        }

        $body = @{
            filters           = $effectiveFilters
            limit             = $Limit
            performAsyncTotal = $true
            skip              = $Skip
            sortDirection     = $SortDirection
            sortField         = $SortField
        }

        $jsonBody = $body | ConvertTo-Json -Depth 10

        Write-Verbose "Retrieving policies from $Uri"
        Write-Verbose "Request body: $jsonBody"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                $result = $result | Add-XdrCloudAppsTypeName -TypeName $typeName
            }

            # Templates cache longer than policies
            $ttl = if ($Type -eq "Template") { 15 } else { 5 }
            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes $ttl

            return $result
        } catch {
            $policyType = if ($Type) { "$Type " } else { "" }
            Write-Error "Failed to retrieve ${policyType}policies: $_"
        }
    }
}
