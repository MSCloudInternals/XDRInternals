Set-StrictMode -Version Latest

$script:XdrTestSettings = $null
$script:XdrTestSettingsPath = $null
$script:XdrConnectionEstablished = $false
$script:XdrWorkloadStatus = $null
$script:XdrFixtureCache = @{}

function ConvertTo-XdrHashtable {
    param (
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [hashtable]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-XdrHashtable -InputObject $InputObject[$key]
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-XdrHashtable -InputObject $InputObject[$key]
        }
        return $result
    }

    if ($InputObject -is [psobject] -and @($InputObject.PSObject.Properties).Count -gt 0) {
        $result = @{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $result[$property.Name] = ConvertTo-XdrHashtable -InputObject $property.Value
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += , (ConvertTo-XdrHashtable -InputObject $item)
        }
        return $items
    }

    return $InputObject
}

function Merge-XdrHashtable {
    param (
        [hashtable]$Base,
        [hashtable]$Overlay
    )

        foreach ($key in $Overlay.Keys) {
        if ($Base.ContainsKey($key) -and $Base[$key] -is [hashtable] -and $Overlay[$key] -is [hashtable]) {
            $null = Merge-XdrHashtable -Base $Base[$key] -Overlay $Overlay[$key]
            continue
        }

        $Base[$key] = $Overlay[$key]
    }

    return $Base
}

function ConvertTo-XdrBoolean {
    param (
        $Value
    )

    if ($Value -is [bool]) {
        return $Value
    }

    if ($Value -is [int]) {
        return ($Value -ne 0)
    }

    if ($Value -is [string]) {
        switch -Regex ($Value.Trim()) {
            '^(1|true|yes|on)$' { return $true }
            '^(0|false|no|off)$' { return $false }
        }
    }

    return [bool]$Value
}

function Get-XdrRepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Resolve-XdrTestPath {
    param (
        [string]$Path,
        [string]$BasePath = (Get-XdrRepoRoot)
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $candidatePaths = [System.Collections.Generic.List[string]]::new()
    if ([System.IO.Path]::IsPathRooted($Path)) {
        $candidatePaths.Add($Path)
    } else {
        if ($BasePath) {
            $candidatePaths.Add((Join-Path $BasePath $Path))
        }

        $repoRoot = Get-XdrRepoRoot
        $repoRelativeCandidate = Join-Path $repoRoot $Path
        if ($candidatePaths -notcontains $repoRelativeCandidate) {
            $candidatePaths.Add($repoRelativeCandidate)
        }
    }

    foreach ($candidatePath in $candidatePaths) {
        if (-not (Test-Path $candidatePath)) {
            continue
        }

        return (Resolve-Path $candidatePath).Path
    }

    return $candidatePaths | Select-Object -First 1
}

function Get-XdrDefaultTestSettings {
    return @{
        liveTests      = @{
            enabled = $false
        }
        authentication = @{
            mode               = 'SoftwarePasskey'
            keyFilePath        = ''
            tenantId           = ''
            keyVaultTenantId   = ''
            keyVaultClientId   = ''
            keyVaultApiVersion = '7.4'
            userAgent          = ''
        }
        execution      = @{
            enableMutationTests          = $false
            requireFullParameterCoverage = $false
            defaultTop                   = 1
            defaultPageSize              = 1
            skipCmdlets                  = @()
        }
        fixtures       = @{}
        scenarios      = @{}
    }
}

function Get-XdrTestSettings {
    if ($script:XdrTestSettings) {
        return $script:XdrTestSettings
    }

    $repoRoot = Get-XdrRepoRoot
    $settings = Get-XdrDefaultTestSettings

    $candidatePaths = @()
    if ($env:XDRINTERNALS_TEST_CONFIG_PATH) {
        $candidatePaths += $env:XDRINTERNALS_TEST_CONFIG_PATH
    }
    $candidatePaths += (Join-Path $repoRoot 'tests\live.settings.json')
    $candidatePaths += (Join-Path $repoRoot 'tests\live.settings.sample.json')

    foreach ($candidate in $candidatePaths) {
        if (-not (Test-Path $candidate)) {
            continue
        }

        $script:XdrTestSettingsPath = (Resolve-Path $candidate).Path
        $fileSettings = Get-Content $script:XdrTestSettingsPath -Raw | ConvertFrom-Json
        $fileSettings = ConvertTo-XdrHashtable -InputObject $fileSettings
        $settings = Merge-XdrHashtable -Base $settings -Overlay $fileSettings
        break
    }

    if ($env:XDRINTERNALS_ENABLE_LIVE_TESTS) {
        $settings['liveTests']['enabled'] = ConvertTo-XdrBoolean $env:XDRINTERNALS_ENABLE_LIVE_TESTS
    }

    if ($env:XDRINTERNALS_ENABLE_MUTATION_TESTS) {
        $settings['execution']['enableMutationTests'] = ConvertTo-XdrBoolean $env:XDRINTERNALS_ENABLE_MUTATION_TESTS
    }

    if ($env:XDRINTERNALS_TEST_KEYFILE) {
        $settings['authentication']['keyFilePath'] = $env:XDRINTERNALS_TEST_KEYFILE
    }

    if ($env:XDRINTERNALS_TEST_TENANT_ID) {
        $settings['authentication']['tenantId'] = $env:XDRINTERNALS_TEST_TENANT_ID
    }

    if ($env:XDRINTERNALS_TEST_KEYVAULT_TENANT_ID) {
        $settings['authentication']['keyVaultTenantId'] = $env:XDRINTERNALS_TEST_KEYVAULT_TENANT_ID
    }

    if ($env:XDRINTERNALS_TEST_KEYVAULT_CLIENT_ID) {
        $settings['authentication']['keyVaultClientId'] = $env:XDRINTERNALS_TEST_KEYVAULT_CLIENT_ID
    }

    if ($env:XDRINTERNALS_TEST_USER_AGENT) {
        $settings['authentication']['userAgent'] = $env:XDRINTERNALS_TEST_USER_AGENT
    }

    if ($env:XDRINTERNALS_TEST_SKIP_CMDLETS) {
        $settings['execution']['skipCmdlets'] = @(
            $env:XDRINTERNALS_TEST_SKIP_CMDLETS -split ',' |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ }
        )
    }

    $script:XdrTestSettings = $settings
    return $script:XdrTestSettings
}

function Get-XdrPublicCommands {
    $repoRoot = Get-XdrRepoRoot
    $manifest = Import-PowerShellDataFile (Join-Path $repoRoot 'XDRInternals\XDRInternals.psd1')
    return @(
        $manifest.FunctionsToExport |
            Sort-Object |
            ForEach-Object { Get-Command $_ -ErrorAction Stop }
    )
}

function Get-XdrRequiredWorkload {
    param (
        [string]$CommandName
    )

    if ($CommandName -match '^Get-XdrCloudApps' -or $CommandName -match '^Set-XdrConfigurationPreviewFeatures$') {
        return 'IsMdaActive'
    }

    if ($CommandName -match '^Get-XdrIdentity' -or $CommandName -match '^New-XdrIdentity' -or $CommandName -match '^Remove-XdrIdentity' -or $CommandName -match '^Set-XdrIdentity') {
        return 'IsMdiActive'
    }

    if ($CommandName -match '^Get-Xdr(Endpoint|ActionsCenter|ThreatAnalytics|ExposureManagement|VulnerabilityManagement)' -or
        $CommandName -match '^Set-XdrEndpoint' -or
        $CommandName -match '^New-XdrEndpoint' -or
        $CommandName -match '^Move-XdrAlert' -or
        $CommandName -match '^Merge-XdrIncident') {
        return 'IsMdeActive'
    }

    return $null
}

function Test-XdrCommandRequiresMutationOptIn {
    param (
        [System.Management.Automation.CommandInfo]$Command
    )

    if ($Command.Name -match '^(New|Set|Remove|Move|Merge)-Xdr') {
        return $true
    }

    return $Command.Name -in @(
        'Invoke-XdrEndpointDeviceAction',
        'Invoke-XdrEndpointDeviceAutomatedInvestigation',
        'Invoke-XdrEndpointDeviceLiveResponseCommand',
        'Invoke-XdrEndpointDevicePolicySync',
        'Invoke-XdrRestMethod'
    )
}

function Get-XdrWorkloadStatusTable {
    if ($script:XdrWorkloadStatus) {
        return $script:XdrWorkloadStatus
    }

    try {
        $status = Get-XdrTenantWorkloadStatus -ErrorAction Stop
        $table = @{}
        foreach ($item in $status) {
            $table[$item.WorkloadName] = [bool]$item.IsActive
            $table[$item.OriginalProperty] = [bool]$item.IsActive
        }
        $script:XdrWorkloadStatus = $table
    } catch {
        $script:XdrWorkloadStatus = @{}
    }

    return $script:XdrWorkloadStatus
}

function Connect-XdrForTests {
    $settings = Get-XdrTestSettings
    if (-not $settings['liveTests']['enabled']) {
        return $false
    }

    if ($script:XdrConnectionEstablished) {
        return $true
    }

    if ($settings['authentication']['mode'] -ne 'SoftwarePasskey') {
        throw "Unsupported authentication mode '$($settings['authentication']['mode'])'. The test suite currently supports only 'SoftwarePasskey'."
    }

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "Live tests with Connect-XdrBySoftwarePasskey require PowerShell 7 or later."
    }

    $basePath = if ($script:XdrTestSettingsPath) {
        Split-Path -Parent $script:XdrTestSettingsPath
    } else {
        Get-XdrRepoRoot
    }

    $keyFilePath = Resolve-XdrTestPath -Path $settings['authentication']['keyFilePath'] -BasePath $basePath
    $connectParams = @{
        KeyFilePath = $keyFilePath
        ErrorAction = 'Stop'
    }

    if ($settings['authentication']['tenantId']) {
        $connectParams.TenantId = $settings['authentication']['tenantId']
    }
    if ($settings['authentication']['keyVaultTenantId']) {
        $connectParams.KeyVaultTenantId = $settings['authentication']['keyVaultTenantId']
    }
    if ($settings['authentication']['keyVaultClientId']) {
        $connectParams.KeyVaultClientId = $settings['authentication']['keyVaultClientId']
    }
    if ($settings['authentication']['keyVaultApiVersion']) {
        $connectParams.KeyVaultApiVersion = $settings['authentication']['keyVaultApiVersion']
    }
    if ($settings['authentication']['userAgent']) {
        $connectParams.UserAgent = $settings['authentication']['userAgent']
    }

    Connect-XdrBySoftwarePasskey @connectParams | Out-Null
    $script:XdrConnectionEstablished = $true
    $null = Get-XdrWorkloadStatusTable
    return $true
}

function Get-XdrSequenceItems {
    param (
        $InputObject
    )

    if ($null -eq $InputObject) {
        return @()
    }

    if ($InputObject -is [string]) {
        return @($InputObject)
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return @($InputObject)
    }

    if ($InputObject.PSObject.Properties.Match('results').Count -gt 0) {
        return @($InputObject.results)
    }

    if ($InputObject.PSObject.Properties.Match('items').Count -gt 0) {
        return @($InputObject.items)
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        return @($InputObject)
    }

    return @($InputObject)
}

function Get-XdrFirstPropertyValue {
    param (
        $InputObject,
        [string[]]$PropertyNames
    )

    $first = Get-XdrSequenceItems -InputObject $InputObject | Select-Object -First 1
    if ($null -eq $first) {
        return $null
    }

    foreach ($propertyName in $PropertyNames) {
        $match = $first.PSObject.Properties.Match($propertyName)
        if ($match.Count -gt 0) {
            return $match[0].Value
        }
    }

    return $null
}

function Get-XdrFixtureValue {
    param (
        [string]$CommandName,
        [string]$ParameterName
    )

    $cacheKey = "$CommandName::$ParameterName"
    if ($script:XdrFixtureCache.ContainsKey($cacheKey)) {
        return $script:XdrFixtureCache[$cacheKey]
    }

    $settings = Get-XdrTestSettings
    if ($settings['fixtures'].ContainsKey($ParameterName) -and $null -ne $settings['fixtures'][$ParameterName]) {
        $script:XdrFixtureCache[$cacheKey] = $settings['fixtures'][$ParameterName]
        return $script:XdrFixtureCache[$cacheKey]
    }

    $identityFixture = $null
    function Get-IdentityFixture {
        if ($script:XdrFixtureCache.ContainsKey('IdentityFixture')) {
            return $script:XdrFixtureCache['IdentityFixture']
        }

        $identityLookup = @{}
        foreach ($candidateKey in @('Upn', 'AadId', 'RadiusUserId', 'Sid')) {
            if (-not $settings['fixtures'].ContainsKey($candidateKey)) {
                continue
            }

            $candidateValue = $settings['fixtures'][$candidateKey]
            if ([string]::IsNullOrWhiteSpace([string]$candidateValue)) {
                continue
            }

            $identityLookup[$candidateKey] = $candidateValue
        }

        if ($identityLookup.Count -eq 0) {
            $script:XdrFixtureCache['IdentityFixture'] = $null
            return $null
        }

        try {
            if ($identityLookup.ContainsKey('Upn')) {
                $script:XdrFixtureCache['IdentityFixture'] = Get-XdrIdentityUser -Upn $identityLookup['Upn'] -ErrorAction Stop
            } elseif ($identityLookup.ContainsKey('AadId')) {
                $script:XdrFixtureCache['IdentityFixture'] = Get-XdrIdentityUser -AadId $identityLookup['AadId'] -ErrorAction Stop
            } elseif ($identityLookup.ContainsKey('RadiusUserId')) {
                $script:XdrFixtureCache['IdentityFixture'] = Get-XdrIdentityUser -RadiusUserId $identityLookup['RadiusUserId'] -ErrorAction Stop
            } elseif ($identityLookup.ContainsKey('Sid')) {
                $script:XdrFixtureCache['IdentityFixture'] = Get-XdrIdentityUser -Sid $identityLookup['Sid'] -ErrorAction Stop
            }
        } catch {
            $script:XdrFixtureCache['IdentityFixture'] = $null
        }

        return $script:XdrFixtureCache['IdentityFixture']
    }

    try {
        $value = switch ($ParameterName) {
            'Upn' {
                $identityFixture = Get-IdentityFixture
                if ($identityFixture) {
                    Get-XdrFirstPropertyValue -InputObject $identityFixture -PropertyNames @('userPrincipalName', 'email')
                }
            }
            'AadId' {
                $identityFixture = Get-IdentityFixture
                if ($identityFixture) {
                    $aadIdValue = Get-XdrFirstPropertyValue -InputObject $identityFixture -PropertyNames @('AadId', 'aadId', 'aad', 'objectId')
                    if (-not $aadIdValue) {
                        $aadIdValue = Get-XdrFirstPropertyValue -InputObject $identityFixture.ids -PropertyNames @('aad')
                    }
                    $aadIdValue
                }
            }
            'Sid' {
                $identityFixture = Get-IdentityFixture
                if ($identityFixture) {
                    Get-XdrFirstPropertyValue -InputObject $identityFixture.ids -PropertyNames @('sid', 'cloudSid')
                }
            }
            'RadiusUserId' {
                $identityFixture = Get-IdentityFixture
                if ($identityFixture) {
                    Get-XdrFirstPropertyValue -InputObject $identityFixture.ids -PropertyNames @('radiusUserId')
                }
            }
            'IncidentId' {
                $incident = Get-XdrIncident | Select-Object -First 1
                Get-XdrFirstPropertyValue -InputObject $incident -PropertyNames @('IncidentId', 'incidentId', 'Id', 'id')
            }
            'TargetIncidentId' {
                $incident = Get-XdrIncident | Select-Object -First 1
                Get-XdrFirstPropertyValue -InputObject $incident -PropertyNames @('IncidentId', 'incidentId', 'Id', 'id')
            }
            'DeviceId' {
                $device = Get-XdrEndpointDevice -PageSize 1 | Select-Object -First 1
                $deviceId = Get-XdrFirstPropertyValue -InputObject $device -PropertyNames @('MachineId', 'machineId', 'DeviceId', 'deviceId', 'Id', 'id')
                if (-not $deviceId) {
                    $incident = Get-XdrIncident | Select-Object -First 1
                    $deviceId = Get-XdrFirstPropertyValue -InputObject $incident -PropertyNames @('SenseMachineId', 'senseMachineId')
                }
                $deviceId
            }
            'MachineDnsName' {
                $device = Get-XdrEndpointDevice -PageSize 1 | Select-Object -First 1
                $machineDnsName = Get-XdrFirstPropertyValue -InputObject $device -PropertyNames @('MachineDnsName', 'machineDnsName', 'ComputerDnsName')
                if (-not $machineDnsName) {
                    $incident = Get-XdrIncident | Select-Object -First 1
                    $machineDnsName = Get-XdrFirstPropertyValue -InputObject $incident -PropertyNames @('ComputerDnsName', 'computerDnsName')
                }
                $machineDnsName
            }
            'RecommendationId' {
                $recommendations = Get-XdrExposureManagementRecommendations -Top 1 | Select-Object -First 1
                Get-XdrFirstPropertyValue -InputObject $recommendations -PropertyNames @('RecommendationId', 'recommendationId', 'Id', 'id')
            }
            'ProfileId' {
                $profiles = Get-XdrVulnerabilityManagementBaseline -Profiles -Top 1 | Select-Object -First 1
                Get-XdrFirstPropertyValue -InputObject $profiles -PropertyNames @('ProfileId', 'profileId', 'Id', 'id')
            }
            'ExtensionId' {
                $extensions = Get-XdrVulnerabilityManagementExtensions -Top 1 | Select-Object -First 1
                Get-XdrFirstPropertyValue -InputObject $extensions -PropertyNames @('ExtensionId', 'extensionId', 'Id', 'id')
            }
            'TargetSoftware' {
                $extensions = Get-XdrVulnerabilityManagementExtensions -Top 1 | Select-Object -First 1
                Get-XdrFirstPropertyValue -InputObject $extensions -PropertyNames @('TargetSoftware', 'targetSoftware', 'Browser', 'browser')
            }
            'AlertIds' {
                $alerts = Get-XdrAlert -PageSize 1 | Select-Object -First 1
                $alertId = Get-XdrFirstPropertyValue -InputObject $alerts -PropertyNames @('Id', 'id', 'AlertId', 'alertId')
                if (-not $alertId) {
                    $incidents = Get-XdrIncident | Select-Object -First 1
                    if ($incidents) {
                        $associatedAlert = Get-XdrIncidentAssociatedAlert -IncidentId $incidents.IncidentId | Select-Object -First 1
                        $alertId = Get-XdrFirstPropertyValue -InputObject $associatedAlert -PropertyNames @('Id', 'id', 'AlertId', 'alertId')
                    }
                }
                if ($alertId) { @($alertId) } else { $null }
            }
            'IncidentIds' {
                $incidents = @(Get-XdrIncident | Select-Object -First 2)
                if ($incidents.Count -ge 2) {
                    @(
                        foreach ($incident in $incidents) {
                            Get-XdrFirstPropertyValue -InputObject $incident -PropertyNames @('IncidentId', 'incidentId', 'Id', 'id')
                        }
                    )
                }
            }
            'Id' {
                switch ($CommandName) {
                    'Remove-XdrAdvancedHuntingFunction' {
                        $function = Get-XdrAdvancedHuntingFunction | Select-Object -First 1
                        Get-XdrFirstPropertyValue -InputObject $function -PropertyNames @('Id', 'id')
                    }
                    'Set-XdrAdvancedHuntingFunction' {
                        $function = Get-XdrAdvancedHuntingFunction | Select-Object -First 1
                        Get-XdrFirstPropertyValue -InputObject $function -PropertyNames @('Id', 'id')
                    }
                    'Remove-XdrIdentityConfigurationRemediationActionAccount' {
                        $account = Get-XdrIdentityConfigurationRemediationActionAccount | Select-Object -First 1
                        Get-XdrFirstPropertyValue -InputObject $account -PropertyNames @('Id', 'id')
                    }
                    default {
                        $null
                    }
                }
            }
            'RuleId' {
                switch ($CommandName) {
                    'Remove-XdrConfigurationCriticalAssetManagementClassification' {
                        $rule = Get-XdrConfigurationCriticalAssetManagementClassification | Where-Object { $_.RuleType -ne 'Predefined' } | Select-Object -First 1
                        Get-XdrFirstPropertyValue -InputObject $rule -PropertyNames @('RuleId', 'ruleId', 'Id', 'id')
                    }
                    'Set-XdrConfigurationCriticalAssetManagementClassification' {
                        $rule = Get-XdrConfigurationCriticalAssetManagementClassification | Select-Object -First 1
                        Get-XdrFirstPropertyValue -InputObject $rule -PropertyNames @('RuleId', 'ruleId', 'Id', 'id')
                    }
                    'Set-XdrEndpointConfigurationCustomCollectionRule' {
                        $rule = Get-XdrEndpointConfigurationCustomCollectionRule | Select-Object -First 1
                        Get-XdrFirstPropertyValue -InputObject $rule -PropertyNames @('RuleId', 'ruleId', 'Id', 'id')
                    }
                    default {
                        $null
                    }
                }
            }
            'InputObject' {
                switch ($CommandName) {
                    'Get-XdrIdentityUserTimeline' {
                        Get-IdentityFixture
                    }
                    'Remove-XdrAdvancedHuntingFunction' {
                        Get-XdrAdvancedHuntingFunction | Select-Object -First 1
                    }
                    'Set-XdrAdvancedHuntingFunction' {
                        Get-XdrAdvancedHuntingFunction | Select-Object -First 1
                    }
                    'Remove-XdrConfigurationCriticalAssetManagementClassification' {
                        Get-XdrConfigurationCriticalAssetManagementClassification | Where-Object { $_.RuleType -ne 'Predefined' } | Select-Object -First 1
                    }
                    'Set-XdrConfigurationCriticalAssetManagementClassification' {
                        Get-XdrConfigurationCriticalAssetManagementClassification | Select-Object -First 1
                    }
                    'Set-XdrEndpointConfigurationCustomCollectionRule' {
                        Get-XdrEndpointConfigurationCustomCollectionRule | Select-Object -First 1
                    }
                    default {
                        $null
                    }
                }
            }
            'FilePath' {
                Resolve-XdrTestPath -Path 'tests/assets/custom-collection-rule.sample.yaml'
            }
            'RuleName' {
                if ($CommandName -eq 'New-XdrConfigurationCriticalAssetManagementClassification') {
                    'Pester Smoke Rule'
                } else {
                    $null
                }
            }
            'RuleDescription' { 'Pester validation rule' }
            'AssetType' { 'Devices' }
            'CriticalityLevel' { 'Low' }
            'Property' { 'Tags' }
            'Operator' { 'Contains' }
            'Value' { @('PesterSmoke') }
            'RuleDefinition' {
                @{
                    conditionType   = 'Operational'
                    logicalOperator = 'AND'
                    conditions      = @(
                        @{
                            conditionType = 'Simple'
                            predicate     = @{
                                property = 'Tags'
                                operator = 'Contains'
                                value    = @('PesterSmoke')
                            }
                        }
                    )
                }
            }
            'GroupObject' {
                [pscustomobject]@{
                    id          = ''
                    name        = 'Pester Smoke Device Group'
                    description = 'Pester validation group'
                    Priority    = 0
                    machinesRule = @(
                        [pscustomobject]@{
                            id        = [guid]::NewGuid().Guid
                            ruleType  = 'computerDnsName'
                            operation = 'startsWith'
                            value     = 'pester-smoke'
                        }
                    )
                }
            }
            'Body' {
                if ($CommandName -eq 'Get-XdrVulnerabilityManagementRemediationTasks') {
                    @{
                        groups             = @()
                        modelName          = 'PreRemediationRequestBodyModel'
                        preRemediationArgs = @{
                            category                              = 'SecurityConfiguration'
                            modelName                            = 'PreRemediationArgsModel'
                            preRemediationSecurityConfigurationArgs = @{
                                modelName = 'PreRemediationSecurityConfigurationArgsModel'
                                scid      = 'scid-79'
                                taskType  = 'ConfigurationChange'
                            }
                        }
                        relatedComponent   = 'deviceMisconfiguration'
                    }
                } else {
                    $null
                }
            }
            default {
                $null
            }
        }
    } catch {
        $value = $null
    }

    $script:XdrFixtureCache[$cacheKey] = $value
    return $value
}

function Test-XdrParameterAvailableInSet {
    param (
        [System.Management.Automation.CommandInfo]$Command,
        [string]$ParameterName,
        [string]$ParameterSetName
    )

    if ($ParameterSetName -eq '__AllParameterSets') {
        return $Command.Parameters.ContainsKey($ParameterName)
    }

    $parameterSet = $Command.ParameterSets | Where-Object Name -eq $ParameterSetName | Select-Object -First 1
    if ($null -eq $parameterSet) {
        return $false
    }

    return [bool]($parameterSet.Parameters | Where-Object Name -eq $ParameterName)
}

function Get-XdrSelectorSwitch {
    param (
        [System.Management.Automation.CommandInfo]$Command,
        [string]$ParameterSetName
    )

    if ($ParameterSetName -eq '__AllParameterSets') {
        return $null
    }

    $targetSet = $Command.ParameterSets | Where-Object Name -eq $ParameterSetName | Select-Object -First 1
    if ($null -eq $targetSet) {
        return $null
    }

    $commonParameters = @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'WhatIf', 'Confirm')

    $totalParameterSetCount = @($Command.ParameterSets).Count
    $candidateSwitches = [System.Collections.Generic.List[object]]::new()

    foreach ($parameter in $targetSet.Parameters) {
        if ($commonParameters -contains $parameter.Name) {
            continue
        }

        if ($parameter.ParameterType -ne [System.Management.Automation.SwitchParameter]) {
            continue
        }

        if ($parameter.IsMandatory) {
            continue
        }

        $availabilityCount = @(
            $Command.ParameterSets |
                Where-Object { $_.Parameters.Name -contains $parameter.Name }
        ).Count

        $candidateSwitches.Add([pscustomobject]@{
                Name              = $parameter.Name
                AvailabilityCount = $availabilityCount
            })
    }

    $selectorSwitch = $candidateSwitches |
        Where-Object { $_.AvailabilityCount -lt $totalParameterSetCount } |
        Sort-Object AvailabilityCount, Name |
        Select-Object -First 1

    if ($selectorSwitch) {
        return $selectorSwitch.Name
    }

    return $null
}

function Resolve-XdrParameterValue {
    param (
        [System.Management.Automation.CommandInfo]$Command,
        $Parameter,
        [string]$ParameterSetName
    )

    switch ($Parameter.Name) {
        'All' { return $true }
        'QueryText' { return 'DeviceInfo | take 1' }
        'Query' {
            if ($Command.Name -eq 'Invoke-XdrXspmHuntingQuery') {
                return @'
AttackPathsV2
| where Status in ('Active', 'New')
| summarize AttackPathsCount=count(), TargetName=take_any(tostring(Target.Name)) by TargetId=tostring(Target.Id)
| top 1 by AttackPathsCount
'@
            }

            return 'AttackPathsV2 | sort by EdgeId asc | take 1'
        }
        'ScenarioName' { return 'PesterSmoke' }
        'Uri' { return 'https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext?realTime=true' }
        'Comment' { return 'Pester validation' }
        'Name' {
            if ($Command.Name -eq 'New-XdrAdvancedHuntingFunction') {
                return 'PesterSmokeFunction'
            }
            return $null
        }
        'KQLQuery' { return 'DeviceInfo | take 1' }
        'LastNDays' { return 1 }
        'Enabled' { return $true }
        'EnableXdrAndMdi' { return $false }
        'EnableMde' { return $false }
        'EnableMda' { return $false }
        'AccountName' { return 'svc-xdr-test' }
        'DomainDnsName' { return 'contoso.com' }
        default {
            if ($Parameter.ParameterType -eq [System.Management.Automation.SwitchParameter]) {
                return $true
            }

            return (Get-XdrFixtureValue -CommandName $Command.Name -ParameterName $Parameter.Name)
        }
    }
}

function Add-XdrDefaultScenarioParameters {
    param (
        [System.Management.Automation.CommandInfo]$Command,
        [string]$ParameterSetName,
        [hashtable]$Parameters
    )

    $settings = Get-XdrTestSettings

    $shouldApplyDefaultTop = $true
    if ($Command.Name -match '^Get-XdrXspm' -or $Command.Name -eq 'Invoke-XdrXspmHuntingQuery') {
        $shouldApplyDefaultTop = $false
    }

    if ($shouldApplyDefaultTop -and (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'Top' -ParameterSetName $ParameterSetName)) {
        if (-not $Parameters.ContainsKey('Top')) {
            $Parameters.Top = [int]$settings['execution']['defaultTop']
        }
    }

    if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'PageSize' -ParameterSetName $ParameterSetName) {
        if (-not $Parameters.ContainsKey('PageSize')) {
            $Parameters.PageSize = [int]$settings['execution']['defaultPageSize']
        }
    }

    if ($Command.Name -eq 'Get-XdrEndpointDeviceTimeline') {
        if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'LastNDays' -ParameterSetName $ParameterSetName) {
            $Parameters.LastNDays = 1
        }
        if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'PageSize' -ParameterSetName $ParameterSetName) {
            $Parameters.PageSize = 25
        }
        if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'ThrottleLimit' -ParameterSetName $ParameterSetName) {
            $Parameters.ThrottleLimit = 2
        }
        if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'TimeoutSeconds' -ParameterSetName $ParameterSetName) {
            $Parameters.TimeoutSeconds = 300
        }
    }

    if ($Command.Name -eq 'Set-XdrConfigurationPreviewFeatures') {
        if (-not ($Parameters.ContainsKey('EnableXdrAndMdi') -or $Parameters.ContainsKey('EnableMde') -or $Parameters.ContainsKey('EnableMda'))) {
            if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'EnableMde' -ParameterSetName $ParameterSetName) {
                $Parameters.EnableMde = $false
            }
        }
    }

    if ($Command.Name -eq 'Set-XdrEndpointAdvancedFeatures') {
        $featureParameter = @(
            'PreviewFeatures',
            'LiveResponse',
            'AuthenticatedTelemetry',
            'MicrosoftIntuneConnection'
        ) | Where-Object { $Parameters.ContainsKey($_) } | Select-Object -First 1

        if (-not $featureParameter) {
            foreach ($candidate in @('PreviewFeatures', 'LiveResponse', 'AuthenticatedTelemetry', 'MicrosoftIntuneConnection')) {
                if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName $candidate -ParameterSetName $ParameterSetName) {
                    $Parameters[$candidate] = $true
                    break
                }
            }
        }
    }

    if ($Command.Name -in @('Set-XdrEndpointDeviceRbacGroup', 'New-XdrEndpointDeviceRbacGroup')) {
        if (Test-XdrParameterAvailableInSet -Command $Command -ParameterName 'GroupObject' -ParameterSetName $ParameterSetName) {
            if (-not $Parameters.ContainsKey('GroupObject')) {
                $Parameters.GroupObject = Get-XdrFixtureValue -CommandName $Command.Name -ParameterName 'GroupObject'
            }
        }
    }

    return $Parameters
}

function New-XdrAutoScenarioForParameterSet {
    param (
        [System.Management.Automation.CommandInfo]$Command,
        [System.Management.Automation.CommandParameterSetInfo]$ParameterSet
    )

    $settings = Get-XdrTestSettings
    if ($settings['execution']['skipCmdlets'] -contains $Command.Name) {
        return $null
    }

    if ($Command.Name -in @('Connect-XdrByEstsCookie', 'Connect-XdrBySoftwarePasskey', 'Set-XdrConnectionSettings')) {
        return $null
    }

    if ((Test-XdrCommandRequiresMutationOptIn -Command $Command) -and -not $settings['execution']['enableMutationTests'] -and -not $Command.Parameters.ContainsKey('WhatIf')) {
        return $null
    }

    $parameters = @{}
    foreach ($mandatoryParameter in ($ParameterSet.Parameters | Where-Object IsMandatory)) {
        $value = Resolve-XdrParameterValue -Command $Command -Parameter $mandatoryParameter -ParameterSetName $ParameterSet.Name
        if ($null -eq $value) {
            return $null
        }
        $parameters[$mandatoryParameter.Name] = $value
    }

    $selectorSwitch = Get-XdrSelectorSwitch -Command $Command -ParameterSetName $ParameterSet.Name
    if ($selectorSwitch -and -not $parameters.ContainsKey($selectorSwitch)) {
        $parameters[$selectorSwitch] = $true
    }

    $parameters = Add-XdrDefaultScenarioParameters -Command $Command -ParameterSetName $ParameterSet.Name -Parameters $parameters

    if ($Command.Parameters.ContainsKey('WhatIf') -and -not $settings['execution']['enableMutationTests']) {
        $parameters['WhatIf'] = $true
        $parameters['Confirm'] = $false
    }

    [pscustomobject]@{
        CommandName      = $Command.Name
        ParameterSetName = $ParameterSet.Name
        ScenarioName     = $ParameterSet.Name
        Parameters       = $parameters
        Source           = 'Auto'
        RequiredWorkload = Get-XdrRequiredWorkload -CommandName $Command.Name
    }
}

function Resolve-XdrScenarioParameterSetName {
    param (
        [System.Management.Automation.CommandInfo]$Command,
        [hashtable]$Parameters
    )

    foreach ($parameterSet in $Command.ParameterSets) {
        $matchFound = $true

        foreach ($mandatoryParameter in ($parameterSet.Parameters | Where-Object IsMandatory)) {
            if (-not $Parameters.ContainsKey($mandatoryParameter.Name)) {
                $matchFound = $false
                break
            }
        }

        if (-not $matchFound) {
            continue
        }

        foreach ($suppliedParameter in $Parameters.Keys) {
            if (-not (Test-XdrParameterAvailableInSet -Command $Command -ParameterName $suppliedParameter -ParameterSetName $parameterSet.Name)) {
                $matchFound = $false
                break
            }
        }

        if ($matchFound) {
            return $parameterSet.Name
        }
    }

    return '__Unknown'
}

function Get-XdrConfiguredScenarios {
    param (
        [System.Management.Automation.CommandInfo]$Command
    )

    $settings = Get-XdrTestSettings
    if (-not $settings['scenarios'].ContainsKey($Command.Name)) {
        return @()
    }

    if ((Test-XdrCommandRequiresMutationOptIn -Command $Command) -and -not $settings['execution']['enableMutationTests'] -and -not $Command.Parameters.ContainsKey('WhatIf')) {
        return @()
    }

    $scenarioList = @()
    foreach ($scenario in @($settings['scenarios'][$Command.Name])) {
        $scenarioHash = ConvertTo-XdrHashtable -InputObject $scenario
        $parameters = if ($scenarioHash.ContainsKey('parameters')) {
            [hashtable]$scenarioHash.parameters
        } else {
            @{}
        }

        if ($Command.Parameters.ContainsKey('WhatIf') -and -not $settings['execution']['enableMutationTests'] -and -not $parameters.ContainsKey('WhatIf')) {
            $parameters['WhatIf'] = $true
            $parameters['Confirm'] = $false
        }

        $scenarioList += [pscustomobject]@{
            CommandName      = $Command.Name
            ParameterSetName = if ($scenarioHash.ContainsKey('parameterSetName')) {
                [string]$scenarioHash.parameterSetName
            } else {
                Resolve-XdrScenarioParameterSetName -Command $Command -Parameters $parameters
            }
            ScenarioName     = if ($scenarioHash.ContainsKey('name')) { [string]$scenarioHash.name } else { 'Configured' }
            Parameters       = $parameters
            Source           = 'Config'
            RequiredWorkload = Get-XdrRequiredWorkload -CommandName $Command.Name
        }
    }

    return $scenarioList
}

function Get-XdrLiveScenarios {
    $settings = Get-XdrTestSettings
    if (-not $settings['liveTests']['enabled']) {
        return @()
    }

    Connect-XdrForTests | Out-Null

    $scenarios = [System.Collections.Generic.List[object]]::new()
    foreach ($command in Get-XdrPublicCommands) {
        foreach ($scenario in Get-XdrConfiguredScenarios -Command $command) {
            $scenarios.Add($scenario)
        }

        foreach ($parameterSet in $command.ParameterSets) {
            $autoScenario = New-XdrAutoScenarioForParameterSet -Command $command -ParameterSet $parameterSet
            if ($null -eq $autoScenario) {
                continue
            }

            $alreadyCovered = $false
            foreach ($existingScenario in $scenarios) {
                if ($existingScenario.CommandName -eq $autoScenario.CommandName -and $existingScenario.ParameterSetName -eq $autoScenario.ParameterSetName) {
                    $alreadyCovered = $true
                    break
                }
            }

            if (-not $alreadyCovered) {
                $scenarios.Add($autoScenario)
            }
        }
    }

    return @($scenarios)
}

function Test-XdrScenarioShouldSkip {
    param (
        $Scenario
    )

    $settings = Get-XdrTestSettings
    if ($settings['execution']['skipCmdlets'] -contains $Scenario.CommandName) {
        return 'Skipped by configuration'
    }

    if ($Scenario.CommandName -in @('New-XdrEndpointConfigurationCustomCollectionRule', 'Set-XdrEndpointConfigurationCustomCollectionRule')) {
        $usesYamlInput = $Scenario.CommandName -eq 'New-XdrEndpointConfigurationCustomCollectionRule' -or $Scenario.ParameterSetName -eq 'YAML'
        if ($usesYamlInput) {
            $hasYamlParser = $null -ne (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue) -or
                $null -ne (Get-Module -Name powershell-yaml -ListAvailable)
            if (-not $hasYamlParser) {
                return 'YAML parser dependency is unavailable in this test environment'
            }
        }
    }

    if ($Scenario.RequiredWorkload) {
        $workloads = Get-XdrWorkloadStatusTable
        if ($workloads.ContainsKey($Scenario.RequiredWorkload) -and -not $workloads[$Scenario.RequiredWorkload]) {
            return "Required workload '$($Scenario.RequiredWorkload)' is not active in this tenant"
        }
    }

    return $null
}

function Invoke-XdrLiveScenario {
    param (
        $Scenario
    )

    $skipReason = Test-XdrScenarioShouldSkip -Scenario $Scenario
    if ($skipReason) {
        return [pscustomobject]@{
            Status = 'Skipped'
            Reason = $skipReason
            Result = $null
        }
    }

    $command = Get-Command $Scenario.CommandName -ErrorAction Stop
    $parameters = [hashtable]$Scenario.Parameters
    $result = & $command @parameters -ErrorAction Stop

    return [pscustomobject]@{
        Status = 'Passed'
        Reason = $null
        Result = $result
    }
}

function Get-XdrLiveCoverageReport {
    $settings = Get-XdrTestSettings
    if (-not $settings['liveTests']['enabled']) {
        return @()
    }

    $scenarios = Get-XdrLiveScenarios
    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($command in Get-XdrPublicCommands) {
        foreach ($parameterSet in $command.ParameterSets) {
            $coveredBy = $scenarios | Where-Object {
                $_.CommandName -eq $command.Name -and $_.ParameterSetName -eq $parameterSet.Name
            } | Select-Object -First 1

            $report.Add([pscustomobject]@{
                CommandName      = $command.Name
                ParameterSetName = $parameterSet.Name
                Covered          = [bool]$coveredBy
                CoverageSource   = if ($coveredBy) { $coveredBy.Source } else { $null }
                ScenarioName     = if ($coveredBy) { $coveredBy.ScenarioName } else { $null }
            })
        }
    }

    return @($report)
}
