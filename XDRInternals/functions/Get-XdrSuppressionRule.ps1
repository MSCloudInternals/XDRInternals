function Get-XdrSuppressionRule {
    <#
    .SYNOPSIS
        Retrieves alert suppression rules from Microsoft Defender XDR.
    
    .DESCRIPTION
        Gets the list of alert suppression rules configured in the Microsoft Defender XDR portal,
        including rule details such as title, conditions, scope, status, and matching alert counts.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrSuppressionRule
        Retrieves all suppression rules using cached data if available.
    
    .EXAMPLE
        Get-XdrSuppressionRule -Force
        Forces a fresh retrieval of suppression rules, bypassing the cache.
    
    .EXAMPLE
        Get-XdrSuppressionRule | Where-Object { $_.IsEnabled }
        Retrieves only enabled suppression rules.
    
    .EXAMPLE
        Get-XdrSuppressionRule | Where-Object { $_.CreatedBy -eq 'Microsoft' }
        Retrieves only Microsoft-created suppression rules.
    
    .EXAMPLE
        Get-XdrSuppressionRule | Where-Object { $_.MatchingAlertsCount -gt 0 }
        Retrieves suppression rules that have matched alerts.
    
    .OUTPUTS
        Object[]
        Returns an array of suppression rule objects with properties:
        - Id: Unique identifier for the suppression rule
        - RuleTitle: The title of the suppression rule
        - SenseMachineId: Machine ID if rule is scoped to specific device
        - ComputerDnsName: DNS name if rule is scoped to specific computer
        - CreatedBy: User or system that created the rule
        - CreationTime: When the rule was created
        - UpdateTime: When the rule was last updated
        - Scope: Scope type (1=Organizational, 2=Device group)
        - IoaDefinitionId: Associated IOA definition GUID
        - IsEnabled: Whether the rule is currently enabled
        - IsSilent: Whether alerts are silently suppressed
        - IsTestRule: Whether this is a test rule
        - OrderIndex: Rule ordering index
        - Action: Action type (1=Alert, 2=Suppress)
        - RuleConditions: JSON string of rule conditions
        - AlertTitle: Title of alerts this rule applies to
        - MatchingAlertsCount: Number of alerts matched by this rule
        - RbacGroupIds: RBAC group IDs (if scoped)
        - DeserializedRbacGroupIds: Deserialized RBAC group IDs
        - FullDeserializedRbacGroupIds: Full deserialized RBAC group IDs
        - IsReadOnly: Whether the rule is read-only
        - ThreatFamilyName: Associated threat family name
        - LastActivity: Last activity timestamp
        - RuleType: Type of rule (1=Alert-based, 2=IOA-based)
        - RuleSource: Source of the rule (1=Microsoft, 2=Custom)
        - ScopeConditions: JSON string of scope conditions
        - AdditionalDetails: Additional rule details
        - Description: Rule description
        - DeserializedScopeConditions: Deserialized scope conditions array
        - BitwiseServiceSources: Bitwise service sources flag
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }
    process {
        $currentCacheValue = Get-XdrCache -CacheKey "XdrSuppressionRule" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Suppression Rules"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrSuppressionRule"
        } else {
            Write-Verbose "XDR Suppression Rules cache is missing or expired"
        }
        Write-Verbose "Retrieving XDR Suppression Rules"
        try {
            $XdrSuppressionRules = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/suppressionRulesService/suppressionRules" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrSuppressionRule" -Value $XdrSuppressionRules -TTLMinutes 30
            return $XdrSuppressionRules
        } catch {
            throw "Failed to retrieve XDR Suppression Rules: $($_.Exception.Message)"
        }
    }
    
    end {
    }
}
