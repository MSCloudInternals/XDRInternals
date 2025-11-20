function Get-XdrIdentityAlertThreshold {
    <#
    .SYNOPSIS
        Retrieves alert threshold configuration for Microsoft Defender for Identity.

    .DESCRIPTION
        Gets the alert threshold settings for Microsoft Defender for Identity detections.
        Alert thresholds determine the sensitivity level (High/Medium/Low) for various security alerts.
        The function maps internal alert names to user-friendly titles for better readability.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityAlertThreshold
        Retrieves the alert threshold configuration using cached data if available.

    .EXAMPLE
        Get-XdrIdentityAlertThreshold -Force
        Forces a fresh retrieval of the alert threshold configuration, bypassing the cache.

    .EXAMPLE
        $thresholds = Get-XdrIdentityAlertThreshold
        $thresholds | Where-Object { $_.Threshold -eq "Low" }
        Retrieves all alerts configured with Low threshold.

    .EXAMPLE
        Get-XdrIdentityAlertThreshold | Format-Table AlertTitle, Threshold, AvailableThresholds -AutoSize
        Displays alert thresholds in a formatted table.

    .OUTPUTS
        Object
        Returns an array of alert threshold configurations with friendly names.
        Each object contains:
        - AlertName: Internal alert identifier
        - AlertTitle: User-friendly alert name
        - Threshold: Current threshold level (High/Medium/Low)
        - AvailableThresholds: Array of available threshold levels for this alert
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityAlertThreshold" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity alert threshold configuration"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityAlertThreshold"
        } else {
            Write-Verbose "XDR Identity alert threshold configuration cache is missing or expired"
        }

        # Alert name mapping from internal names to friendly titles
        $alertNameMap = @{
            "AbnormalSensitiveGroupMembershipChangeSecurityAlert" = "Suspicious additions to sensitive groups"
            "AdfsDistributedKeyManagerReadSecurityAlert"          = "Suspected AD FS DKM key read"
            "BruteForceSecurityAlert"                             = "Suspected Brute Force attack (Kerberos, NTLM)"
            "DirectoryServicesReplicationSecurityAlert"           = "Suspected DCSync attack (replication of directory services)"
            "DnsReconnaissanceSecurityAlert"                      = "Network-mapping reconnaissance (DNS)"
            "ForgedPrincipalSecurityAlert"                        = "Suspected Golden Ticket usage (forged authorization data)"
            "GoldenTicketEncryptionDowngradeSecurityAlert"        = "Suspected Golden Ticket usage (encryption downgrade)"
            "LdapSearchReconnaissanceSecurityAlert"               = "Security principal reconnaissance (LDAP)"
            "PassTheCertificateSecurityAlert"                     = "Suspected identity theft (pass-the-certificate)"
            "PassTheTicketSecurityAlert"                          = "Suspected identity theft (pass-the-ticket)"
            "SamrReconnaissanceSecurityAlert"                     = "User and Group membership reconnaissance (SAMR)"
        }

        $Uri = "https://security.microsoft.com/apiproxy/aatp/api/alertthresholds/withExpiry"
        Write-Verbose "Retrieving XDR Identity alert threshold configuration"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        # Output test mode status as verbose information
        if ($result.IsRecommendedTestModeEnabled) {
            Write-Verbose "Recommended test mode is enabled"
        } else {
            Write-Verbose "Recommended test mode is not enabled"
        }

        # Enhance alert thresholds with friendly names
        if ($result.AlertThresholds) {
            foreach ($alert in $result.AlertThresholds) {
                $friendlyName = $alertNameMap[$alert.AlertName]
                if ($friendlyName) {
                    $alert | Add-Member -MemberType NoteProperty -Name "AlertTitle" -Value $friendlyName -Force
                } else {
                    # Fallback to original name if no mapping exists
                    $alert | Add-Member -MemberType NoteProperty -Name "AlertTitle" -Value $alert.AlertName -Force
                }
            }
            Write-Verbose "Retrieved $($result.AlertThresholds.Count) alert threshold configurations"
        }

        # Cache and return only the AlertThresholds array
        Set-XdrCache -CacheKey "XdrIdentityAlertThreshold" -Value $result.AlertThresholds -TTLMinutes 30
        return $result.AlertThresholds
    }

    end {

    }
}
