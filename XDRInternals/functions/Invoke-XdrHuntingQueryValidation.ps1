function Invoke-XdrHuntingQueryValidation {
    <#
    .SYNOPSIS
        Validates an Advanced Hunting query for custom detection rules in Microsoft Defender XDR.

    .DESCRIPTION
        Validates whether an Advanced Hunting query is allowed and checks the permissions required
        for creating custom detection rules. This is useful before attempting to create a custom
        detection rule to ensure the query syntax is valid and the user has appropriate permissions.

    .PARAMETER QueryText
        The KQL (Kusto Query Language) query text to validate. This should be a valid Advanced Hunting query.

    .PARAMETER HuntingRule
        Optional hunting rule object to validate. If not specified, defaults to null.

    .EXAMPLE
        Invoke-XdrHuntingQueryValidation -QueryText "DeviceEvents | where Timestamp > ago(1h)"
        Validates the specified Advanced Hunting query.

    .EXAMPLE
        $query = @"
        DeviceEvents
        | where ActionType == "ProcessCreated"
        | where FileName == "powershell.exe"
        | project Timestamp, DeviceName, AccountName, ProcessCommandLine
        "@
        Invoke-XdrHuntingQueryValidation -QueryText $query
        Validates a multi-line Advanced Hunting query.

    .EXAMPLE
        Invoke-XdrHuntingQueryValidation -QueryText "DeviceProcessEvents | where false"
        Validates a simple test query that returns no results.

    .OUTPUTS
        Object
        Returns a validation response object containing:
        - IsAllowed: Boolean indicating if the query is allowed
        - Permissions: Object containing permission details for each workload (Mdatp, etc.)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$QueryText,

        [Parameter()]
        [object]$HuntingRule = $null
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $body = @{
            QueryText   = $QueryText
            HuntingRule = $HuntingRule
        } | ConvertTo-Json -Depth 10

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/rules/validateQuery"
        
            Write-Verbose "Validating Advanced Hunting query"
            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
        
            return $result
        } catch {
            Write-Error "Failed to validate Advanced Hunting query: $_"
            throw
        }
    }

    end {

    }
}
