function Move-XdrAlertToIncident {
    <#
    .SYNOPSIS
        Moves alerts to a specific incident or creates a new one.

    .DESCRIPTION
        Moves one or more alerts to a target incident. If TargetIncidentId is not specified,
        a new incident is created containing the alerts.
        Validates that the TargetIncidentId and AlertIds exist before attempting the move.

    .PARAMETER AlertIds
        A list of alert IDs to move.

    .PARAMETER TargetIncidentId
        The ID of the incident to move the alerts to. If null or omitted, a new incident is created.

    .PARAMETER Comment
        Optional comment for the operation. Default is "Moved via XDRInternals".
    
    .PARAMETER Confirm
        Prompts for confirmation before executing the move operation.
    
    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs.

    .EXAMPLE
        Move-XdrAlertToIncident -AlertIds "ed638962183442188554_-691007355" -TargetIncidentId 2822
        Moves the specified alert to incident 2822.

    .EXAMPLE
        Move-XdrAlertToIncident -AlertIds "ed638962183442188554_-691007355"
        Moves the specified alert to a new incident.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$AlertIds,

        [Parameter()]
        [long]$TargetIncidentId,

        [Parameter()]
        [string]$Comment = "Moved via XDRInternals"
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Validate TargetIncidentId if provided
        $incidentIdValue = $null
        if ($PSBoundParameters.ContainsKey('TargetIncidentId') -and $TargetIncidentId -gt 0) {
            Write-Verbose "Validating TargetIncidentId: $TargetIncidentId"
            $incidentSearch = Get-XdrIncidentSearch -Term "$TargetIncidentId"
            
            # Check if we found an exact match
            $incidentMatch = $incidentSearch | Where-Object { $_.incidentId -eq $TargetIncidentId }
            
            if (-not $incidentMatch) {
                Write-Error "Target Incident ID '$TargetIncidentId' not found."
                return
            }
            $incidentIdValue = $TargetIncidentId
        }

        # Validate AlertIds
        $validAlertIds = @()
        foreach ($alertId in $AlertIds) {
            Write-Verbose "Validating AlertId: $alertId"
            $alertSearch = Get-XdrAlertSearch -SearchTerm $alertId
            
            # Check if we found an exact match
            $alertMatch = $alertSearch | Where-Object { $_.id -eq $alertId }

            if ($alertMatch) {
                $validAlertIds += $alertId
            } else {
                Write-Error "Alert ID '$alertId' not found."
                return
            }
        }

        if ($validAlertIds.Count -eq 0) {
            return
        }

        if ($PSCmdlet.ShouldProcess("Alerts: $($validAlertIds -join ', ')", "Move to Incident: $(if ($incidentIdValue) { $incidentIdValue } else { 'New Incident' })")) {
            
            $body = @{
                AlertIds                               = $validAlertIds
                IncidentId                             = $incidentIdValue
                Comment                                = $Comment
                ReturnOkIfAlertAlreadyLinkedToIncident = $true
                FeedbackContent                        = @{
                    ClientFalseCorrelationEntities  = @()
                    ClientFalseCorrelationLinkTypes = @()
                    ClientNewLinkReasons            = @()
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mtp/alertsLinks/alerts/incidentLinks?newApi=true"
            
            try {
                $response = Invoke-XdrRestMethod -Uri $Uri -Method POST -Body ($body | ConvertTo-Json -Depth 10) -ErrorAction Stop
                return $response
            } catch {
                Write-Error "Failed to move alerts: $_"
            }
        }
    }
}
