function Merge-XdrIncident {
    <#
    .SYNOPSIS
        Merges multiple incidents into a single incident in Microsoft Defender XDR.

    .DESCRIPTION
        Combines multiple incidents into one incident in Microsoft Defender XDR.
        All incidents must exist before merging. The cmdlet validates each incident ID before proceeding.
        This operation requires confirmation due to its high impact.

    .PARAMETER IncidentIds
        Array of incident IDs to merge. Must contain at least 2 incident IDs.
        All incidents will be validated before the merge operation.

    .PARAMETER Comment
        Comment explaining the reason for merging the incidents.
        This will be recorded in the incident history.
    
    .PARAMETER Confirm
    Prompts for confirmation before executing the merge operation.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The JSON body for the merge operation will be displayed.

    .EXAMPLE
        Merge-XdrIncident -IncidentIds 2821, 2823 -Comment "Related phishing attacks"
        Merges incidents 2821 and 2823 with a comment.

    .EXAMPLE
        Merge-XdrIncident -IncidentIds 100, 101, 102 -Comment "Same threat actor campaign"
        Merges three incidents into one.

    .EXAMPLE
        $incidents = 2821, 2823, 2825
        Merge-XdrIncident -IncidentIds $incidents -Comment "Coordinated attack"
        Merges multiple incidents using a variable.

    .OUTPUTS
        Object
        Returns the result of the merge operation from the API.

    .NOTES
        This operation cannot be undone. Use with caution.
        All specified incidents must exist in the tenant.
        The operation requires user confirmation unless -Confirm:$false is specified.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateCount(2, [int]::MaxValue)]
        [int[]]$IncidentIds,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Comment
    )

    begin {
        Update-XdrConnectionSettings

        # Get current user for AadUserId field
        Write-Verbose "Retrieving current user information"
        try {
            $tenantContext = Get-XdrTenantContext -ErrorAction SilentlyContinue
            $aadUserId = $tenantContext.AuthInfo.UserName
            if (-not $aadUserId) {
                throw "Unable to determine current user principal name from tenant context"
            }
            Write-Verbose "Current user: $aadUserId"
        } catch {
            throw "Failed to retrieve tenant context: $($_.Exception.Message)"
        }
    }

    process {
        # Validate all incidents exist using search (faster than individual Get calls)
        Write-Verbose "Validating incident IDs: $($IncidentIds -join ', ')"
        $validatedIncidents = @()
        $invalidIncidents = @()

        # Build a search term with all incident IDs for batch validation
        foreach ($incidentId in $IncidentIds) {
            Write-Verbose "Validating incident ID: $incidentId"
            try {
                # Use search endpoint for faster validation
                $searchResults = Get-XdrIncidentSearch -Term $incidentId.ToString() -ErrorAction Stop
                $incident = $searchResults | Where-Object { $_.IncidentId -eq $incidentId }
                
                if ($incident) {
                    $validatedIncidents += $incident
                    Write-Verbose "Incident $incidentId validated: $($incident.Title)"
                } else {
                    $invalidIncidents += $incidentId
                    Write-Warning "Incident ID $incidentId not found"
                }
            } catch {
                $invalidIncidents += $incidentId
                Write-Warning "Failed to validate incident ID $incidentId : $($_.Exception.Message)"
            }
        }

        # Check if any incidents were invalid
        if ($invalidIncidents.Count -gt 0) {
            throw "The following incident IDs could not be validated: $($invalidIncidents -join ', '). All incidents must exist before merging."
        }

        if ($validatedIncidents.Count -lt 2) {
            throw "At least 2 valid incidents are required for merging. Only $($validatedIncidents.Count) incident(s) validated successfully."
        }

        Write-Verbose "All $($validatedIncidents.Count) incidents validated successfully"

        # Build incident titles for confirmation message
        $incidentTitles = $validatedIncidents | ForEach-Object { "  - [$($_.IncidentId)] $($_.Title)" }
        $confirmMessage = "Merge $($validatedIncidents.Count) incidents:`n$($incidentTitles -join "`n")`n`nComment: $Comment"

        # Build API request body
        $body = @{
            IncidentIds     = $IncidentIds
            Comment         = $Comment
            AadUserId       = $aadUserId
            FeedbackContent = @{
                ClientMergeReasons = @()
            }
        } | ConvertTo-Json -Depth 10

        $Uri = "https://security.microsoft.com/apiproxy/mtp/incidents/merge"

        # If WhatIf is specified, output the JSON body
        if ($WhatIfPreference) {
            Write-Host "JSON Body for merging incidents:"
            Write-Host $body
            return
        }

        if ($PSCmdlet.ShouldProcess($confirmMessage, "Merge incidents")) {
            Write-Verbose "Merging incidents: $($IncidentIds -join ', ')"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                Write-Verbose "Successfully merged $($validatedIncidents.Count) incidents"
                return $result
            } catch {
                throw "Failed to merge incidents: $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
