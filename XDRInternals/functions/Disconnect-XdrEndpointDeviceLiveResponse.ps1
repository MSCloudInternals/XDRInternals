function Disconnect-XdrEndpointDeviceLiveResponse {
    <#
    .SYNOPSIS
        Closes an active Live Response session in Microsoft Defender XDR.

    .DESCRIPTION
        Closes an active Live Response session by calling the close_session API.
        This should be called when done with a Live Response session to free resources.
        Also clears the script-scoped LiveResponseSession variable if it matches.

    .PARAMETER SessionId
        The Live Response session ID to close (starts with CLR prefix).

    .EXAMPLE
        Disconnect-XdrEndpointDeviceLiveResponse -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb"
        Closes the specified Live Response session.

    .EXAMPLE
        $sessions | Disconnect-XdrEndpointDeviceLiveResponse
        Closes Live Response sessions passed through the pipeline.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$SessionId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $body = @{
            session_id = $SessionId
        } | ConvertTo-Json -Depth 10

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/close_session?useV2Api=false&useV3Api=true"
            Write-Verbose "Closing Live Response session $SessionId"
            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

            # Clear script-scoped session if it matches
            if ((Test-Path variable:script:LiveResponseSession) -and $script:LiveResponseSession -and $script:LiveResponseSession.SessionId -eq $SessionId) {
                $script:LiveResponseSession = $null
            }

            Write-Host "Live Response session closed." -ForegroundColor Yellow
            return $result
        } catch {
            Write-Error "Failed to close Live Response session: $_"
        }
    }

    end {
    }
}
