function Remove-XdrEndpointDeviceLiveResponseLibraryFile {
    <#
    .SYNOPSIS
        Deletes a file from the Live Response library.

    .DESCRIPTION
        Removes a script file from the Microsoft Defender XDR Live Response library.
        When only -FileName is provided, the cmdlet automatically looks up the file metadata
        (last_updated_time) required by the API. Accepts pipeline input from
        Get-XdrEndpointDeviceLiveResponseLibrary.

    .PARAMETER FileName
        The name of the file to delete from the library (e.g. 'PasskeyLogin.ps1').

    .PARAMETER InputObject
        A library file object from Get-XdrEndpointDeviceLiveResponseLibrary. Extracts
        file_name and last_updated_time automatically.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The file is not deleted.

    .PARAMETER Confirm
        Prompts you for confirmation before deleting the file. Confirmation is required by default.

    .EXAMPLE
        Remove-XdrEndpointDeviceLiveResponseLibraryFile -FileName 'OldScript.ps1'
        Deletes OldScript.ps1 from the library after confirmation.

    .EXAMPLE
        Remove-XdrEndpointDeviceLiveResponseLibraryFile -FileName 'OldScript.ps1' -Confirm:$false
        Deletes without prompting.

    .EXAMPLE
        Get-XdrEndpointDeviceLiveResponseLibrary | Where-Object file_name -eq 'OldScript.ps1' | Remove-XdrEndpointDeviceLiveResponseLibraryFile
        Deletes using pipeline input from the library listing.

    .EXAMPLE
        Remove-XdrEndpointDeviceLiveResponseLibraryFile -FileName 'OldScript.ps1' -WhatIf
        Shows what would be deleted without performing the deletion.

    .OUTPUTS
        None
        This cmdlet does not return output on successful deletion.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('file_name')]
        [string]$FileName,

        [Parameter(Mandatory = $true, ParameterSetName = 'InputObject', ValueFromPipeline = $true)]
        [object]$InputObject
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            $resolvedFileName = $null
            $lastUpdatedTime = $null

            if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
                if (-not $InputObject.file_name) {
                    throw "InputObject must contain a 'file_name' property. Ensure you are passing an object from Get-XdrEndpointDeviceLiveResponseLibrary."
                }
                $resolvedFileName = $InputObject.file_name
                $lastUpdatedTime = $InputObject.last_updated_time
            } else {
                $resolvedFileName = $FileName

                # Look up metadata required by the API (last_updated_time)
                Write-Verbose "Looking up metadata for '$resolvedFileName'"
                $library = Get-XdrEndpointDeviceLiveResponseLibrary -Force
                $fileEntry = $library | Where-Object { $_.file_name -eq $resolvedFileName } | Select-Object -First 1

                if (-not $fileEntry) {
                    throw "File '$resolvedFileName' was not found in the Live Response library."
                }
                $lastUpdatedTime = $fileEntry.last_updated_time
            }

            $Uri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/library/delete_file?useV3Api=true"
            $body = [ordered]@{
                file_id           = $null
                last_updated_time = $lastUpdatedTime
                file_name         = $resolvedFileName
            } | ConvertTo-Json -Compress

            if ($PSCmdlet.ShouldProcess($resolvedFileName, "Delete from Live Response library")) {
                Write-Verbose "Deleting '$resolvedFileName' from Live Response library"
                $null = Invoke-RestMethod -Uri $Uri -Method Delete -Body $body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Invalidate library listing cache
                Clear-XdrCache -CacheKey "XdrLiveResponseLibrary" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully deleted '$resolvedFileName'"
            }
        } catch {
            Write-Error "Failed to delete '$resolvedFileName' from Live Response library: $_"
        }
    }

    end {
    }
}
