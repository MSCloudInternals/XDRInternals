function Get-XdrEndpointDeviceLiveResponseLibraryFile {
    <#
    .SYNOPSIS
        Downloads a script file from the Live Response library.

    .DESCRIPTION
        Retrieves the content of a specific file from the Microsoft Defender XDR Live Response library.
        Accepts pipeline input from Get-XdrEndpointDeviceLiveResponseLibrary.
        If -OutputPath is specified, the file is saved to disk. Otherwise the decoded content is returned as a string.

    .PARAMETER FileName
        The name of the file to download from the library (e.g. 'PasskeyLogin.ps1').
        Accepts ValueFromPipelineByPropertyName, so objects from Get-XdrEndpointDeviceLiveResponseLibrary
        pipe directly using the file_name property.

    .PARAMETER OutputPath
        Optional file path to save the downloaded content. If omitted, the content is returned as a string.

    .EXAMPLE
        Get-XdrEndpointDeviceLiveResponseLibraryFile -FileName 'PasskeyLogin.ps1'
        Returns the content of PasskeyLogin.ps1 as a string.

    .EXAMPLE
        Get-XdrEndpointDeviceLiveResponseLibraryFile -FileName 'PasskeyLogin.ps1' -OutputPath 'C:\Temp\PasskeyLogin.ps1'
        Downloads and saves the file to disk.

    .EXAMPLE
        Get-XdrEndpointDeviceLiveResponseLibrary | Where-Object file_name -eq 'PasskeyLogin.ps1' | Get-XdrEndpointDeviceLiveResponseLibraryFile
        Downloads a library file using pipeline input.

    .OUTPUTS
        System.String
        Returns the file content as a string when no OutputPath is specified.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('file_name')]
        [string]$FileName,

        [Parameter()]
        [string]$OutputPath
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/library/download_file?file_name=$([System.Uri]::EscapeDataString($FileName))"
            Write-Verbose "Downloading '$FileName' from Live Response library"
            $response = Invoke-WebRequest -Uri $Uri -Method Get -WebSession $script:session -Headers $script:headers

            # Read raw bytes from the response stream; the API serves files as application/octet-stream
            $responseBytes = $response.RawContentStream.ToArray()

            # Try base64 decode first (HAR shows the proxy may return base64-encoded content);
            # fall back to treating the raw bytes directly as UTF-8 text
            $content = $null
            try {
                $rawString = [System.Text.Encoding]::ASCII.GetString($responseBytes).Trim()
                $decodedBytes = [System.Convert]::FromBase64String($rawString)
                $content = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
            } catch {
                # Not base64 — raw bytes are the file content (e.g. text served directly)
                $content = [System.Text.Encoding]::UTF8.GetString($responseBytes)
            }

            if ($OutputPath) {
                [System.IO.File]::WriteAllText($OutputPath, $content, [System.Text.Encoding]::UTF8)
                Write-Verbose "Saved '$FileName' to '$OutputPath'"
            } else {
                return $content
            }
        } catch {
            Write-Error "Failed to download '$FileName' from Live Response library: $_"
        }
    }

    end {
    }
}
