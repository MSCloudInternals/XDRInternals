function New-XdrEndpointDeviceLiveResponseLibraryFile {
    <#
    .SYNOPSIS
        Uploads a script file to the Live Response library.

    .DESCRIPTION
        Uploads a local script file to the Microsoft Defender XDR Live Response library.
        The file can then be used with the 'putfile' and 'run' commands during Live Response sessions.
        Multipart form-data is constructed as a byte array to maintain WebSession cookie compatibility.

    .PARAMETER FilePath
        The full path to the local script file to upload.

    .PARAMETER Description
        Optional description for the library file.

    .PARAMETER HasParameters
        Indicates that the script accepts parameters during execution.

    .PARAMETER ParametersDescription
        Description of the parameters accepted by the script. Only relevant when -HasParameters is specified.

    .PARAMETER OverrideIfExists
        If specified, overwrites an existing library file with the same name.
        Without this switch, uploading a duplicate file name will fail.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The file is not uploaded.

    .PARAMETER Confirm
        Prompts you for confirmation before uploading the file.

    .EXAMPLE
        New-XdrEndpointDeviceLiveResponseLibraryFile -FilePath 'C:\Scripts\Remediate.ps1'
        Uploads Remediate.ps1 to the Live Response library.

    .EXAMPLE
        New-XdrEndpointDeviceLiveResponseLibraryFile -FilePath 'C:\Scripts\Remediate.ps1' -Description 'Remediation script' -HasParameters -ParametersDescription '-TargetProcess <string>'
        Uploads with metadata describing the script parameters.

    .EXAMPLE
        New-XdrEndpointDeviceLiveResponseLibraryFile -FilePath 'C:\Scripts\Remediate.ps1' -OverrideIfExists
        Replaces an existing library file with the same name.

    .OUTPUTS
        Object
        Returns the API response containing the uploaded file metadata.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$FilePath,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [switch]$HasParameters,

        [Parameter()]
        [string]$ParametersDescription,

        [Parameter()]
        [switch]$OverrideIfExists
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            $fileName = [System.IO.Path]::GetFileName($FilePath)

            if (-not $PSCmdlet.ShouldProcess($fileName, "Upload to Live Response library")) {
                return
            }

            # Build file_fields metadata JSON
            $fileFields = [ordered]@{
                description            = if ($Description) { $Description } else { $null }
                has_parameters         = $HasParameters.IsPresent
                parameters_description = if ($ParametersDescription) { $ParametersDescription } else { $null }
                override_if_exists     = $OverrideIfExists.IsPresent
            }
            $fileFieldsJson = $fileFields | ConvertTo-Json -Compress

            # Read file bytes
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)

            # Build multipart/form-data body as byte array (required for binary content with WebSession)
            $boundary = [System.Guid]::NewGuid().ToString()
            $encoding = [System.Text.Encoding]::UTF8
            $stream = [System.IO.MemoryStream]::new()

            # Part 1: file[] (binary)
            $part1Header = "--$boundary`r`nContent-Disposition: form-data; name=`"file[]`"; filename=`"$fileName`"`r`nContent-Type: application/octet-stream`r`n`r`n"
            $part1HeaderBytes = $encoding.GetBytes($part1Header)
            $stream.Write($part1HeaderBytes, 0, $part1HeaderBytes.Length)
            $stream.Write($fileBytes, 0, $fileBytes.Length)

            # Part 2: file_fields (JSON metadata)
            $part2 = "`r`n--$boundary`r`nContent-Disposition: form-data; name=`"file_fields`"`r`n`r`n$fileFieldsJson`r`n--$boundary--`r`n"
            $part2Bytes = $encoding.GetBytes($part2)
            $stream.Write($part2Bytes, 0, $part2Bytes.Length)

            $bodyBytes = $stream.ToArray()
            $stream.Dispose()

            $contentType = "multipart/form-data; boundary=$boundary"
            $Uri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/library/upload_file?useV3Api=true"

            Write-Verbose "Uploading '$fileName' to Live Response library"
            $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyBytes -ContentType $contentType -WebSession $script:session -Headers $script:headers

            # Invalidate the library listing cache so next Get- call reflects the new file
            Clear-XdrCache -CacheKey "XdrLiveResponseLibrary" -ErrorAction SilentlyContinue

            Write-Verbose "Successfully uploaded '$fileName'"
            return $result
        } catch {
            Write-Error "Failed to upload '$FilePath' to Live Response library: $_"
        }
    }

    end {
    }
}
