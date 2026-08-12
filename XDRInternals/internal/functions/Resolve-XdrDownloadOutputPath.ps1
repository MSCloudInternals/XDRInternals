function Resolve-XdrDownloadOutputPath {
    <#
    .SYNOPSIS
        Resolves a download destination without silently overwriting a file.

    .DESCRIPTION
        Resolves an optional file or directory path, verifies that its parent directory exists,
        and rejects an existing destination unless Force is explicitly supplied.

    .PARAMETER SuggestedFileName
        The safe default file name supplied by the download operation.

    .PARAMETER OutputPath
        An optional destination file or existing directory. The current directory is used by default.

    .PARAMETER Force
        Allows an existing destination file to be overwritten.

    .EXAMPLE
        Resolve-XdrDownloadOutputPath -SuggestedFileName 'result.zip' -OutputPath '/tmp'

        Returns the full path /tmp/result.zip when it does not already exist.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SuggestedFileName,

        [string]$OutputPath,

        [switch]$Force
    )

    $safeFileName = [System.IO.Path]::GetFileName($SuggestedFileName)
    if ([string]::IsNullOrWhiteSpace($safeFileName)) {
        throw 'The download did not provide a safe file name.'
    }

    $candidatePath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Join-Path $PWD $safeFileName
    } elseif (Test-Path -LiteralPath $OutputPath -PathType Container) {
        Join-Path $OutputPath $safeFileName
    } else {
        $OutputPath
    }

    $fullPath = [System.IO.Path]::GetFullPath($candidatePath)
    $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parentPath) -or -not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        throw 'The download destination parent directory does not exist.'
    }
    if ((Test-Path -LiteralPath $fullPath) -and -not $Force) {
        throw "The download destination already exists: '$fullPath'. Specify -Force to overwrite it."
    }

    return $fullPath
}
