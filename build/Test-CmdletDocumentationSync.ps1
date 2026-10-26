<#
.SYNOPSIS
    Verifies committed generated cmdlet documentation without changing the working tree.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outputs = @('README.md', 'XDRInternals/XDRInternals.psd1', 'XDRay/CmdletApiMapping.json', 'XDRay Firefox/CmdletApiMapping.json')

foreach ($output in $outputs) {
    & git -C $repoRoot ls-files --error-unmatch -- $output *> $null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $repoRoot $output) -PathType Leaf)) {
        throw "Generated output must exist and be tracked: $output"
    }
}
$dirty = & git -C $repoRoot status --porcelain --untracked-files=all -- $outputs
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect generated output status.' }
if ($dirty) { throw 'Generated outputs have local changes. Preserve and commit them before verification; no files were changed.' }

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('cmdlet-docs-' + [guid]::NewGuid())
try {
    $null = New-Item -ItemType Directory -Path $fixture
    # Include internal catalogs and any other module inputs, without importing the module.
    Copy-Item -LiteralPath (Join-Path $repoRoot 'XDRInternals') -Destination $fixture -Recurse
    foreach ($output in $outputs) {
        $target = Join-Path $fixture $output
        $null = New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force
        Copy-Item -LiteralPath (Join-Path $repoRoot $output) -Destination $target -Force
    }
    $null = New-Item -ItemType Directory -Path (Join-Path $fixture 'build')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Sync-CmdletDocumentation.ps1') -Destination (Join-Path $fixture 'build')
    & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -File (Join-Path $fixture 'build/Sync-CmdletDocumentation.ps1')
    if ($LASTEXITCODE -ne 0) { throw "Documentation generation failed (exit $LASTEXITCODE)." }

    $drift = foreach ($output in $outputs) {
        $generated = Join-Path $fixture $output
        if (-not (Test-Path -LiteralPath $generated -PathType Leaf)) { throw "Generator omitted output: $output" }
        if ((Get-FileHash -LiteralPath $generated).Hash -ne (Get-FileHash -LiteralPath (Join-Path $repoRoot $output)).Hash) { $output }
    }
    if ($drift) { throw "Generated documentation is stale: $($drift -join ', '). Run ./build/Sync-CmdletDocumentation.ps1 and commit all four outputs in this PR." }
    Write-Host 'All four generated documentation outputs are synchronized.'
} finally {
    # This literal path is created above, under the system temporary directory.
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
