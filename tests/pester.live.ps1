param (
	[string]$LiveConfigurationPath,

	[switch]$EnableLiveTests,

	[switch]$EnableMutationTests,
	
	[ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')]
	[Alias('Show')]
	$Output = "None",
	
	$Include = "*",
	
	$Exclude = ""
)

Write-Host "Starting Live Tests"

if ($LiveConfigurationPath) {
	$env:XDRINTERNALS_TEST_CONFIG_PATH = (Resolve-Path $LiveConfigurationPath).Path
}
if ($EnableLiveTests) {
	$env:XDRINTERNALS_ENABLE_LIVE_TESTS = 'true'
}
if ($EnableMutationTests) {
	$env:XDRINTERNALS_ENABLE_MUTATION_TESTS = 'true'
}

Write-Host "Importing Module"

$global:testroot = $PSScriptRoot
$global:__pester_data = @{ }

Remove-Module XDRInternals -ErrorAction Ignore
Import-Module "$PSScriptRoot\..\XDRInternals\XDRInternals.psd1"
Import-Module "$PSScriptRoot\..\XDRInternals\XDRInternals.psm1" -Force

Import-Module Pester

Write-Host "Creating test result folder"
$null = New-Item -Path "$PSScriptRoot\.." -Name TestResults -ItemType Directory -Force

$totalFailed = 0
$totalRun = 0

$testresults = @()
$config = [PesterConfiguration]::Default
$config.TestResult.Enabled = $true

Write-Host "Proceeding with live tests"
foreach ($file in (Get-ChildItem "$PSScriptRoot\live" -Recurse -File | Where-Object Name -like "*Tests.ps1"))
{
	if ($file.Name -notlike $Include) { continue }
	if ($file.Name -like $Exclude) { continue }

	Write-Host "  Executing $($file.Name)"
	$config.TestResult.OutputPath = Join-Path "$PSScriptRoot\..\TestResults" "TEST-$($file.BaseName).xml"
	$config.Run.Path = $file.FullName
	$config.Run.PassThru = $true
	$config.Output.Verbosity = $Output
	$results = Invoke-Pester -Configuration $config
	foreach ($result in $results)
	{
		$totalRun += $result.TotalCount
		$totalFailed += $result.FailedCount
		$result.Tests | Where-Object Result -ne 'Passed' | ForEach-Object {
			$testresults += [pscustomobject]@{
				Block    = $_.Block
				Name	 = "It $($_.Name)"
				Result   = $_.Result
				Message  = $_.ErrorRecord.DisplayErrorMessage
			}
		}
	}
}

$testresults | Sort-Object Block, Name, Result, Message | Format-List

if ($totalFailed -eq 0) { Write-Host "All $totalRun live tests executed without a single failure!" }
else { Write-Host "$totalFailed live tests out of $totalRun tests failed!" }

if ($totalFailed -gt 0)
{
	throw "$totalFailed / $totalRun live tests failed!"
}
