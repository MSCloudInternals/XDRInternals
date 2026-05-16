param(
    [string]$BenchmarkConfigurationPath,

    [switch]$EnableBenchmarks,

    [ValidateSet('None', 'Normal', 'Detailed')]
    [Alias('Show')]
    [string]$Output = 'Normal',

    [string]$Include = '*',

    [string]$Exclude = ''
)

Write-Host 'Starting device timeline benchmarks'

$helperPath = Join-Path $PSScriptRoot 'helpers\Xdr.BenchmarkHelpers.ps1'
. $helperPath

$settings = Get-XdrBenchmarkSettings -ConfigurationPath $BenchmarkConfigurationPath
if ($EnableBenchmarks) {
    $settings.benchmarks.enabled = $true
}

if ($Output -ne 'None') {
    Write-Host "Using benchmark configuration: $($settings.__meta.configurationPath)"
}

$suiteResult = Invoke-XdrBenchmarkSuite -Settings $settings -Include $Include -Exclude $Exclude

if ($Output -in @('Normal', 'Detailed')) {
    Write-Host "Batch: $($suiteResult.batchId)"
    Write-Host "Captured ToDate: $($suiteResult.capturedToDate)"
    Write-Host "Results: $($suiteResult.resultsPath)"
    Write-Host "Summary: $($suiteResult.summaryPath)"

    foreach ($comparison in @($suiteResult.summary.comparisons)) {
        Write-Host ("{0} | main={1}s | current={2}s | delta={3}s ({4}%)" -f `
                $comparison.comparisonKey,
                $comparison.medianMainSeconds,
                $comparison.medianCurrentSeconds,
                $comparison.currentMinusMainSeconds,
                $comparison.currentVsMainPercent)
    }
}
