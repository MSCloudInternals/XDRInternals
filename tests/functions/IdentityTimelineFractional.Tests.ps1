BeforeAll {
    if (-not ('IdentityTimelineFractionalJob' -as [type])) {
        Add-Type @'
using System.Management.Automation;
public sealed class IdentityTimelineFractionalJob : Job {
    public IdentityTimelineFractionalJob() : base("synthetic", "payload") { SetJobState(JobState.Completed); }
    public override string StatusMessage => string.Empty;
    public override bool HasMoreData => false;
    public override string Location => "localhost";
    public override void StopJob() { }
}
'@
    }
}
Describe 'Identity timeline fractional API envelope' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrIdentityUser { [pscustomobject]@{ displayName = 'Synthetic'; ids = [pscustomobject]@{ upn = 'synthetic@example.invalid' } } } -ModuleName XDRInternals
        InModuleScope XDRInternals { $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new(); $script:headers = @{} }
        $script:PayloadWorkerResults = @()
        Mock Start-ThreadJob {
            param($ArgumentList)
            $script:PayloadWorkerResults = @(InModuleScope XDRInternals -Parameters @{ Arguments = $ArgumentList } {
                param($Arguments)
                $worker = [scriptblock]::Create($Arguments[8])
                foreach ($chunk in $Arguments[0]) {
                    & $worker -chunk $chunk -userIds $Arguments[2] -baseParams $Arguments[3] -tempPath $Arguments[4] -cookieInfo $Arguments[5] -headerInfo $Arguments[6] -baseUrl $Arguments[7]
                }
            })
            [IdentityTimelineFractionalJob]::new()
        } -ModuleName XDRInternals
        Mock Receive-Job { $script:PayloadWorkerResults } -ModuleName XDRInternals
        Mock Remove-Job {} -ModuleName XDRInternals
        Mock Invoke-WebRequest { throw 'Unexpected web request' } -ModuleName XDRInternals
    }
    It 'handles <Case> without confusing logical padding and API violations' -ForEach @(
        @{ Case = 'both margins and exact logical boundaries'; Pages = @('02.900,02.750,02.749,00.250,00.100'); PageSize = 10; Expected = @('at-02.749','at-00.250'); UpperBounds = @(1767225603); Fails = $false }
        @{ Case = 'full pages withholding the oldest raw second'; Pages = @('02.900,02.749,01.900,01.100','01.900,01.100,00.250,00.100','00.250,00.100'); PageSize = 4; Expected = @('at-02.749','at-01.900','at-01.100','at-00.250'); UpperBounds = @(1767225603,1767225602,1767225601); Fails = $false }
        @{ Case = 'padding-only full page still advances'; Pages = @('02.900,00.100','00.100'); PageSize = 2; Expected = @(); UpperBounds = @(1767225603,1767225601); Fails = $false }
        @{ Case = 'exclusive API lower bound violation'; Pages = @('00.000'); PageSize = 10; Expected = @(); Fails = $true }
        @{ Case = 'exclusive API upper bound violation'; Pages = @('03.000'); PageSize = 10; Expected = @(); Fails = $true }
        @{ Case = 'padding participates in raw ordering'; Pages = @('02.500,02.900'); PageSize = 10; Expected = @(); Fails = $true }
        @{ Case = 'padding-filled single second remains unpageable'; Pages = @('02.900,02.800'); PageSize = 2; Expected = @(); Fails = $true }
    ) {
        $script:FractionalPages = $Pages
        $script:FractionalCall = 0
        $script:FractionalUpperBounds = [System.Collections.Generic.List[long]]::new()
        Mock Invoke-RestMethod {
            param($Body)
            $request = $Body | ConvertFrom-Json
            $request.skip | Should -Be 0
            $request.filters.Timeframe.between[0] | Should -Be 1767225600
            $script:FractionalUpperBounds.Add($request.filters.Timeframe.between[1])
            if ($script:FractionalCall -ge $script:FractionalPages.Count) { throw 'Unexpected extra page' }
            $events = @($script:FractionalPages[$script:FractionalCall].Split(',') | ForEach-Object {
                [pscustomobject]@{ EventId = "at-$_"; Timestamp = "2026-01-01T00:00:${_}Z" }
            })
            $script:FractionalCall++
            [pscustomobject]@{ count = $events.Count; data = $events; errors = $null }
        } -ModuleName XDRInternals
        $parameters = @{ Upn = 'synthetic@example.invalid'; FromDate = [datetime]'2026-01-01T00:00:00.250Z'; ToDate = [datetime]'2026-01-01T00:00:02.750Z'; OutputPath = $TestDrive; MaxRetries = 1; PageSize = $PageSize; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
        if ($Fails) {
            { Get-XdrIdentityUserTimeline @parameters 6>$null } | Should -Throw '*failed for*'
            $script:PayloadWorkerResults[0].Success | Should -BeFalse
        } else {
            $result = @(Get-XdrIdentityUserTimeline @parameters 6>$null)
            $script:PayloadWorkerResults[0].Success | Should -BeTrue
            $script:PayloadWorkerResults[0].EventCount | Should -Be $Expected.Count
            @($result.EventId) | Should -Be $Expected
            @($script:FractionalUpperBounds.ToArray()) | Should -Be $UpperBounds
        }
        Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 0 -Exactly
    }
    It 'preserves exact half-open membership across adjacent fractional windows' {
        Mock Invoke-RestMethod {
            param($Body)
            $bounds = ($Body | ConvertFrom-Json).filters.Timeframe.between
            $from = [datetimeoffset]::FromUnixTimeSeconds($bounds[0]).UtcDateTime
            $to = [datetimeoffset]::FromUnixTimeSeconds($bounds[1]).UtcDateTime
            $events = @(@('02.900','02.749','01.250','01.249','00.250','00.100') | ForEach-Object {
                [pscustomobject]@{ EventId = "at-$_"; Timestamp = "2026-01-01T00:00:${_}Z" }
            } | Where-Object { ([datetime]$_.Timestamp).ToUniversalTime() -gt $from -and ([datetime]$_.Timestamp).ToUniversalTime() -lt $to })
            [pscustomobject]@{ count = $events.Count; data = $events; errors = $null }
        } -ModuleName XDRInternals
        $parameters = @{ Upn = 'synthetic@example.invalid'; OutputPath = $TestDrive; MaxRetries = 1; ErrorAction = 'Stop' }
        $left = @(Get-XdrIdentityUserTimeline @parameters -FromDate ([datetime]'2026-01-01T00:00:00.250Z') -ToDate ([datetime]'2026-01-01T00:00:01.250Z') 6>$null)
        $right = @(Get-XdrIdentityUserTimeline @parameters -FromDate ([datetime]'2026-01-01T00:00:01.250Z') -ToDate ([datetime]'2026-01-01T00:00:02.750Z') 6>$null)
        @($left.EventId) | Should -Be @('at-01.249','at-00.250')
        @($right.EventId) | Should -Be @('at-02.749','at-01.250')
        @(@($left.EventId) + @($right.EventId) | Select-Object -Unique) | Should -HaveCount 4
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
    }
}
