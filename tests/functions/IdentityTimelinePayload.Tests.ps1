BeforeAll {
    if (-not ('IdentityTimelinePayloadJob' -as [type])) {
        Add-Type @'
using System.Management.Automation;
public sealed class IdentityTimelinePayloadJob : Job {
    public IdentityTimelinePayloadJob() : base("synthetic", "payload") { SetJobState(JobState.Completed); }
    public override string StatusMessage => string.Empty;
    public override bool HasMoreData => false;
    public override string Location => "localhost";
    public override void StopJob() { }
}
'@
    }
}
Describe 'Identity timeline structural payload preservation' {
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
            [IdentityTimelinePayloadJob]::new()
        } -ModuleName XDRInternals
        Mock Receive-Job { $script:PayloadWorkerResults } -ModuleName XDRInternals
        Mock Remove-Job {} -ModuleName XDRInternals
        Mock Invoke-WebRequest { throw 'Unexpected web request' } -ModuleName XDRInternals
    }
    It 'preserves <Case> with EventId=<HasEventId> in worker and final merge' -ForEach @(
        foreach ($hasId in @($true, $false)) {
            foreach ($testCase in @(
        @{ Case = 'empty array versus null'; Values = '[[],null]'; Expected = 2 }
        @{ Case = 'singleton array versus scalar'; Values = '[["x"],"x"]'; Expected = 2 }
        @{ Case = 'nested array versus flat array'; Values = '[[["x"]],["x"]]'; Expected = 2 }
        @{ Case = 'nested empty array versus null element'; Values = '[[[]],[null]]'; Expected = 2 }
        @{ Case = 'object property ordering equivalence'; Values = '[{"a":1,"b":2},{"b":2,"a":1}]'; Expected = 1 }
            )) { $testCase + @{ HasEventId = $hasId } }
        }
    ) {
        $valuesObject = ('{"values":' + $Values + '}') | ConvertFrom-Json
        $script:PayloadEvents = @(
            for ($i = 0; $i -lt $valuesObject.values.Count; $i++) {
                $event = [pscustomobject]@{ EventId = 'same'; Timestamp = '2026-01-01T00:30:00Z'; Value = $valuesObject.values[$i]; Id = "volatile-$i"; Description = "volatile-$i"; RowNumber = $i }
                if (-not $HasEventId) { $event.PSObject.Properties.Remove('EventId') }
                $event
            }
        )
        Mock Invoke-RestMethod { [pscustomobject]@{ count = $script:PayloadEvents.Count; data = $script:PayloadEvents; errors = $null } } -ModuleName XDRInternals
        $result = @(Get-XdrIdentityUserTimeline -Upn 'synthetic@example.invalid' -FromDate ([datetime]'2026-01-01T00:00:00Z') -ToDate ([datetime]'2026-01-01T01:00:00Z') -OutputPath $TestDrive -MaxRetries 1 -ErrorAction Stop 6>$null)
        $script:PayloadWorkerResults | Should -HaveCount 1
        $script:PayloadWorkerResults[0].Success | Should -BeTrue
        $script:PayloadWorkerResults[0].EventCount | Should -Be $Expected
        $result | Should -HaveCount $Expected
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly
        Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 0 -Exactly
    }
}
