Describe 'Identity timeline exact lower-bound tolerance' {
    BeforeEach {
        $caseRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item $caseRoot -ItemType Directory
    }
    It '<Worker> handles <Case> with raw pagination intact' -ForEach @(
        foreach ($worker in @('Get', 'Export')) {
            foreach ($case in @(
                @{ Case='short fractional interval'; From='01.5'; To='03.5'; Pages=@('03.5,03.4,01.5,01.0'); Size=10; Expected=@('03.4','01.5'); Upper=@(1767225604); Success=$true }
                @{ Case='integer logical lower boundary'; From='02.0'; To='04.0'; Pages=@('03.9,02.0,01.0'); Size=10; Expected=@('03.9','02.0'); Upper=@(1767225604); Success=$true }
                @{ Case='one tick above echoed lower'; From='01.0000001'; To='03.5'; Pages=@('01.0000001,01.0'); Size=10; Expected=@('01.0000001'); Upper=@(1767225604); Success=$true }
                @{ Case='full page counts lower echo and replays oldest second'; From='01.5'; To='03.5'; Pages=@('03.4,02.8,01.7,01.5,01.0','01.7,01.5,01.0'); Size=5; Expected=@('03.4','02.8','01.7','01.5'); Upper=@(1767225604,1767225602); Success=$true }
                @{ Case='padding-only full page retains raw progress'; From='01.5'; To='03.5'; Pages=@('03.8,03.6,01.0,01.0','01.0,01.0'); Size=4; Expected=@(); Upper=@(1767225604,1767225602); Success=$true }
                @{ Case='all-lower full page remains unpageable'; From='01.5'; To='03.5'; Pages=@('01.0,01.0'); Size=2; Expected=@(); Success=$false; Error='*complete*page*' }
                @{ Case='reversed raw padding order'; From='01.5'; To='03.5'; Pages=@('01.0,01.1'); Size=10; Expected=@(); Success=$false; Error='*descending timestamp order*' }
                @{ Case='one tick below sent lower'; From='01.5'; To='03.5'; Pages=@('00.9999999'); Size=10; Expected=@(); Success=$false; Error='*exclusive interval*' }
                @{ Case='equality at sent upper'; From='01.5'; To='03.5'; Pages=@('04.0'); Size=10; Expected=@(); Success=$false; Error='*exclusive interval*' }
                @{ Case='echo colliding with logical range fails'; From='02.0'; To='04.0'; Pages=@('02.0'); Size=10; Expected=@(); Success=$false; Error='*exclusive interval*'; Collision=$true }
            )) { $case + @{ Worker=$worker } }
        }
    ) {
        InModuleScope XDRInternals -Parameters @{ Root=$caseRoot; Worker=$Worker; From=$From; To=$To; Pages=$Pages; Size=$Size; Expected=$Expected; Upper=$Upper; Success=$Success; ErrorPattern=$Error; Collision=$Collision } {
            $script:LowerPages=$Pages; $script:LowerPageIndex=0
            $script:LowerRequests=[Collections.Generic.List[object]]::new()
            Mock Invoke-RestMethod {
                param($Body)
                $script:LowerRequests.Add(($Body | ConvertFrom-Json))
                if ($script:LowerPageIndex -ge $script:LowerPages.Count) { throw 'Unexpected extra page' }
                $rows=@($script:LowerPages[$script:LowerPageIndex++].Split(',') | ForEach-Object {
                    [pscustomobject]@{ Timestamp="2026-01-01T00:00:${_}Z"; EventId=$_ }
                })
                [pscustomobject]@{ count=$rows.Count; data=$rows; errors=[pscustomobject]@{} }
            }
            Mock Invoke-WebRequest { throw 'Unexpected transport' }
            $chunk=[pscustomobject]@{ Index=0; FromDate=[datetime]"2026-01-01T00:00:${From}Z"; ToDate=[datetime]"2026-01-01T00:00:${To}Z"; FileName='part.ndjson' }
            if ($Worker -eq 'Get') {
                $assignments=@((Get-Command Get-XdrIdentityUserTimeline).ScriptBlock.Ast.FindAll({ param($node)
                    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                    $node.Left.VariablePath.UserPath -eq 'chunkProcessingScript'
                }, $true))
                $assignments | Should -HaveCount 1
                $source=$assignments[0].Right.Extent.Text.Trim()
                $source=$source.Substring(1,$source.Length-2)
                # Exercise the explicit safety condition under a hypothetical tighter
                # envelope: equality must never discard a logically requested row.
                if ($Collision) { $source=$source.Replace('$fromUnix--', '$fromUnix = $fromOffset.ToUnixTimeSeconds()') }
                $run=[scriptblock]::Create($source)
                $result=& $run -chunk $chunk -userIds @{upn='synthetic'} -baseParams @{MaxRetries=1; RetryDelaySeconds=0; RequestTimeoutSec=10; PageSize=$Size} -tempPath $Root -cookieInfo @() -headerInfo @{} -baseUrl 'https://security.microsoft.com'
                $actual=if ($result.Success) { @((Get-Content $result.FilePath -Raw | ConvertFrom-Json).Events | ForEach-Object EventId) } else { @() }
            } else {
                $run=New-XdrIdentityTimelineExportWorker
                if ($Collision) {
                    $run=[scriptblock]::Create($run.ToString().Replace('$requestFromUnix = (& $getCeilingUnixSecond $chunkFromDate) - 1L', '$requestFromUnix = (& $getCeilingUnixSecond $chunkFromDate)'))
                }
                $result=& $run $chunk @{ PartsPath=$Root; BaseUrl='https://security.microsoft.com'; UserIdentifiers=@{upn='synthetic'}; CookieData=@(); HeadersData=@{}; PageSize=$Size; MaxRetries=1; RequestTimeoutSeconds=10 } ([Collections.Concurrent.ConcurrentDictionary[int,object]]::new())
                $actual=if ($result.Success) { @(Get-Content $result.FilePath | ForEach-Object { ($_ | ConvertFrom-Json).EventId }) } else { @() }
            }
            $result.Success | Should -Be $Success -Because $result.Error
            $script:LowerRequests | Should -HaveCount $Pages.Count
            foreach ($request in $script:LowerRequests) {
                $request.skip | Should -Be 0
                $request.filters.Timeframe.between[0] | Should -Be $(if ($Collision) {1767225602} else {1767225601})
            }
            if ($Success) {
                $result.EventCount | Should -Be $Expected.Count
                ($actual -join ',') | Should -BeExactly ($Expected -join ',')
                @($script:LowerRequests | ForEach-Object { $_.filters.Timeframe.between[1] }) | Should -Be $Upper
            } else {
                $result.Error | Should -BeLike $ErrorPattern
                $actual | Should -HaveCount 0
            }
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        }
    }

    It '<Worker> keeps adjacent half-open sets exact with lower-bound echoes' -ForEach @(@{Worker='Get'},@{Worker='Export'}) {
        InModuleScope XDRInternals -Parameters @{ Root=$caseRoot; Worker=$Worker } {
            Mock Invoke-RestMethod {
                param($Body)
                $bounds=($Body | ConvertFrom-Json).filters.Timeframe.between
                $from=[datetimeoffset]::FromUnixTimeSeconds($bounds[0]).UtcDateTime
                $to=[datetimeoffset]::FromUnixTimeSeconds($bounds[1]).UtcDateTime
                $rows=@(@('03.8','03.4','02.5','02.0','01.5','01.0') | ForEach-Object {
                    [pscustomobject]@{ Timestamp="2026-01-01T00:00:${_}Z"; EventId=$_ }
                } | Where-Object { ([datetime]$_.Timestamp).ToUniversalTime() -ge $from -and ([datetime]$_.Timestamp).ToUniversalTime() -lt $to })
                [pscustomobject]@{count=$rows.Count;data=$rows;errors=[pscustomobject]@{}}
            }
            if ($Worker -eq 'Get') {
                $assignment=(Get-Command Get-XdrIdentityUserTimeline).ScriptBlock.Ast.Find({param($node)
                    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -eq 'chunkProcessingScript'
                },$true)
                $source=$assignment.Right.Extent.Text.Trim();$run=[scriptblock]::Create($source.Substring(1,$source.Length-2))
            } else { $run=New-XdrIdentityTimelineExportWorker }
            $sets=@{}
            foreach ($range in @(@{Name='whole';From='01.5';To='03.5'},@{Name='left';From='01.5';To='02.0000001'},@{Name='right';From='02.0000001';To='03.5'})) {
                $root=Join-Path $Root $range.Name; $null=New-Item $root -ItemType Directory
                $chunk=[pscustomobject]@{Index=0;FromDate=[datetime]"2026-01-01T00:00:$($range.From)Z";ToDate=[datetime]"2026-01-01T00:00:$($range.To)Z";FileName='part.ndjson'}
                if ($Worker -eq 'Get') {
                    $result=& $run -chunk $chunk -userIds @{upn='synthetic'} -baseParams @{MaxRetries=1;RetryDelaySeconds=0;RequestTimeoutSec=10;PageSize=20} -tempPath $root -cookieInfo @() -headerInfo @{} -baseUrl 'https://security.microsoft.com'
                    $rows=if($result.Success){ @((Get-Content $result.FilePath -Raw | ConvertFrom-Json).Events) }else{@()}
                } else {
                    $result=& $run $chunk @{PartsPath=$root;BaseUrl='https://security.microsoft.com';UserIdentifiers=@{upn='synthetic'};CookieData=@();HeadersData=@{};PageSize=20;MaxRetries=1;RequestTimeoutSeconds=10} ([Collections.Concurrent.ConcurrentDictionary[int,object]]::new())
                    $rows=if($result.Success){@(Get-Content $result.FilePath|ForEach-Object{$_|ConvertFrom-Json})}else{@()}
                }
                $result.Success | Should -BeTrue -Because $result.Error
                $sets[$range.Name]=@($rows.EventId)
            }
            $sets.whole | Should -Be @('03.4','02.5','02.0','01.5')
            $sets.left | Should -Be @('02.0','01.5')
            $sets.right | Should -Be @('03.4','02.5')
            @($sets.left+$sets.right|Sort-Object) | Should -Be @($sets.whole|Sort-Object)
            Should -Invoke Invoke-RestMethod -Times 3 -Exactly
        }
    }
}
