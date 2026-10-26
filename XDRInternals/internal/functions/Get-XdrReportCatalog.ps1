function Get-XdrReportCatalog {
    <#
    .SYNOPSIS
        Gets observed Defender portal report request definitions.

    .DESCRIPTION
        Defines read operations discovered from portal navigation, HAR captures, and nodoc.
        Query and body placeholders are resolved against the active session and requested dates.

    .EXAMPLE
        Get-XdrReportCatalog
        Lists the supported report request definitions.
    #>
    [CmdletBinding()]
    param ()

    $groups = @(
        @{ Family = 'DeviceControl'; Root = '/apiproxy/mdepdevicecontrol/m365/devicecontrolservice/'; Names = @('SummaryStatistics', 'Policies', 'CookMark', 'EventDetails', 'AhQuery') }
        @{ Family = 'DeviceHealth'; Root = '/apiproxy/mtp/mdepDnH/reports/machineHealth/'; Names = @('healthStatus', 'osPlatform', 'osVersion'); Query = @{ fromDate = '{FromDate}'; toDate = '{ToDate}'; alignToPeriod = 'true' } }
        @{ Family = 'AntivirusHealth'; Root = '/apiproxy/mtp/tvm/analytics/deviceHealth/'; Names = @('avsignature', 'avengine', 'avplatform', 'avscan', 'avmode') }
        @{ Family = 'VulnerableDevices'; Root = '/apiproxy/mtp/tvm/analytics/vulnerableDevicesReport/'; Names = @('severityLevel', 'exploitAvailability', 'vulnerabilityAge', 'operationSystem'); Query = @{ '$filter' = '(date ge {FromDate} and date le {ToDate})' } }
        @{ Family = 'AttackSurfaceReduction'; Root = '/apiproxy/mdepasrdetections/m365/reporting/asrinsights/'; Names = @('AsrDetections', 'AsrDetectionsTrend', 'TopFiles') }
        @{ Family = 'AttackSurfaceReductionConfiguration'; Root = '/apiproxy/mtp/tvm/analytics/asrconfiguration/'; Names = @('MachineSecurityStates', 'configurationstates') }
        @{ Family = 'WebThreat'; Root = '/apiproxy/mtp/webThreatProtection/webThreats/reports/'; Names = @('webThreatHealthStatus', 'webThreatSummary') }
        @{ Family = 'WebContentFiltering'; Root = '/apiproxy/mtp/webThreatProtection/WebContentFiltering/Reports/'; Names = @('TopParentCategories', 'CategoryReports', 'DomainReports', 'MachineList', 'CategoryLookup') }
        @{ Family = 'UnifiedSecurity'; Root = '/apiproxy/mtp/phoenixValueReflectionApi/'; Names = @('secure-score', 'saas-score', 'phishing-ransomware', 'devices', 'mdi/mpu', 'disrupt', 'disrupt/incidents', 'avblocks', 'webcontentfiltering', 'emails/blocked', 'summary', 'summary/trend', 'custom-detection', 'incidents/top', 'autoir', 'emails/zapped', 'optimize/coverage/threat', 'optimize/coverage/risk'); Query = @{ lookbackDays = '{LookbackInDays}' } }
    )
    foreach ($group in $groups) {
        foreach ($reportName in $group.Names) {
            $query = @{}
            if ($group.Query) {
                foreach ($key in $group.Query.Keys) { $query[$key] = $group.Query[$key] }
            }
            if ($group.Family -eq 'DeviceControl' -and $reportName -eq 'SummaryStatistics') { $query.lookbackInDays = '{LookbackInDays}' }
            if ($group.Family -eq 'DeviceControl' -and $reportName -in @('EventDetails', 'AhQuery')) {
                $query = @{ lookbackInDays = '{LookbackInDays}'; actionMode = $null; deviceClassName = $null; deviceId = $null; policies = $null }
            }
            if ($group.Family -eq 'WebThreat' -and $reportName -eq 'webThreatHealthStatus') { $query.lookBackInDays = '{LookbackInDays}' }
            if ($group.Family -eq 'WebContentFiltering' -and $reportName -ne 'CategoryLookup') {
                $query.lookBackInDays = '{LookbackInDays}'
                if ($reportName -eq 'TopParentCategories') { $query.includeActivityChange = 'true' } else {
                    $query.rbacGroupIds = $null
                    if ($reportName -ne 'MachineList') { $query.parentCategory = $null; $query.activityType = $null }
                }
            }
            if ($reportName -in @('AsrDetections', 'AsrDetectionsTrend')) { $query['$filter'] = 'eventTime ge {FromDate} and eventTime le {ToDate}' }
            if ($reportName -eq 'AsrDetections') { $query['$orderby'] = 'eventTime desc'; $query['$top'] = '{Top}' }
            if ($reportName -eq 'TopFiles') { $query['$top'] = '{Top}' }
            if ($reportName -eq 'configurationstates') { $query.asrRuleIds = 'e6db77e5-3df2-4cf1-b95a-636979351e5b,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,56a863a9-875e-4185-98a7-b882c64b5ce5' }
            $method = 'Get'
            $body = $null
            if ($reportName -eq 'CategoryLookup') { $method = 'Post'; $body = @{ Url = 'https://www.microsoft.com' } }
            [pscustomobject]@{ Name = "$($group.Family).$($reportName.Replace('/', '.'))"; Family = $group.Family; Method = $method; Path = $group.Root + $reportName; Query = $query; Body = $body; Source = 'HAR' }
        }
    }
    foreach ($direction in @('firewallInbound', 'firewallOutbound', 'firewallBlockedApp')) {
        $names = if ($direction -eq 'firewallBlockedApp') { @('blockSummary', 'topBlockedAppProcesses', 'topBlockedAppComputers', 'blockedAppProfileConnection') } else { @('blockSummary', 'topLocalPorts', 'topProcesses', 'topComputers', 'topRemoteIPsToComputers', 'topRemoteIPsToConnections') }
        foreach ($reportName in $names) {
            [pscustomobject]@{ Name = "Firewall.$direction.$reportName"; Family = 'Firewall'; Method = 'Get'; Path = "/apiproxy/mdepfirewall/m365/firewallservice/$direction/$reportName"; Query = @{}; Body = $null; Source = 'HAR' }
            if ($reportName -ne 'blockedAppProfileConnection') {
                [pscustomobject]@{ Name = "Firewall.$direction.${reportName}AhQuery"; Family = 'Firewall'; Method = 'Get'; Path = "/apiproxy/mdepfirewall/m365/firewallservice/$direction/${reportName}AhQuery"; Query = @{}; Body = $null; Source = 'HAR' }
            }
        }
    }
    foreach ($reportName in @('allDomains', 'urls', 'exposedMachines')) {
        $query = @{ lookBackInDays = '{LookbackInDays}'; webThreatCategory = 'Any'; status = '0'; severity = '0' }
        $requiredParameters = @()
        if ($reportName -ne 'allDomains') {
            $query.id = $null
            $query.fullList = 'false'
            $requiredParameters = @('id')
        }
        [pscustomobject]@{ Name = "WebThreat.$reportName"; Family = 'WebThreat'; Method = 'Get'; Path = "/apiproxy/mtp/webThreatProtection/webThreats/domains/$reportName/"; Query = $query; Body = $null; RequiredParameters = $requiredParameters; Source = 'HAR client' }
    }
    foreach ($provider in @('SecureScore', 'DeviceInventory', 'WebContentFiltering', 'Incidents')) {
        [pscustomobject]@{ Name = "MonthlySecurity.$provider"; Family = 'MonthlySecurity'; Method = 'Get'; Path = '/apiproxy/mtp/valueReport/mdb/securityreport/test/providers/fetch'; Query = @{ dataProviders = $provider; lookBackDays = '{LookbackInDays}' }; Body = $null; Source = 'HAR' }
    }
    [pscustomobject]@{ Name = 'Hunting.Quota'; Family = 'Hunting'; Method = 'Get'; Path = '/apiproxy/hunting/huntingService/reports/quota'; Query = @{ aggregationType = 'Average'; startTime = '{FromDate}'; endTime = '{ToDate}' }; Body = $null; Source = 'HAR' }
    [pscustomobject]@{ Name = 'Hunting.QueryResources'; Family = 'Hunting'; Method = 'Post'; Path = '/apiproxy/hunting/huntingService/reports'; Query = @{}; Body = @{ startTime = '{FromDate}'; endTime = '{ToDate}' }; Source = 'HAR' }

    $emailReports = @(
        @{ Id = 'TPSAggregateReportATP'; Summary = 'AggTPSReportData'; Body = @{ DetectionFilter = @('ATP', 'EOP'); PolicyType = @('AntiMalwarePolicy', 'SafeAttachmentPolicy', 'AntiPhishPolicy', 'HostedContentFilterPolicy', 'ExchangeTransportRule', 'Unknown'); EventType = @('File Detonation', 'Anti-malware Engine', 'URL Detonation Malware', 'File Reputation', 'FileHashList', 'URLList Malware', 'Url Reputation Malware', 'Campaign Malware', 'URLList', 'Advanced phish filter', 'General phish filter', 'Anti-spoof: Intra-org', 'Anti-spoof: external domain', 'Brand Impersonation', 'Dmarc', 'Mixed analysis detection', 'FileHashList Phish', 'Fingerprint matching', 'Url Reputation', 'URL Detonation Phish', 'User Impersonation', 'Domain Impersonation', 'Mailbox intelligence impersonation', 'File Detonation Phish', 'File Reputation Phish', 'Campaign Phish', 'LLM content analysis', 'Prompt Injection Protection', 'URL Malicious Reputation - Spam', 'Advanced Filter - Spam', 'General Filter - Spam', 'Mixed Analysis Detection - Spam', 'Fingerprint Matching - Spam', 'Domain Reputation - Spam', 'IPList', 'Bulk', 'Mail bombing', 'MalwareEngine - Content Malware', 'FileDetonation - Content Malware', 'FileReputation - Content Malware') } }
        @{ Id = 'ZapReport'; Summary = 'AggZapReport'; Detail = 'DetailZapReport'; Body = @{ EventType = @('NotSpamZAP', 'SpamZAP', 'PhishZAP', 'MalwareZAP') } }
        @{ Id = 'URLProtectionActionReport'; Summary = 'AggSafeLinksReport'; Detail = 'DetailSafeLinksReport'; Body = @{ Action = @('Blocked', 'TenantBlocked', 'ClickedEvenBlocked', 'TenantBlockedAndClickedThrough', 'ClickedDuringScan', 'Scanning'); DisplayBy = 'Action'; App = @('Email Client', 'OfficeDocs', 'Teams', 'Copilot'); EvalValue = @('Default') } }
        @{ Id = 'TopMalware'; Summary = 'MailTrafficSummaryReport'; Detail = 'MailTrafficSummaryReport'; Body = @{ Category = 'TopMalware' } }
        @{ Id = 'SpoofMailReport'; Summary = 'SpoofMailCompAuthReport'; Detail = 'SpoofMailReport'; Body = @{ EventType = 'SpoofMailCompAuthResult'; Action = @('pass', 'fail', 'softpass', 'none', 'other'); SpoofType = @('Internal', 'External') } }
        @{ Id = 'CompromisedUsers'; Summary = 'AggCompromiseReport'; Detail = 'CompromiseReportDetailData'; Body = @{ Action = @('Restricted', 'Suspicious') } }
    )
    foreach ($report in $emailReports) {
        [pscustomobject]@{ Name = "Email.$($report.Id).Definition"; Family = 'Email'; Method = 'Get'; Path = '/api/Report/GetReportDefinition/'; Query = @{ reportId = $report.Id }; Body = $null; Source = 'Browser' }
        foreach ($view in @('Summary', 'Detail')) {
            if (-not $report[$view]) { continue }
            $body = @{ StartDate = '{FromDate}'; EndDate = '{ToDate}' }
            if (-not ($report.Id -eq 'SpoofMailReport' -and $view -eq 'Detail')) {
                foreach ($key in $report.Body.Keys) { $body[$key] = $report.Body[$key] }
            }
            if ($view -eq 'Detail' -and $report.Id -in @('URLProtectionActionReport', 'CompromisedUsers')) { $body.UserTag = @('') }
            [pscustomobject]@{ Name = "Email.$($report.Id).$view"; Family = 'Email'; Method = 'Post'; Path = "/api/Report/GetReport${view}Data/"; Query = @{ reportId = $report.Id; dataSourceId = $report[$view] }; Body = $body; Source = 'Browser' }
        }
    }
    foreach ($endpoint in @('MailLatencyData', 'MailLatencyDataExtension')) {
        $filter = "MailLatencyMessageView eq 'AllMessages'"
        if ($endpoint -eq 'MailLatencyData') { $filter += " and MailLatencyStatisticsName eq 'P50'" }
        [pscustomobject]@{ Name = "Email.$endpoint"; Family = 'Email'; Method = 'Get'; Path = "/apiproxy/di/Find/$endpoint"; Query = @{ tenantid = '{TenantId}'; StartTime = '{FromDate}'; EndTime = '{ToDate}'; PageSize = '{Top}'; Filter = $filter }; Body = $null; Source = 'Browser' }
    }
    foreach ($category in @('TopMailSender', 'TopMailRecipient')) {
        [pscustomobject]@{ Name = "Email.$category"; Family = 'Email'; Method = 'Get'; Path = '/apiproxy/di/Find/MailTopTrafficReport'; Query = @{ tenantid = '{TenantId}'; startTime = '{FromDate}'; endTime = '{ToDate}'; filter = "Category eq '$category' and TagIds eq 'All'" }; Body = $null; Source = 'Browser' }
    }
    foreach ($channel in @('User', 'Admin')) {
        $channelFilter = if ($channel -eq 'User') { @{ Name = 'Channel'; Op = 'any'; Value = '1,4,5,6'; ValueType = 'int32' } } else { @{ Name = 'Channel'; Op = 'eq'; Value = 2; ValueType = 'int32' } }
        $query = @{ tenantid = '{TenantId}'; StartTime = '{FromDate}'; EndTime = '{ToDate}' }
        [pscustomobject]@{ Name = "Email.${channel}Submissions.Detail"; Family = 'Email'; Method = 'Post'; Path = '/apiproxy/di/Search/SubmissionDIESData'; Query = $query; Body = @{ WaterMark = ''; PageSize = 100; QueryFilter = @{ Filter = $channelFilter } }; Source = 'Browser' }
        $pivot = if ($channel -eq 'User') { 'SubmissionCategory' } else { 'SubmissionStatus' }
        [pscustomobject]@{ Name = "Email.${channel}Submissions.Summary"; Family = 'Email'; Method = 'Post'; Path = '/apiproxy/di/Search/SubmissionDIESDataAggregation'; Query = $query; Body = @{ WaterMark = $null; PageSize = 100; QueryFilter = @{ Filter = @{ Name = ''; ValueType = 'string'; Value = ''; Op = 'and' }; Expressions = @(@{ Filter = $channelFilter }, @{ Filter = @{ Name = 'Interval'; Op = 'eq'; Value = '4'; ValueType = 'string' } }, @{ Filter = @{ Name = 'PivotBy'; Op = 'eq'; Value = $pivot; ValueType = 'string' } }) } }; Source = 'Browser' }
    }
    [pscustomobject]@{ Name = 'CloudApps.ExportedReports.Metadata'; Family = 'CloudApps'; Method = 'Get'; Path = '/apiproxy/mcas/cas/api/v1/custom_reports/metadata/'; Query = @{}; Body = $null; Source = 'Browser' }
    [pscustomobject]@{ Name = 'CloudApps.ExportedReports'; Family = 'CloudApps'; Method = 'Post'; Path = '/apiproxy/mcas/cas/api/v1/custom_reports/'; Query = @{}; Body = @{ skip = 0; limit = 20; filters = @{}; performAsyncTotal = $false; sortDirection = 'desc'; sortField = 'created' }; Source = 'Browser' }
    foreach ($catalog in @('public-catalog', 'executive-catalog', 'personal-catalog')) {
        [pscustomobject]@{ Name = "Cloud.$catalog"; Family = 'Cloud'; Method = 'Get'; Path = "/apiproxy/mdc/dashboards/$catalog/rule-collections"; Query = @{ '$expand' = 'Rules'; '$filter' = $null }; Body = $null; Source = 'Browser' }
    }
    foreach ($report in @(
        @{ Name = 'CnappExecutiveSummary'; Identifier = '901899bd-08ca-4484-bb87-4bb9e98dfc74' }
        @{ Name = 'CloudPosture'; Identifier = '8cd8e724-0a8a-4118-86d2-76bb63db0f78' }
    )) {
        [pscustomobject]@{ Name = "Cloud.$($report.Name).Definition"; Family = 'Cloud'; Method = 'Get'; Path = '/apiproxy/mdc/dashboards/public-catalog/rule-collections'; Query = @{ '$filter' = "Identifier Eq $($report.Identifier)"; '$expand' = 'Rules' }; Body = $null; Source = 'Browser' }
    }
    [pscustomobject]@{ Name = 'Cloud.Coverage.Schema'; Family = 'Cloud'; Method = 'Post'; Path = '/apiproxy/mdc/views/dashboards/schema'; Query = @{ c = 'en-us'; v = '1.0.3236.0' }; Body = @{ schemaId = 'dashboardsAndReports_CoverageByPlan' }; Source = 'Browser' }
    foreach ($chart in @('AlertsData', 'CoverageByWorkload', 'CoverageByPlan', 'RegulatoryCompliance', 'RemediationEffort', 'TopCloudCVEs', 'TopCloudRecommendations', 'TopRecommendationsByCriticality', 'AssetCountByCriticality', 'AssetCountByCloudProvider', 'RecommendationCountByCloudProvider', 'AssetCountByCloudWorkload', 'RecommendationCountByCategory', 'RecommendationCountByWorkload', 'CloudVulnerabilitiesRecommendationCountByFixAvailable', 'CloudCvesInsights')) {
        $path = if ($chart -eq 'TopCloudCVEs') { '/apiproxy/mdc/views/vulnerabilities/topCloudCVEsItems' } else { '/apiproxy/mdc/views/dashboards/items' }
        [pscustomobject]@{ Name = "Cloud.$chart"; Family = 'Cloud'; Method = 'Post'; Path = $path; Query = @{ c = 'en-us'; v = '1.0.3236.0' }; Body = @{ schemaId = "dashboardsAndReports_$chart"; paging = @{ pageSize = '{Top}' }; filters = @() }; Source = 'Browser client' }
    }
    foreach ($dimension in @('Workload', 'Scope')) {
        [pscustomobject]@{ Name = "Cloud.SecureScoreBy$dimension"; Family = 'Cloud'; Method = 'Post'; Path = '/apiproxy/mdc/views/secureScore/items'; Query = @{ c = 'en-us'; v = '1.0.3236.0' }; Body = @{ schemaId = "CloudInitiative_SecureScoreBy$dimension"; schemaParameters = @{ startDate = '{FromDate}' }; paging = @{ pageSize = '{Top}' }; filters = @() }; Source = 'Browser client' }
    }
    [pscustomobject]@{ Name = 'Cloud.DcspmCoverageByScope'; Family = 'Cloud'; Method = 'Post'; Path = '/apiproxy/mdc/views/dashboards/metrics'; Query = @{ c = 'en-us'; v = '1.0.3236.0' }; Body = @{ schemaId = 'dashboardsAndReports_DcspmCoverageByScope'; aggregatedColumns = @(@{ id = 'CriticalAssetsCount' }, @{ id = 'DcspmEnabledCount' }, @{ id = 'DcspmNotEnabledCount' }, @{ id = 'IsPartiallyCoveredCount' }); filters = @() }; Source = 'Browser client' }
    foreach ($metric in @(
        @{ Name = 'SecureScore.Trend'; Id = 'bfe1ef21-4a0f-4403-8c3b-974634756076'; Filters = @(@{ id = 'Workload'; operator = 'Equals'; value = 'All' }, @{ id = 'AssessmentCategory'; operator = 'Equals'; value = 'All' }) }
        @{ Name = 'SecureScore.Category.Secrets.Trend'; Id = 'bfe1ef21-4a0f-4403-8c3b-974634756076'; Filters = @(@{ id = 'Workload'; operator = 'Equals'; value = 'All' }, @{ id = 'AssessmentCategory'; operator = 'Equals'; value = 'Secrets' }) }
        @{ Name = 'SecureScore.Category.Vulnerabilities.Trend'; Id = 'bfe1ef21-4a0f-4403-8c3b-974634756076'; Filters = @(@{ id = 'Workload'; operator = 'Equals'; value = 'All' }, @{ id = 'AssessmentCategory'; operator = 'Equals'; value = 'Vulnerabilities' }) }
        @{ Name = 'SecureScore.Category.Misconfigurations.Trend'; Id = 'bfe1ef21-4a0f-4403-8c3b-974634756076'; Filters = @(@{ id = 'Workload'; operator = 'Equals'; value = 'All' }, @{ id = 'AssessmentCategory'; operator = 'Equals'; value = 'Misconfigurations' }) }
        @{ Name = 'Alerts.Trend'; Id = 'b88fc1ae-7689-4f0e-bf5a-cee3b682cbbf'; Filters = @() }
        @{ Name = 'Coverage.Trend'; Id = 'b91982bd-5197-4fb7-bcd0-52c3a3ccd361'; Filters = @() }
        @{ Name = 'Recommendations.Trend'; Id = '28eed83f-c704-4729-992b-305f089932b6'; Filters = @(@{ id = 'category'; operator = 'Equals'; value = 'All' }) }
        @{ Name = 'RecommendationsByCategory.Trend'; Id = '371a0598-b0dd-4b40-8dd0-de3896d56802'; Filters = @(@{ id = 'category'; operator = 'NotEquals'; value = 'All' }, @{ id = 'riskLevel'; operator = 'Equals'; value = 'All' }) }
        @{ Name = 'Vulnerabilities.Trend'; Id = '02b6c709-62b7-47af-9a65-786f53eae965'; Filters = @(@{ id = 'severity'; operator = 'NotEquals'; value = @(0) }) }
    )) {
        [pscustomobject]@{ Name = "Cloud.$($metric.Name)"; Family = 'Cloud'; Method = 'Post'; Path = '/apiproxy/mdc/views/dashboards/overtimeData'; Query = @{ c = 'en-us'; v = '1.0.3236.0' }; Body = @{ startDateTime = '{FromDate}'; metricsProperties = @(@{ metricId = $metric.Id; metricName = $metric.Id; requestOption = 'All'; dimensionsFilters = $metric.Filters }) }; Source = 'Browser client' }
    }
    foreach ($workload in @(
        @{ Name = 'ByWorkload'; Value = 'All'; Operator = 'NotEquals' }
        @{ Name = 'Compute'; Value = 'compute'; Operator = 'Equals' }
        @{ Name = 'Data'; Value = 'data'; Operator = 'Equals' }
        @{ Name = 'Containers'; Value = 'container'; Operator = 'Equals' }
        @{ Name = 'AI'; Value = 'AI'; Operator = 'Equals' }
        @{ Name = 'API'; Value = 'api'; Operator = 'Equals' }
        @{ Name = 'DevOps'; Value = 'devops'; Operator = 'Equals' }
        @{ Name = 'Identity'; Value = 'identity'; Operator = 'Equals' }
        @{ Name = 'Secrets'; Value = 'secret'; Operator = 'Equals' }
        @{ Name = 'Network'; Value = 'network'; Operator = 'Equals' }
    )) {
        $metricId = 'bfe1ef21-4a0f-4403-8c3b-974634756076'
        [pscustomobject]@{ Name = "Cloud.SecureScore.$($workload.Name).Trend"; Family = 'Cloud'; Method = 'Post'; Path = '/apiproxy/mdc/views/dashboards/overtimeData'; Query = @{ c = 'en-us'; v = '1.0.3236.0' }; Body = @{ startDateTime = '{FromDate}'; metricsProperties = @(@{ metricId = $metricId; metricName = $metricId; requestOption = 'All'; dimensionsFilters = @(@{ id = 'Workload'; operator = $workload.Operator; value = $workload.Value }, @{ id = 'AssessmentCategory'; operator = 'Equals'; value = 'All' }) }) }; Source = 'Browser client' }
    }
    foreach ($reportType in @('PasswordHygiene', 'PasswordPolicies', 'ExposedPasswords', 'LeakedCredentials')) {
        [pscustomobject]@{ Name = "Identity.$reportType.Definition"; Family = 'Identity'; Method = 'Get'; Path = "/apiproxy/mdi/identity/userapiservice/pdProtection/reportDefinitions/$reportType"; Query = @{}; Body = $null; Source = 'nodoc' }
        if ($reportType -in @('PasswordHygiene', 'PasswordPolicies')) {
            [pscustomobject]@{ Name = "Identity.$reportType"; Family = 'Identity'; Method = 'Get'; Path = "/apiproxy/mdi/identity/userapiservice/pdProtection/mdaReports/$reportType"; Query = @{}; Body = $null; Source = 'nodoc' }
        }
    }
    foreach ($view in @('Summary', 'Detail')) {
        [pscustomobject]@{ Name = "Email.MailFlowStatusReport.$view"; Family = 'Email'; Method = 'Post'; Path = "/api/ReportV2/GetReport${view}Data/"; Query = @{ reportId = 'MailFlowStatusReport'; dataSourceId = "MailFlowStatus$view" }; Body = @{ Direction = @('Inbound', 'Outbound', 'IntraOrg'); EventType = @('GoodMail', 'EmailMalware', 'SpamDetections', 'EdgeBlockSpam', 'TransportRules', 'EmailPhish', 'DLP'); StartDate = '{FromDate}'; EndDate = '{ToDate}' }; Source = 'Browser' }
    }
    [pscustomobject]@{ Name = 'Email.DownloadableReports'; Family = 'Email'; Method = 'Post'; Path = '/api/historicalsearch/GetList'; Query = @{}; Body = $null; Source = 'Browser' }
    [pscustomobject]@{ Name = 'Email.ReportSchedules'; Family = 'Email'; Method = 'Post'; Path = '/api/reportschedule/GetList'; Query = @{}; Body = $null; Source = 'Browser' }
    [pscustomobject]@{ Name = 'Hunting.UserHistory'; Family = 'Hunting'; Method = 'Post'; Path = '/apiproxy/mtp/huntingService/reports/userHistory'; Query = @{}; Body = @{ startTime = '{FromDate}'; maxResults = '{Top}' }; Source = 'Existing cmdlet' }
    foreach ($chart in @('NRT/RepeatOffender', 'NRT/TrainingCompletion', 'TrainingEfficacy', 'UserCoverage')) {
        [pscustomobject]@{ Name = "AttackSimulation.$($chart.Replace('/', '.'))"; Family = 'AttackSimulation'; Method = 'Get'; Path = "/apiproxy/astgws/AttackSimulator/api/v1/AdvanceReporting/chart/$chart"; Query = @{}; Body = $null; Source = 'nodoc' }
    }
    [pscustomobject]@{ Name = 'CloudApps.DiscoverySnapshotReports'; Family = 'CloudApps'; Method = 'Post'; Path = '/apiproxy/mcas/cas/api/v1/discovery/snapshot_reports/'; Query = @{}; Body = @{ skip = 0; limit = 20; filters = @{} }; Source = 'nodoc' }
    foreach ($reportType in @('Summary', 'SensitiveGroupMembershipChanges', 'LdapCleartextPasswords', 'LateralMovementPaths')) {
        $query = @{ startTime = '{FromDate}'; endTime = '{ToDate}'; isV2 = 'false' }
        [pscustomobject]@{ Name = "Identity.$reportType.Validate"; Family = 'Identity'; Method = 'Get'; Path = "/apiproxy/aatp/api/reports/$reportType/validate"; Query = $query.Clone(); Body = $null; Source = 'Browser client' }
        $query.localeId = 'en'; $query.utcOffset = '0'
        [pscustomobject]@{ Name = "Identity.$reportType.Download"; Family = 'Identity'; Method = 'Get'; Path = "/apiproxy/aatp/api/reports/$reportType"; Query = $query; Body = $null; Binary = $true; ValidationPath = "/apiproxy/aatp/api/reports/$reportType/validate"; Source = 'Browser client' }
    }
    [pscustomobject]@{ Name = 'EndpointLicense.SkuUsage'; Family = 'EndpointLicense'; Method = 'Get'; Path = '/apiproxy/mtp/k8sMachineApi/ine/machineapiservice/machines/skuReport'; Query = @{}; Body = $null; Source = 'Existing cmdlet' }
}