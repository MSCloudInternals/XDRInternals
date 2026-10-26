const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function createElement() {
    return { style: {}, classList: { add() { }, remove() { }, toggle() { } }, appendChild() { }, addEventListener() { }, setAttribute() { }, querySelectorAll() { return []; } };
}

async function main() {
    for (const directory of ['XDRay', 'XDRay Firefox']) {
        let listener;
        let body = null;
        const captured = [];
        const context = vm.createContext({
            URL, console, Date, Blob,
            document: { getElementById: createElement, createElement, querySelectorAll() { return []; } },
            fetch: async () => ({ json: async () => [] }),
            chrome: {
                devtools: { network: { onRequestFinished: { addListener(callback) { listener = callback; } } } },
                runtime: { sendMessage(request, callback) { callback({ success: true, body: body ? JSON.stringify(body) : null }); } }
            },
            capture: data => captured.push(data)
        });
        const source = fs.readFileSync(path.join(__dirname, '..', '..', directory, 'panel.js'), 'utf8');
        vm.runInContext(source, context);
        await Promise.resolve();
        await Promise.resolve();
        const mappings = [
            { Cmdlet: 'Get-XdrReport', ApiUri: 'https://security.microsoft.com/api/Report/GetReportSummaryData/', Parameters: { Name: 'fixed:Email.ZapReport.Summary' }, Method: 'Post', QueryMatch: { reportId: 'ZapReport', dataSourceId: 'AggZapReport' }, ReportQueryKeys: ['reportId', 'dataSourceId'], ReportBinary: false },
            { Cmdlet: 'Get-XdrReport', ApiUri: 'https://security.microsoft.com/api/Report/GetReportSummaryData/', Parameters: { Name: 'fixed:Email.TopMalware.Summary' }, Method: 'Post', QueryMatch: { reportId: 'TopMalware', dataSourceId: 'MailTrafficSummaryReport' }, ReportQueryKeys: ['reportId', 'dataSourceId'], ReportBinary: false },
            { Cmdlet: 'Get-XdrReport', ApiUri: 'https://security.microsoft.com/apiproxy/report/download', Parameters: { Name: 'fixed:Identity.Summary.Download' }, Method: 'Get', QueryMatch: {}, ReportQueryKeys: ['localeId'], ReportBinary: true },
            { Cmdlet: 'Get-XdrReport', ApiUri: 'https://security.microsoft.com/apiproxy/di/Search/SubmissionDIESData', Parameters: { Name: 'fixed:Email.AdminSubmissions.Detail' }, Method: 'Post', QueryMatch: {}, BodyMatch: { 'QueryFilter.Filter.Value': 2 }, ReportQueryKeys: [], ReportBinary: false },
            { Cmdlet: 'Get-XdrReport', ApiUri: 'https://security.microsoft.com/apiproxy/di/Search/SubmissionDIESData', Parameters: { Name: 'fixed:Email.UserSubmissions.Detail' }, Method: 'Post', QueryMatch: {}, BodyMatch: { 'QueryFilter.Filter.Value': '1,4,5,6' }, ReportQueryKeys: [], ReportBinary: false }
        ];
        context.mappings = mappings;
        vm.runInContext('cmdletMapping = mappings; addRequestToUI = capture;', context);
        body = { Category: "O'Brien $value `test" };
        listener({ request: { url: 'https://security.microsoft.com/api/Report/GetReportSummaryData/?reportId=TopMalware&dataSourceId=MailTrafficSummaryReport', method: 'POST', headers: [] } });
        assert.equal(captured[0].report.name, 'Email.TopMalware.Summary', directory);
        context.data = captured[0];
        const code = vm.runInContext('generatePowerShellCode(data)', context);
        assert.match(code, /Get-XdrReport -Name 'Email.TopMalware.Summary'/);
        assert.match(code, /'reportId' = 'TopMalware'/);
        assert.match(code, /O''Brien \$value `test/);
        assert.match(code, /ConvertFrom-Json -AsHashtable/);
        body = null;
        listener({ request: { url: 'https://security.microsoft.com/apiproxy/report/download?localeId=en', method: 'GET', headers: [] } });
        context.data = captured[1];
        assert.match(vm.runInContext('generatePowerShellCode(data)', context), /-OutFile '\.\/Identity.Summary.Download.report'/);
        listener({ request: { url: 'https://security.microsoft.com.evil.example/apiproxy/report/download', method: 'GET', headers: [] } });
        assert.equal(captured.length, 2);
        listener({ request: { url: 'https://security.microsoft.com/api/Report/GetReportSummaryData/?reportId=TopMalware&dataSourceId=MailTrafficSummaryReport', method: 'GET', headers: [] } });
        assert.equal(captured[2].report, null);
        body = { QueryFilter: { Filter: { Value: '1,4,5,6' } } };
        listener({ request: { url: 'https://security.microsoft.com/apiproxy/di/Search/SubmissionDIESData', method: 'POST', headers: [] } });
        assert.equal(captured[3].report.name, 'Email.UserSubmissions.Detail');
        body.QueryFilter.Filter.Value = 2;
        listener({ request: { url: 'https://security.microsoft.com/apiproxy/di/Search/SubmissionDIESData', method: 'POST', headers: [] } });
        assert.equal(captured[4].report.name, 'Email.AdminSubmissions.Detail');
        context.mappings = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', directory, 'CmdletApiMapping.json'), 'utf8').replace(/^\uFEFF/, ''));
        vm.runInContext('cmdletMapping = mappings;', context);
        body = { schemaId: 'dashboardsAndReports_CoverageByPlan', paging: { pageSize: 200 }, filters: [] };
        listener({ request: { url: 'https://security.microsoft.com/apiproxy/mdc/views/dashboards/items?c=en-us&v=1.0.3236.0', method: 'POST', headers: [] } });
        assert.equal(captured[5].report.name, 'Cloud.CoverageByPlan', directory);
        body = {
            startDateTime: '2026-09-01T00:00:00.000Z',
            metricsProperties: [{
                metricId: 'bfe1ef21-4a0f-4403-8c3b-974634756076',
                requestOption: 'All',
                dimensionsFilters: [
                    { id: 'Workload', operator: 'Equals', value: 'compute' },
                    { id: 'AssessmentCategory', operator: 'Equals', value: 'All' }
                ]
            }]
        };
        const trendRequest = { request: { url: 'https://security.microsoft.com/apiproxy/mdc/views/dashboards/overtimeData?c=en-us&v=1.0.3236.0', method: 'POST', headers: [] } };
        listener(trendRequest);
        assert.equal(captured[6].report.name, 'Cloud.SecureScore.Compute.Trend', directory);
        body.metricsProperties[0].dimensionsFilters[0].value = 'network';
        listener(trendRequest);
        assert.equal(captured[7].report.name, 'Cloud.SecureScore.Network.Trend', directory);
        body.metricsProperties[0].metricId = '02b6c709-62b7-47af-9a65-786f53eae965';
        body.metricsProperties[0].dimensionsFilters = [{ id: 'severity', operator: 'NotEquals', value: [0] }];
        listener(trendRequest);
        assert.equal(captured[8].report.name, 'Cloud.Vulnerabilities.Trend', directory);
        body.metricsProperties[0].metricId = 'bfe1ef21-4a0f-4403-8c3b-974634756076';
        for (const category of ['Secrets', 'Vulnerabilities', 'Misconfigurations']) {
            body.metricsProperties[0].dimensionsFilters = [
                { id: 'Workload', operator: 'Equals', value: 'All' },
                { id: 'AssessmentCategory', operator: 'Equals', value: category }
            ];
            listener(trendRequest);
            assert.equal(captured.at(-1).report.name, `Cloud.SecureScore.Category.${category}.Trend`, directory);
        }
        body.metricsProperties[0].dimensionsFilters.reverse();
        listener(trendRequest);
        assert.equal(captured.at(-1).report?.name, 'Cloud.SecureScore.Category.Misconfigurations.Trend', `${directory}: reordered dimensions`);
        console.log(`${directory}: report selection, Cloud schemas/dimensions, quoting, downloads, and origin/method checks passed`);
    }
}

main().catch(error => { console.error(error); process.exitCode = 1; });