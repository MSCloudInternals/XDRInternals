const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const root = path.resolve(__dirname, '../..');
const origin = 'https://security.microsoft.com';
const prefix = '/apiproxy/mtp/';
const cases = [
    ['disrupt/api/exclusions/IP', 'ConfigurationAttackDisruptionExclusion', ' -Type "IP"'],
    ['disrupt/api/exclusions/DeviceTag', 'ConfigurationAttackDisruptionExclusion', ' -Type "DeviceTag"'],
    ['disrupt/api/exclusions/deviceTag/default', 'ConfigurationAttackDisruptionExclusion', ' -Type "DefaultDeviceTag"'],
    ['autoIr/ui/admin/advanced', 'ConfigurationAutomatedInvestigation', ''],
    ['autoIr/acl/all?type=memory_content', 'ConfigurationAutomatedInvestigationExclusion', ' -Type "MemoryContent"'],
    ['autoIr/folder_exclusion/all?type=folder&page_size=99999', 'ConfigurationAutomatedInvestigationExclusion', ' -Type "Folder"'],
    ['mdeCustomCollection/model', 'ConfigurationCustomCollectionModel', ''],
    ['customizationApi/?customizationType=IsolationAllowRules&osPlatform=Windows', 'ConfigurationIsolationAllowRule', ' -OsPlatform "Windows"'],
    ['customizationApi/?osPlatform=MacOs&customizationType=IsolationAllowRules', 'ConfigurationIsolationAllowRule', ' -OsPlatform "MacOs"'],
    ['packages/DownloadOnboardingWindowsActivator/List', 'OnboardingActivator', ''],
    ['packages/DownloadOnboardingWindowsActivator/ListHidden', 'OnboardingActivator', ' -Hidden'],
    ['settings/EndpointOnboardingStatus', 'OnboardingStatus', ''],
    ['userRequests/webcategory/policies', 'WebContentFilteringPolicy', '']
];

function load(extension) {
    const mapping = JSON.parse(fs.readFileSync(path.join(root, extension, 'CmdletApiMapping.json'), 'utf8').replace(/^\uFEFF/, ''));
    const element = () => ({ style: {}, appendChild() {}, insertBefore() {}, addEventListener() {} });
    const context = vm.createContext({
        URL, URLSearchParams, console, Date,
        fetch: () => new Promise(() => {}), // No network; mappings are supplied from disk below.
        document: { getElementById: element, createElement: element },
        chrome: {
            devtools: { network: { onRequestFinished: { addListener() {} } } },
            runtime: { sendMessage: (_message, callback) => callback({ success: false }) }
        }
    });
    vm.runInContext(fs.readFileSync(path.join(root, extension, 'panel.js'), 'utf8'), context);
    context.mapping = mapping;
    vm.runInContext('cmdletMapping = mapping; addRequestToUI = () => {};', context);
    return (route, method = 'GET', suppliedOrigin = origin) => {
        context.input = { request: { url: suppliedOrigin + prefix + route, method, headers: [] } };
        return vm.runInContext('processRequest(input); generatePowerShellCode(capturedRequests.at(-1));', context);
    };
}

for (const extension of ['XDRay', 'XDRay Firefox']) {
    const generate = load(extension);
    for (const [route, suffix, parameters] of cases) {
        test(`${extension}: concrete GET ${route}`, () => {
            const cmdlet = 'Get-XdrEndpoint' + suffix;
            assert.equal(generate(route), `# ${cmdlet}\n${cmdlet}${parameters}`);
        });
        test(`${extension}: non-GET ${route} stays generic`, () => {
            assert.match(generate(route, 'POST'), /^Invoke-XdrRestMethod /);
        });
    }
    for (const route of [
        'disrupt/api/exclusions/Unknown', 'disrupt/api/exclusions/deviceTag/other',
        'disrupt/api/exclusions/deviceTag%2Fdefault', 'disrupt/api/exclusions/IP/extra',
        'packages/DownloadOnboardingWindowsActivator/Download',
        'packages/DownloadOnboardingWindowsActivator/ListHidden/extra',
        'customizationApi/',
        'customizationApi/?customizationType=Other&osPlatform=Windows',
        'customizationApi/?customizationType=IsolationAllowRules&osPlatform=Linux',
        'customizationApi/?customizationType=IsolationAllowRules&osPlatform=Windows&osPlatform=MacOs',
        'autoIr/acl/all?type=folder', 'autoIr/folder_exclusion/all?type=memory_content'
    ]) {
        test(`${extension}: unsupported route ${route} stays generic`, () => {
            assert.match(generate(route), /^Invoke-XdrRestMethod /);
        });
    }
    test(`${extension}: origin must match a scoped mapping`, () => {
        assert.match(generate(cases[0][0], 'GET', 'https://example.invalid'), /^Invoke-XdrRestMethod /);
    });
    test(`${extension}: extra pagination/query fields do not become cmdlet parameters`, () => {
        const cmdlet = 'Get-XdrEndpointConfigurationAutomatedInvestigationExclusion';
        assert.equal(generate('autoIr/folder_exclusion/all?type=folder&page=2&page_size=99999'), `# ${cmdlet}\n${cmdlet} -Type "Folder"`);
    });
    test(`${extension}: existing mapping still resolves`, () => {
        assert.match(generate('settings/GetAdvancedFeaturesSetting'), /^# Get-XdrEndpointConfigurationAdvancedFeatures\n/);
    });
}
test('Chromium and Firefox mappings stay byte-identical', () => {
    assert.deepEqual(fs.readFileSync(path.join(root, 'XDRay/CmdletApiMapping.json')), fs.readFileSync(path.join(root, 'XDRay Firefox/CmdletApiMapping.json')));
});
