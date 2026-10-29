let cmdletMapping = [];
let capturedRequests = [];

// Load mapping
fetch('CmdletApiMapping.json')
    .then(response => response.json())
    .then(data => {
        cmdletMapping = data;
    })
    .catch(err => console.error('Failed to load mapping', err));

// Add disclaimer on load
addDisclaimerToUI();

// Listen for network requests
chrome.devtools.network.onRequestFinished.addListener(request => {
    const url = request.request.url;
    const parsedUrl = new URL(url);
    if (parsedUrl.origin === 'https://security.microsoft.com' && (parsedUrl.pathname.startsWith('/apiproxy/') || /^\/api\/(Report(V2)?\/GetReport|historicalsearch\/GetList|reportschedule\/GetList)/.test(parsedUrl.pathname))) {
        processRequest(request);
    }
});

function findReportMapping(url, method, body) {
    return cmdletMapping.find(map => map.Cmdlet === 'Get-XdrReport' &&
        new URL(map.ApiUri).pathname.toLowerCase() === url.pathname.toLowerCase() &&
        map.Method.toLowerCase() === method.toLowerCase() &&
        Object.entries(map.QueryMatch || {}).every(([key, value]) => url.searchParams.get(key) === value) &&
        Object.entries(map.BodyMatch || {}).every(([key, value]) => {
            let actualValue = body;
            const pathParts = key.split('.');
            for (const [index, part] of pathParts.entries()) {
                if (Array.isArray(actualValue) && /^\d+$/.test(part)) {
                    const prefix = pathParts.slice(0, index + 1).join('.');
                    const identityField = ['metricId', 'id'].find(field => Object.prototype.hasOwnProperty.call(map.BodyMatch, `${prefix}.${field}`));
                    actualValue = identityField ? actualValue.find(item => item?.[identityField] === map.BodyMatch[`${prefix}.${identityField}`]) : actualValue[part];
                } else {
                    actualValue = actualValue?.[part];
                }
            }
            return actualValue === value;
        }));
}

function processRequest(request) {
    const url = new URL(request.request.url);
    const method = request.request.method;
    const path = url.pathname + url.search;

    // Extract headers
    const headers = {};
    if (request.request.headers) {
        request.request.headers.forEach(h => {
            headers[h.name.toLowerCase()] = h.value;
        });
    }

    // Find matching cmdlet
    let matchedCmdlet = null;
    let matchedParams = null;
    let matchedReport = null;

    for (const map of cmdletMapping) {
        if (map.Cmdlet === 'Get-XdrReport' && (map.Method.toLowerCase() !== method.toLowerCase() || Object.entries(map.QueryMatch || {}).some(([key, value]) => url.searchParams.get(key) !== value))) continue;
        const mappingPath = new URL(map.ApiUri).pathname;
        const regexStr = '^' + mappingPath.replace(/\{[^}]+\}/g, '([^/]+)') + '$';
        const regex = new RegExp(regexStr, 'i');

        if (regex.test(url.pathname)) {
            matchedCmdlet = map.Cmdlet;
            matchedParams = map.Parameters;
            if (map.Cmdlet === 'Get-XdrReport') matchedReport = { name: map.Parameters.Name.substring(6), queryKeys: map.ReportQueryKeys, binary: map.ReportBinary };
            break;
        }

        if (url.pathname.toLowerCase() === mappingPath.toLowerCase()) {
            matchedCmdlet = map.Cmdlet;
            matchedParams = map.Parameters;
            if (map.Cmdlet === 'Get-XdrReport') matchedReport = { name: map.Parameters.Name.substring(6), queryKeys: map.ReportQueryKeys, binary: map.ReportBinary };
            break;
        }
    }

    // Get the request body from the background script
    // The background script captures it via chrome.webRequest.onBeforeRequest
    chrome.runtime.sendMessage(
        { type: 'GET_REQUEST_BODY', url: request.request.url },
        (response) => {
            let body = null;

            if (response && response.success && response.body) {
                try {
                    body = JSON.parse(response.body);
                } catch (e) {
                    body = response.body;
                }
            }

            if (matchedCmdlet === 'Get-XdrReport') {
                const reportMap = findReportMapping(url, method, body);
                matchedCmdlet = reportMap?.Cmdlet || null;
                matchedParams = reportMap?.Parameters || null;
                matchedReport = reportMap ? { name: reportMap.Parameters.Name.substring(6), queryKeys: reportMap.ReportQueryKeys, binary: reportMap.ReportBinary } : null;
            }
            const requestData = {
                method: method,
                url: request.request.url,
                headers: headers,
                cmdlet: matchedCmdlet || 'Invoke-XdrRestMethod',
                parameters: matchedParams,
                report: matchedReport,
                body: body,
                timestamp: new Date().toISOString()
            };

            capturedRequests.push(requestData);
            addRequestToUI(requestData);
        }
    );
}

function addRequestToUI(data) {
    const list = document.getElementById('request-list');
    const item = document.createElement('div');
    item.className = 'request-item';

    const summary = document.createElement('div');
    summary.className = 'request-summary';

    const methodSpan = document.createElement('span');
    methodSpan.className = `method ${data.method}`;
    methodSpan.textContent = data.method;
    summary.appendChild(methodSpan);

    const cmdletSpan = document.createElement('span');
    cmdletSpan.className = 'cmdlet';
    cmdletSpan.textContent = data.cmdlet;
    summary.appendChild(cmdletSpan);

    const urlSpan = document.createElement('span');
    urlSpan.className = 'url';
    // Safely handle URL splitting
    const urlParts = data.url.split('apiproxy');
    urlSpan.textContent = urlParts.length > 1 ? urlParts[1] : data.url;
    summary.appendChild(urlSpan);

    const details = document.createElement('div');
    details.className = 'details';

    // Generate PowerShell Code
    const psCode = generatePowerShellCode(data);

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy Code';
    details.appendChild(copyBtn);

    const codeDiv = document.createElement('div');
    codeDiv.style.marginBottom = '10px';
    codeDiv.style.color = '#9cdcfe';
    codeDiv.style.whiteSpace = 'pre-wrap'; // Preserve formatting
    codeDiv.textContent = psCode;
    details.appendChild(codeDiv);

    const urlDiv = document.createElement('div');
    urlDiv.style.color = '#6a9955';
    urlDiv.textContent = `# Full URL: ${data.url}`;
    details.appendChild(urlDiv);

    if (data.body) {
        const bodyDiv = document.createElement('div');
        bodyDiv.style.marginTop = '5px';
        bodyDiv.style.color = '#6a9955';
        bodyDiv.style.whiteSpace = 'pre-wrap';
        bodyDiv.textContent = `# Request Payload: ${JSON.stringify(data.body, null, 2)}`;
        details.appendChild(bodyDiv);
    }

    summary.addEventListener('click', () => {
        details.classList.toggle('open');
    });

    copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(psCode, copyBtn);
    });

    item.appendChild(summary);
    item.appendChild(details);
    list.appendChild(item);
}

function generatePowerShellCode(data) {
    const urlObj = new URL(data.url);
    let code = '';
    if (data.report) {
        const quote = value => `'${String(value).replace(/'/g, "''")}'`;
        code = `Get-XdrReport -Name ${quote(data.report.name)}`;
        const query = [...urlObj.searchParams].filter(([key]) => data.report.queryKeys.includes(key));
        if (query.length) code += ` -Parameters @{ ${query.map(([key, value]) => `${quote(key)} = ${quote(value)}`).join('; ')} }`;
        if (data.body && typeof data.body === 'object') code += ` -Body (${quote(JSON.stringify(data.body))} | ConvertFrom-Json -AsHashtable)`;
        if (data.report.binary) code += ` -OutFile ${quote('./' + data.report.name + '.report')}`;
        return code;
    }

    // Helper function to escape values for PowerShell
    function escapeForPowerShell(value) {
        if (typeof value === 'string') {
            // Escape double quotes with backticks and backslashes
            return value.replace(/"/g, '`"').replace(/\\/g, '\\');
        } else if (typeof value === 'object' && value !== null) {
            // For objects, convert to JSON and escape
            return JSON.stringify(value, null, 2).replace(/"/g, '`"');
        }
        return value;
    }

    // Helper to resolve values from data based on path
    function resolveValue(data, path) {
        if (path.startsWith('fixed:')) {
            return path.substring(6);
        }
        if (path.startsWith('header:')) {
            const headerName = path.substring(7).toLowerCase();
            return data.headers ? data.headers[headerName] : undefined;
        }

        const parts = path.split('.');
        let current = data;

        for (const part of parts) {
            if (current === null || current === undefined) return undefined;
            current = current[part];
        }

        return current;
    }

    if (data.cmdlet !== 'Invoke-XdrRestMethod') {
        code += `# ${data.cmdlet}\n`;
        code += `${data.cmdlet}`;

        if (data.parameters) {
            // Use explicit mapping
            for (const [paramName, sourcePath] of Object.entries(data.parameters)) {
                const value = resolveValue(data, sourcePath);
                if (value !== undefined && value !== null) {
                    const escapedValue = escapeForPowerShell(value);
                    code += ` -${paramName} "${escapedValue}"`;
                }
            }
        } else {
            // Fallback to heuristics
            // Try to map parameters from Query String
            urlObj.searchParams.forEach((value, key) => {
                // Simple heuristic: capitalize first letter
                const paramName = key.charAt(0).toUpperCase() + key.slice(1);
                const escapedValue = escapeForPowerShell(value);
                code += ` -${paramName} "${escapedValue}"`;
            });

            // Try to map parameters from Body
            if (data.body && typeof data.body === 'object') {
                // If body is flat, map keys to parameters
                // This is a best-effort guess
                Object.keys(data.body).forEach(key => {
                    const paramName = key.charAt(0).toUpperCase() + key.slice(1);
                    const value = data.body[key];
                    if (typeof value !== 'object' && value !== null) {
                        const escapedValue = escapeForPowerShell(value);
                        code += ` -${paramName} "${escapedValue}"`;
                    }
                });
            }
        }

        // Don't show fallback when native cmdlet is available
        return code;
    }

    // Only use Invoke-XdrRestMethod when no native cmdlet is found
    code += `Invoke-XdrRestMethod -Uri "${data.url}" -Method "${data.method}"`;

    if (data.body) {
        // Properly escape the JSON body for PowerShell
        // Replace " with `" and wrap in single quotes to preserve formatting
        const bodyJson = JSON.stringify(data.body, null, 2).replace(/"/g, '`"');
        code += ` -Body "${bodyJson}"`;
    }

    return code;
}

// UI Event Listeners
document.getElementById('clear-btn').addEventListener('click', () => {
    capturedRequests = [];
    document.getElementById('request-list').innerHTML = '';
    addDisclaimerToUI();
});

document.getElementById('save-btn').addEventListener('click', () => {
    let scriptContent = '# XDRay Generated Script\n';
    scriptContent += '# The mapping to cmdlets is based on best effort but might not reflect the actual parameters of the parameter in question.\n';
    scriptContent += '# Do NOT run this code without verifying it yourself.\n\n';

    capturedRequests.forEach(req => {
        scriptContent += generatePowerShellCode(req) + '\n\n';
    });

    const blob = new Blob([scriptContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'XDRay-Script.ps1.txt'; // .txt to avoid browser warnings
    a.click();
    URL.revokeObjectURL(url);
});

document.getElementById('danger-zone-toggle').addEventListener('click', (e) => {
    const btn = e.currentTarget;
    if (btn.textContent.includes('Danger Zone')) {
        btn.textContent = 'I understand the security risks';
        btn.style.backgroundColor = '#ce9178';
        btn.style.color = '#1e1e1e';
    } else {
        document.getElementById('danger-zone-content').style.display = 'flex';
        addDangerZoneInfoToUI();
        btn.style.display = 'none';
    }
});

function addDangerZoneInfoToUI() {
    const list = document.getElementById('request-list');
    const item = document.createElement('div');
    item.className = 'request-item';
    item.style.borderColor = '#ce9178';

    const summary = document.createElement('div');
    summary.className = 'request-summary';
    summary.style.backgroundColor = '#3e2d2d';

    const iconSpan = document.createElement('span');
    iconSpan.textContent = '⚠';
    iconSpan.style.marginRight = '10px';
    iconSpan.style.color = '#ce9178';
    summary.appendChild(iconSpan);

    const titleSpan = document.createElement('span');
    titleSpan.textContent = 'Setup XDRInternals with captured tokens';
    titleSpan.style.fontWeight = 'bold';
    titleSpan.style.color = '#ce9178';
    summary.appendChild(titleSpan);

    const details = document.createElement('div');
    details.className = 'details open'; // Open by default

    const codeBlock = document.createElement('div');
    codeBlock.style.color = '#dcdcaa';
    codeBlock.style.whiteSpace = 'pre-wrap';
    codeBlock.style.marginBottom = '10px';
    codeBlock.textContent = `Import-Module XDRInternals.psd1
$SccAuth = Read-Host -Prompt "Paste the sccauth cookie value" -AsSecureString
$Xsrf = Read-Host -Prompt "Paste the XSRF-TOKEN cookie value" -AsSecureString
Set-XdrConnectionSettings -SccAuth $SccAuth -Xsrf $Xsrf -Verbose`;

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy Code';
    copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(codeBlock.textContent, copyBtn);
    });

    details.appendChild(copyBtn);
    details.appendChild(codeBlock);

    summary.addEventListener('click', () => {
        details.classList.toggle('open');
    });

    item.appendChild(summary);
    item.appendChild(details);

    // Prepend to list
    list.insertBefore(item, list.firstChild);
}

function addDisclaimerToUI() {
    const list = document.getElementById('request-list');
    const item = document.createElement('div');
    item.className = 'request-item';
    item.style.borderColor = '#007acc';

    const summary = document.createElement('div');
    summary.className = 'request-summary';
    summary.style.backgroundColor = '#1e2e3e';
    summary.style.cursor = 'default';

    const iconSpan = document.createElement('span');
    iconSpan.textContent = 'ℹ';
    iconSpan.style.marginRight = '10px';
    iconSpan.style.color = '#007acc';
    summary.appendChild(iconSpan);

    const titleSpan = document.createElement('span');
    titleSpan.textContent = 'The mapping to cmdlets is based on best effort but might not reflect the actual parameters of the parameter in question. Do NOT run this code without verifying it yourself.';
    titleSpan.style.color = '#cccccc';
    titleSpan.style.fontSize = '11px';
    summary.appendChild(titleSpan);

    item.appendChild(summary);

    // Prepend to list
    if (list.firstChild) {
        list.insertBefore(item, list.firstChild);
    } else {
        list.appendChild(item);
    }
}

document.getElementById('copy-sccauth-btn').addEventListener('click', (e) => {
    const btn = e.currentTarget;
    chrome.cookies.getAll({ domain: "security.microsoft.com" }, (cookies) => {
        const sccauthCookie = cookies.find(cookie => cookie.name === "sccauth");

        if (sccauthCookie) {
            copyToClipboard(sccauthCookie.value, btn, true);
            console.warn("WARNING: Sensitive sccauth value copied to clipboard! Do not share this value.");
        } else {
            console.warn("sccauth cookie not found.");
            const originalText = btn.textContent;
            btn.textContent = 'Not Found';
            setTimeout(() => btn.textContent = originalText, 2000);
        }
    });
});

document.getElementById('copy-xsrf-btn').addEventListener('click', (e) => {
    const btn = e.currentTarget;
    chrome.cookies.getAll({ domain: "security.microsoft.com" }, (cookies) => {
        const xsrfCookie = cookies.find(cookie => cookie.name === "XSRF-TOKEN");

        if (xsrfCookie) {
            copyToClipboard(xsrfCookie.value, btn, true);
            console.warn("WARNING: Sensitive XSRF-TOKEN value copied to clipboard! Do not share this value.");
        } else {
            console.warn("XSRF-TOKEN cookie not found.");
            const originalText = btn.textContent;
            btn.textContent = 'Not Found';
            setTimeout(() => btn.textContent = originalText, 2000);
        }
    });
});

function copyToClipboard(text, button, isSensitive = false) {
    // Try Clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            if (isSensitive) {
                showSensitiveCopySuccess(button);
            } else {
                showCopySuccess(button);
            }
        }).catch(err => {
            console.warn('Clipboard API failed, trying execCommand fallback', err);
            fallbackCopyTextToClipboard(text, button, isSensitive);
        });
    } else {
        fallbackCopyTextToClipboard(text, button, isSensitive);
    }
}

function showCopySuccess(button) {
    if (button) {
        const originalText = button.textContent;
        button.textContent = '✓ Copied!';
        button.style.backgroundColor = '#16825d';

        setTimeout(() => {
            button.textContent = originalText;
            button.style.backgroundColor = '';
        }, 2000);
    }
}

function showSensitiveCopySuccess(button) {
    if (button) {
        const originalText = button.textContent;
        button.textContent = '⚠ Copied! SENSITIVE!';
        button.title = 'Do not share this value!';
        button.style.backgroundColor = '#d13438'; // Red
        button.style.color = 'white';

        setTimeout(() => {
            button.textContent = originalText;
            button.title = '';
            button.style.backgroundColor = '';
            button.style.color = '';
        }, 4000);
    }
}

function fallbackCopyTextToClipboard(text, button, isSensitive = false) {
    const textArea = document.createElement("textarea");
    textArea.value = text;

    // Avoid scrolling to bottom
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";

    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
        const successful = document.execCommand('copy');
        if (successful) {
            if (isSensitive) {
                showSensitiveCopySuccess(button);
            } else {
                showCopySuccess(button);
            }
        }
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
    }

    document.body.removeChild(textArea);
}
