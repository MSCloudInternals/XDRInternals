let cmdletMapping = [];
let capturedRequests = [];

fetch('CmdletApiMapping.json')
    .then(response => response.json())
    .then(data => { cmdletMapping = data; })
    .catch(err => console.error('Failed to load mapping', err));

addDisclaimerToUI();

chrome.devtools.network.onRequestFinished.addListener(request => {
    const url = request.request.url;
    if (url.includes('https://security.microsoft.com/apiproxy')) {
        processRequest(request);
    }
});

function processRequest(request) {
    const url = new URL(request.request.url);
    const method = request.request.method;

    const headers = {};
    if (request.request.headers) {
        request.request.headers.forEach(h => { headers[h.name.toLowerCase()] = h.value; });
    }

    let matchedCmdlet = null;
    let matchedParams = null;

    for (const map of cmdletMapping) {
        const mappingPath = new URL(map.ApiUri).pathname;
        const regexStr = '^' + mappingPath.replace(/\{[^}]+\}/g, '([^/]+)') + '$';
        const regex = new RegExp(regexStr, 'i');
        if (regex.test(url.pathname) || url.pathname.toLowerCase() === mappingPath.toLowerCase()) {
            matchedCmdlet = map.Cmdlet;
            matchedParams = map.Parameters;
            break;
        }
    }

    chrome.runtime.sendMessage(
        { type: 'GET_REQUEST_BODY', url: request.request.url },
        (response) => {
            let body = null;
            if (response && response.success && response.body) {
                try { body = JSON.parse(response.body); } catch (e) { body = response.body; }
            }
            const requestData = {
                method,
                url: request.request.url,
                headers,
                cmdlet: matchedCmdlet || 'Invoke-XdrRestMethod',
                parameters: matchedParams,
                body,
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

    const cmdletSpan = document.createElement('span');
    cmdletSpan.className = 'cmdlet';
    cmdletSpan.textContent = data.cmdlet;

    const urlSpan = document.createElement('span');
    urlSpan.className = 'url';
    const urlParts = data.url.split('apiproxy');
    urlSpan.textContent = urlParts.length > 1 ? urlParts[1] : data.url;

    summary.appendChild(methodSpan);
    summary.appendChild(cmdletSpan);
    summary.appendChild(urlSpan);

    const details = document.createElement('div');
    details.className = 'details';

    const psCode = generatePowerShellCode(data);

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy Code';

    const codeDiv = document.createElement('div');
    codeDiv.style.marginBottom = '10px';
    codeDiv.style.color = '#9cdcfe';
    codeDiv.style.whiteSpace = 'pre-wrap';
    codeDiv.textContent = psCode;

    const urlDiv = document.createElement('div');
    urlDiv.style.color = '#6a9955';
    urlDiv.textContent = `# Full URL: ${data.url}`;

    if (data.body) {
        const bodyDiv = document.createElement('div');
        bodyDiv.style.marginTop = '5px';
        bodyDiv.style.color = '#6a9955';
        bodyDiv.style.whiteSpace = 'pre-wrap';
        bodyDiv.textContent = `# Request Payload: ${JSON.stringify(data.body, null, 2)}`;
        details.appendChild(bodyDiv);
    }

    summary.addEventListener('click', () => { details.classList.toggle('open'); });
    copyBtn.addEventListener('click', (e) => { e.stopPropagation(); copyToClipboard(psCode, copyBtn); });

    details.appendChild(copyBtn);
    details.appendChild(codeDiv);
    details.appendChild(urlDiv);

    item.appendChild(summary);
    item.appendChild(details);
    list.appendChild(item);
}

function generatePowerShellCode(data) {
    const urlObj = new URL(data.url);
    let code = '';

    function escapeForPowerShell(value) {
        if (typeof value === 'string') {
            return value.replace(/"/g, '`"').replace(/\\/g, '\\');
        } else if (typeof value === 'object' && value !== null) {
            return JSON.stringify(value, null, 2).replace(/"/g, '`"');
        }
        return value;
    }

    function resolveValue(data, path) {
        if (path.startsWith('fixed:')) return path.substring(6);
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
            for (const [paramName, sourcePath] of Object.entries(data.parameters)) {
                const value = resolveValue(data, sourcePath);
                if (value !== undefined && value !== null) {
                    const escapedValue = escapeForPowerShell(value);
                    code += ` -${paramName} "${escapedValue}"`;
                }
            }
        } else {
            urlObj.searchParams.forEach((value, key) => {
                const paramName = key.charAt(0).toUpperCase() + key.slice(1);
                const escapedValue = escapeForPowerShell(value);
                code += ` -${paramName} "${escapedValue}"`;
            });
            if (data.body && typeof data.body === 'object') {
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
        return code;
    }

    code += `Invoke-XdrRestMethod -Uri "${data.url}" -Method "${data.method}"`;
    if (data.body) {
        const bodyJson = JSON.stringify(data.body, null, 2).replace(/"/g, '`"');
        code += ` -Body "${bodyJson}"`;
    }
    return code;
}

// UI Events
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
    if (list.firstChild) { list.insertBefore(item, list.firstChild); } else { list.appendChild(item); }
}

document.getElementById('clear-btn').addEventListener('click', () => {
    capturedRequests = [];
    document.getElementById('request-list').innerHTML = '';
    addDisclaimerToUI();
});

document.getElementById('save-btn').addEventListener('click', () => {
    let scriptContent = '# XDRay Generated Script\n';
    scriptContent += '# The mapping to cmdlets is based on best effort but might not reflect the actual parameters of the parameter in question.\n';
    scriptContent += '# Do NOT run this code without verifying it yourself.\n\n';
    capturedRequests.forEach(req => { scriptContent += generatePowerShellCode(req) + '\n\n'; });
    const blob = new Blob([scriptContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'XDRay-Script.ps1.txt';
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
    details.className = 'details open';

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
    copyBtn.addEventListener('click', (e) => { e.stopPropagation(); copyToClipboard(codeBlock.textContent, copyBtn); });

    details.appendChild(copyBtn);
    details.appendChild(codeBlock);

    summary.addEventListener('click', () => { details.classList.toggle('open'); });

    item.appendChild(summary);
    item.appendChild(details);
    list.insertBefore(item, list.firstChild);
}

document.getElementById('copy-sccauth-btn').addEventListener('click', (e) => {
    const btn = e.currentTarget;

    // Request cookie from background script
    chrome.runtime.sendMessage(
        { type: 'GET_COOKIE', cookieName: 'sccauth' },
        (response) => {
            if (chrome.runtime.lastError) {
                console.error("Runtime error:", chrome.runtime.lastError);
                btn.textContent = 'Error';
                setTimeout(() => btn.textContent = 'Copy sccauth', 3000);
                return;
            }

            if (response && response.success) {
                copyToClipboard(response.value, btn, true);
                console.warn("WARNING: Sensitive sccauth value copied to clipboard! Do not share this value.");
            } else {
                console.warn("sccauth cookie not found:", response?.error);
                btn.textContent = 'Not Found';
                setTimeout(() => btn.textContent = 'Copy sccauth', 2000);
            }
        }
    );
});

document.getElementById('copy-xsrf-btn').addEventListener('click', (e) => {
    const btn = e.currentTarget;

    // Request cookie from background script
    chrome.runtime.sendMessage(
        { type: 'GET_COOKIE', cookieName: 'XSRF-TOKEN' },
        (response) => {
            if (chrome.runtime.lastError) {
                console.error("Runtime error:", chrome.runtime.lastError);
                btn.textContent = 'Error';
                setTimeout(() => btn.textContent = 'Copy XSRF-TOKEN', 3000);
                return;
            }

            if (response && response.success) {
                copyToClipboard(response.value, btn, true);
                console.warn("WARNING: Sensitive XSRF-TOKEN value copied to clipboard! Do not share this value.");
            } else {
                console.warn("XSRF-TOKEN cookie not found:", response?.error);
                btn.textContent = 'Not Found';
                setTimeout(() => btn.textContent = 'Copy XSRF-TOKEN', 2000);
            }
        }
    );
});

function copyToClipboard(text, button, isSensitive = false) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            if (isSensitive) { showSensitiveCopySuccess(button); } else { showCopySuccess(button); }
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
        setTimeout(() => { button.textContent = originalText; button.style.backgroundColor = ''; }, 2000);
    }
}

function showSensitiveCopySuccess(button) {
    if (button) {
        const originalText = button.textContent;
        button.textContent = '⚠ Copied! SENSITIVE!';
        button.title = 'Do not share this value!';
        button.style.backgroundColor = '#d13438';
        button.style.color = 'white';
        setTimeout(() => { button.textContent = originalText; button.title = ''; button.style.backgroundColor = ''; button.style.color = ''; }, 4000);
    }
}

function fallbackCopyTextToClipboard(text, button, isSensitive = false) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        const successful = document.execCommand('copy');
        if (successful) { if (isSensitive) { showSensitiveCopySuccess(button); } else { showCopySuccess(button); } }
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
    }
    document.body.removeChild(textArea);
}
