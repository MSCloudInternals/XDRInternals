let cmdletMapping = [];
let capturedRequests = [];

// Load mapping
fetch('CmdletApiMapping.json')
    .then(response => response.json())
    .then(data => {
        cmdletMapping = data;
    })
    .catch(err => console.error('Failed to load mapping', err));

// Listen for network requests
chrome.devtools.network.onRequestFinished.addListener(request => {
    const url = request.request.url;
    if (url.includes('https://security.microsoft.com/apiproxy')) {
        processRequest(request);
    }
});

function processRequest(request) {
    const url = new URL(request.request.url);
    const method = request.request.method;
    const path = url.pathname + url.search;

    // Find matching cmdlet
    let matchedCmdlet = null;

    for (const map of cmdletMapping) {
        const mappingPath = new URL(map.ApiUri).pathname;
        const regexStr = '^' + mappingPath.replace(/\{[^}]+\}/g, '([^/]+)') + '$';
        const regex = new RegExp(regexStr, 'i');

        if (regex.test(url.pathname)) {
            matchedCmdlet = map.Cmdlet;
            break;
        }

        if (url.pathname.toLowerCase() === mappingPath.toLowerCase()) {
            matchedCmdlet = map.Cmdlet;
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

            const requestData = {
                method: method,
                url: request.request.url,
                cmdlet: matchedCmdlet || 'Invoke-XdrRestMethod',
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

    if (data.cmdlet !== 'Invoke-XdrRestMethod') {
        code += `# ${data.cmdlet}\n`;
        code += `${data.cmdlet}`;

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
});

document.getElementById('save-btn').addEventListener('click', () => {
    let scriptContent = '# XDRay Generated Script\n\n';
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
