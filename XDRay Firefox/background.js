// Background page to intercept requests and capture payloads (Firefox MV2)
// Uses chrome.webRequest.onBeforeRequest; mapped via browserShim when running in Firefox

const requestBodies = new Map();

setInterval(() => {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    for (const [key, value] of requestBodies.entries()) {
        if (value.timestamp < fiveMinutesAgo) {
            requestBodies.delete(key);
        }
    }
}, 60000);

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.url.includes('https://security.microsoft.com/apiproxy')) {
            let bodyData = null;
            if (details.requestBody) {
                if (details.requestBody.raw) {
                    const decoder = new TextDecoder('utf-8');
                    const bodyParts = details.requestBody.raw.map(part => decoder.decode(part.bytes));
                    bodyData = bodyParts.join('');
                } else if (details.requestBody.formData) {
                    bodyData = JSON.stringify(details.requestBody.formData);
                }
            }
            requestBodies.set(details.url, {
                body: bodyData,
                method: details.method,
                timestamp: Date.now()
            });
        }
    },
    { urls: ["https://security.microsoft.com/apiproxy/*"] },
    ["requestBody"]
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_REQUEST_BODY') {
        const stored = requestBodies.get(message.url);
        if (stored) {
            sendResponse({ success: true, body: stored.body, method: stored.method });
            if (!stored.retrieved) {
                stored.retrieved = true;
                setTimeout(() => requestBodies.delete(message.url), 5000);
            }
        } else {
            sendResponse({ success: false, error: 'No body found for this URL' });
        }
        return true;
    }

    if (message.type === 'GET_COOKIE') {
        const cookieApi = typeof browser !== 'undefined' ? browser.cookies : chrome.cookies;

        cookieApi.getAll({
            url: "https://security.microsoft.com",
            name: message.cookieName
        }).then(cookies => {
            const cookie = cookies.find(c => c.name === message.cookieName) || cookies[0];
            if (cookie) {
                sendResponse({ success: true, value: cookie.value });
            } else {
                sendResponse({ success: false, error: 'Cookie not found' });
            }
        }).catch(error => {
            sendResponse({ success: false, error: error.message });
        });
        return true;
    }
});

console.log('XDRay Firefox background initialized');
