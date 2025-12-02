// Background service worker to intercept requests and capture payloads
// This uses chrome.webRequest.onBeforeRequest to capture request bodies

// Store request bodies temporarily
const requestBodies = new Map();

// Clean up old entries (older than 5 minutes)
setInterval(() => {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    for (const [key, value] of requestBodies.entries()) {
        if (value.timestamp < fiveMinutesAgo) {
            requestBodies.delete(key);
        }
    }
}, 60000);

// Intercept requests BEFORE they are sent to capture the actual payload
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        // Only process XDR API calls
        if (details.url.includes('https://security.microsoft.com/apiproxy')) {
            let bodyData = null;

            // Extract request body if present
            if (details.requestBody) {
                if (details.requestBody.raw) {
                    // Binary data - decode it
                    const decoder = new TextDecoder('utf-8');
                    const bodyParts = details.requestBody.raw.map(part => {
                        return decoder.decode(part.bytes);
                    });
                    bodyData = bodyParts.join('');
                } else if (details.requestBody.formData) {
                    // Form data
                    bodyData = JSON.stringify(details.requestBody.formData);
                }
            }

            // Store the request body with URL as key
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

// Listen for messages from panel to retrieve stored request bodies
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_REQUEST_BODY') {
        const stored = requestBodies.get(message.url);

        if (stored) {
            sendResponse({
                success: true,
                body: stored.body,
                method: stored.method
            });

            // Don't delete immediately - allow it to be retrieved multiple times
            // Mark it as retrieved and delete after a short delay (5 seconds)
            if (!stored.retrieved) {
                stored.retrieved = true;
                setTimeout(() => {
                    requestBodies.delete(message.url);
                }, 5000);
            }
        } else {
            sendResponse({
                success: false,
                error: 'No body found for this URL'
            });
        }

        return true; // Keep message channel open for async response
    }
});

console.log('XDRay background service worker initialized');
