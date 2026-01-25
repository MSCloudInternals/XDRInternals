// Minimal Firefox compatibility shim for Chrome-style APIs
// Maps promise-based browser.* APIs to callback-style chrome.* where needed
// Only implements methods used by this extension

(function () {
    if (typeof browser !== 'undefined' && typeof chrome === 'undefined') {
        const wrapPromise = (promise, callback) => {
            if (typeof callback === 'function') {
                promise.then(result => callback(result)).catch(err => {
                    console.error('Shimmed API call failed', err);
                    callback(undefined);
                });
            }
            return promise;
        };

        const shim = {
            runtime: {
                sendMessage: (message, callback) => wrapPromise(browser.runtime.sendMessage(message), callback),
                onMessage: browser.runtime.onMessage
            },
            cookies: {
                getAll: (details, callback) => wrapPromise(browser.cookies.getAll(details), callback)
            },
            devtools: browser.devtools,
            webRequest: browser.webRequest
        };

        Object.defineProperty(window, 'chrome', {
            value: shim,
            writable: false,
            configurable: false
        });
    }
})();
