// Θα κρατήσουμε τελευταία headers per tab για να τα περάσουμε στο popup
const tabHeaders = {};

// Listener για HTTP headers (μόνο response headers)
chrome.webRequest.onHeadersReceived.addListener(
  details => {
    tabHeaders[details.tabId] = details.responseHeaders;
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Απάντηση στο popup για headers
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'getHeaders') {
    const tabId = request.tabId;
    sendResponse({ headers: tabHeaders[tabId] || [] });
  } else if (request.type === 'getCookies') {
    // Παίρνουμε cookies για το domain
    chrome.cookies.getAll({ domain: request.domain }, (cookies) => {
      sendResponse(cookies);
    });
    return true; // async
  }
});
