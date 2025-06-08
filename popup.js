document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('run').addEventListener('click', runRecon);
  document.getElementById('clearHighlights').addEventListener('click', clearHighlights);
  document.getElementById('saveReport').addEventListener('click', saveReport);
});

let currentReport = '';
let currentUrl = '';
let currentTimestamp = '';

async function runRecon() {
  chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
    if (!tab || !tab.id) {
      document.getElementById('report').textContent = 'No active tab found.';
      return;
    }

    currentUrl = tab.url;
    currentTimestamp = new Date();

    chrome.tabs.sendMessage(tab.id, { type: "ping" }, async (pongResponse) => {
      if (chrome.runtime.lastError || !pongResponse || pongResponse.status !== "ready") {
        // Δεν απάντησε => inject το content.js
        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ['content.js']
        }, () => {
          if (chrome.runtime.lastError) {
            document.getElementById('report').textContent = 'Error injecting content script:\n' + chrome.runtime.lastError.message;
            return;
          }
          runReconAfterInjection(tab);
        });
      } else {
        // Το script είναι ήδη loaded
        runReconAfterInjection(tab);
      }
    });
  });
}

function runReconAfterInjection(tab) {
  chrome.runtime.sendMessage({ type: 'getHeaders', tabId: tab.id }, headers => {
    chrome.runtime.sendMessage({ type: 'getCookies', domain: new URL(tab.url).hostname }, cookies => {

      let extraReport = '\n[+] Cookie Flags:\n';
      cookies.forEach(cookie => {
        const secure = cookie.secure ? '✔' : '✘';
        const httpOnly = cookie.httpOnly ? '✔' : '✘';
        const sameSite = cookie.sameSite || 'None';
        extraReport += ` - ${cookie.name}: Secure=${secure}, HttpOnly=${httpOnly}, SameSite=${sameSite}\n`;
      });

      extraReport += '\n[+] HTTP Security Headers:\n';
      (headers.headers || []).forEach(h => {
        const name = h.name.toLowerCase();
        if (
          name === 'content-security-policy' ||
          name === 'strict-transport-security' ||
          name === 'x-frame-options' ||
          name === 'x-content-type-options'
        ) {
          extraReport += ` - ${h.name}: ${h.value}\n`;
        }
      });

      chrome.tabs.sendMessage(tab.id, { type: "runRecon" }, (response) => {
        if (chrome.runtime.lastError) {
          document.getElementById('report').textContent =
            'Error: Content script not available even after injection.\n' +
            'Details: ' + chrome.runtime.lastError.message;
          currentReport = '';
        } else {
          const header = `URL: ${currentUrl}\nDate: ${currentTimestamp.toLocaleString()}\n\n`;
          currentReport = header + response.report + extraReport;
          document.getElementById('report').innerHTML = colorizeReport(currentReport);
        }
      });
    });
  });
}

function clearHighlights() {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab || !tab.id) return;
    chrome.tabs.sendMessage(tab.id, { type: "clearHighlights" });
  });
}

function saveReport() {
  if (!currentReport) {
    alert('No report to save! Please run recon first.');
    return;
  }

  const safeUrl = currentUrl.replace(/[^a-z0-9]/gi, '_').toLowerCase().slice(0, 50);
  const timestampStr = currentTimestamp.toISOString().replace(/[:.-]/g, '');
  const filename = `recon_${safeUrl}_${timestampStr}.txt`;

  const blob = new Blob([currentReport], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function colorizeReport(text) {
  return text
    .replace(/✔/g, '✔')
    .replace(/✘/g, '✘')
    .replace(/\b(VULNERABLE)\b/g, '$1')
    .replace(/\b(OK)\b/g, '$1')
    .replace(/\b(No reflected XSS payload detected)\b/g, '$1')
    .replace(/\b(Form missing CSRF token.*?)$/gm, '$1')
    .replace(/\[+\] Vulnerabilities Found: (\d+)/g, (match, count) => {
      const color = parseInt(count) > 0 ? 'red' : 'green';
      return `${match}`;
    });
}
