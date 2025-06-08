const vulnerableLibs = [
  { name: 'jQuery', pattern: /jquery(?:\.min)?\.js/i, vulnerableVersions: ['1.7.0', '1.8.3', '1.9.1'] },
  { name: 'AngularJS', pattern: /angular(?:\.min)?\.js/i, vulnerableVersions: ['1.4.6', '1.5.0'] }
];

const cmsFingerprints = [
  { name: 'WordPress', pattern: /wp-content|wp-includes|wp-admin/i },
  { name: 'Joomla', pattern: /\/templates\/|\/components\//i },
  { name: 'Drupal', pattern: /\/sites\/default\/files\//i },
  { name: 'Magento', pattern: /\/skin\/frontend\//i },
  { name: 'Shopify', pattern: /cdn\.shopify\.com/i },
  { name: 'Typo3', pattern: /typo3temp/i },
  { name: 'Ghost', pattern: /ghost\/assets/i },
  { name: 'Prestashop', pattern: /\/modules\//i }
];

async function checkExposedAPIEndpoints() {
  const endpoints = [
    '/api/', '/wp-json/', '/admin/', '/backup/', '/config/', '/.git/', '/.env'
  ];
  let report = '\n[+] Exposed API / Admin / Sensitive Endpoints Check:\n';
  for (const path of endpoints) {
    try {
      const url = new URL(path, location.href).href;
      const resp = await fetch(url, { method: 'HEAD', mode: 'no-cors' });
      if (resp.status === 200 || resp.status === 0) {
        report += ` - Possible exposed endpoint found: ${url} (status: ${resp.status})\n`;
      }
    } catch (e) {}
  }
  return report;
}

function checkSRI() {
  let report = '\n[+] Subresource Integrity (SRI) Check:\n';
  const scripts = [...document.querySelectorAll('script[src]')];
  const links = [...document.querySelectorAll('link[rel="stylesheet"][href]')];
  let missingSRI = 0;
  [...scripts, ...links].forEach(el => {
    const src = el.src || el.href || '';
    try {
      const url = new URL(src, location.href);
      if (url.origin !== location.origin && !el.hasAttribute('integrity')) {
        missingSRI++;
        report += ` - External resource without SRI: ${src}\n`;
      }
    } catch {}
  });
  if (missingSRI === 0) {
    report += ' - All external scripts/stylesheets have SRI attribute.\n';
  }
  return report;
}

async function checkDefaultAdminPanels() {
  const adminPaths = ['/admin', '/wp-admin', '/administrator', '/login', '/user/login'];
  let report = '\n[+] Default Admin Panels Check:\n';
  for (const path of adminPaths) {
    try {
      const url = new URL(path, location.href).href;
      const resp = await fetch(url, { method: 'HEAD', mode: 'no-cors' });
      if (resp.status === 200 || resp.status === 0) {
        report += ` - Possible admin/login page found: ${url} (status: ${resp.status})\n`;
      }
    } catch (e) {}
  }
  return report;
}

function detectCMS() {
  const html = document.documentElement.innerHTML.toLowerCase();
  for (const cms of cmsFingerprints) {
    if (cms.pattern.test(location.href) || cms.pattern.test(html)) {
      return `[+] CMS Detected: ${cms.name}`;
    }
  }
  return '[+] CMS Detected: Unknown or None';
}

function checkVulnerableLibs() {
  const scripts = [...document.querySelectorAll('script[src]')];
  let report = '\n[+] Vulnerable Libraries Check:\n';
  let found = false;
  for (const lib of vulnerableLibs) {
    for (const script of scripts) {
      const src = script.src || '';
      if (lib.pattern.test(src)) {
        report += ` - Found potentially vulnerable library: ${lib.name} (script src: ${src})\n`;
        found = true;
      }
    }
  }
  if (!found) report += ' - No vulnerable libraries found.\n';
  return report;
}

function checkSSLDetails() {
  let report = '\n[+] SSL/TLS Check:\n';
  try {
    if (location.protocol === 'https:') {
      report += ` - Site uses HTTPS protocol.\n`;
    } else {
      report += ` - Site does NOT use HTTPS.\n`;
    }
  } catch {
    report += ' - Unable to determine SSL status.\n';
  }
  return report;
}

async function runRecon() {
  let report = '';
  const forms = document.forms;
  report += `[+] Forms Found: ${forms.length}\n\n`;

  const vulnerableElements = [];
  for (let i = 0; i < forms.length; i++) {
    const form = forms[i];
    let hasCSRF = false;
    report += `Form ${i + 1}:\n`;
    for (const elem of form.elements) {
      const tag = elem.tagName;
      const type = elem.type || '';
      const name = elem.name || '';
      const inlineEvents = Array.from(elem.attributes)
        .filter(attr => attr.name.startsWith('on') && attr.value.trim() !== '')
        .map(attr => attr.name);
      report += `  - ${tag} [name=${name}] [type=${type}]\n`;
      if (type === 'hidden' && /csrf|token/i.test(name)) hasCSRF = true;
      if (inlineEvents.length > 0)
        vulnerableElements.push({ element: elem, reason: `Inline event handlers: ${inlineEvents.join(', ')}` });
      if (type === 'text' && /pass|pwd/i.test(name))
        vulnerableElements.push({ element: elem, reason: `Text input with password-like name "${name}"` });
    }
    if (!hasCSRF)
      vulnerableElements.push({ element: form, reason: `Form missing CSRF token (no hidden input with 'csrf' or 'token' in name)` });
    report += '\n';
  }

  vulnerableElements.forEach(({ element, reason }) => {
    if (element.style) {
      element.style.outline = '3px solid red';
      element.setAttribute('title', reason);
    }
  });

  report += `[+] Vulnerabilities Found: ${vulnerableElements.length}\n`;
  vulnerableElements.forEach(({ element, reason }, i) => {
    const tag = element.tagName || 'FORM';
    const name = element.name || '(no name)';
    report += `  ${i + 1}. <${tag.toLowerCase()}> [name=${name}]: ${reason}\n`;
  });

  report += '\n[+] XSS Payload Test Results:\n - testXSSPayloads function not defined. Skipped.\n';
  report += '\n' + detectCMS() + '\n';
  report += checkVulnerableLibs();
  report += checkSSLDetails();
  report += await checkExposedAPIEndpoints();
  report += await checkDefaultAdminPanels();
  report += checkSRI();

  return report;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ping") {
    sendResponse({ status: "ready" });
  } else if (message.type === "runRecon") {
    runRecon().then(report => sendResponse({ report }));
    return true; // για να υποστηρίξει async
  } else if (message.type === "clearHighlights") {
    document.querySelectorAll('[style*="3px solid red"]').forEach(el => {
      el.style.outline = '';
      el.removeAttribute('title');
    });
  }
});
