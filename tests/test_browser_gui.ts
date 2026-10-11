import { chromium, Browser, Page } from 'playwright';

interface TestResult {
  name: string;
  category: string;
  passed: boolean;
  error?: string;
  details?: string;
}

const results: TestResult[] = [];

function recordTest(category: string, name: string, passed: boolean, details?: string, error?: string) {
  results.push({ category, name, passed, details, error });
  const status = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`${status} | [${category}] ${name}${details ? ` -> ${details}` : ''}${error ? ` (Error: ${error})` : ''}`);
}

async function runBrowserTests() {
  console.log('='.repeat(75));
  console.log('Starting PhishGuard End-to-End Browser GUI Test Suite (Playwright)');
  console.log('Target Dev Server: http://localhost:3000');
  console.log('='.repeat(75));

  let browser: Browser | null = null;
  const consoleErrors: string[] = [];
  const failedRequests: string[] = [];

  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
    });

    const context = await browser.newContext({
      viewport: { width: 1280, height: 800 }
    });

    const page: Page = await context.newPage();

    // Listen to console and request errors
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        if (!text.includes('WebSocket') && !text.includes('vite') && !text.includes('favicon')) {
          consoleErrors.push(text);
        }
      }
    });

    page.on('requestfailed', (req) => {
      const url = req.url();
      if (!url.includes('favicon') && !url.includes('.map')) {
        failedRequests.push(`${req.method()} ${url} (${req.failure()?.errorText || 'Unknown'})`);
      }
    });

    // ----------------------------------------------------
    // TEST 1: Initial Page Load & Home Page Elements
    // ----------------------------------------------------
    try {
      const response = await page.goto('http://localhost:3000', { waitUntil: 'networkidle', timeout: 10000 });
      const statusOk = response?.status() === 200;
      recordTest('Home Page', 'Initial page load returns HTTP 200', statusOk, `Status: ${response?.status()}`);

      const title = await page.title();
      const titleMatches = title.includes('PhishGuard');
      recordTest('Home Page', 'HTML <title> contains PhishGuard', titleMatches, `Title: "${title}"`);

      const heading = await page.locator('h1').textContent();
      const headingOk = heading?.includes('Is This Website Safe?') ?? false;
      recordTest('Home Page', 'Hero headline renders correctly', headingOk, `Heading: "${heading?.trim()}"`);

      const inputVisible = await page.locator('input[placeholder*="Enter website URL"]').first().isVisible();
      recordTest('Home Page', 'URL input box is visible and accessible', inputVisible);

      const analyzeBtn = await page.locator('button:has-text("Analyze Website")').first().isVisible();
      recordTest('Home Page', '"Analyze Website" button is present', analyzeBtn);
    } catch (e: any) {
      recordTest('Home Page', 'Home page initialization', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 2: Validation - Empty Input
    // ----------------------------------------------------
    try {
      const input = page.locator('input[placeholder*="Enter website URL"]').first();
      await input.fill('');
      const submitBtn = page.locator('button:has-text("Analyze Website")').first();
      await submitBtn.click();
      await page.waitForTimeout(300);

      const errorText = await page.locator('text=Please enter a valid website URL').first().isVisible();
      recordTest('Validation', 'Empty URL input shows validation error', errorText, 'Error banner displayed');
    } catch (e: any) {
      recordTest('Validation', 'Empty URL validation', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 3: Validation - Malformed / Unsupported Protocol
    // ----------------------------------------------------
    try {
      const input = page.locator('input[placeholder*="Enter website URL"]').first();
      await input.fill('ftp://unsupported-site.org/file.zip');
      const submitBtn = page.locator('button:has-text("Analyze Website")').first();
      await submitBtn.click();
      await page.waitForTimeout(300);

      const errorAlert = await page.locator('text=Unsupported protocol').first().isVisible();
      recordTest('Validation', 'Unsupported protocol (ftp://) shows protocol error', errorAlert, 'Protocol rejected');
    } catch (e: any) {
      recordTest('Validation', 'Unsupported protocol validation', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 4: Valid URL Analysis (Safe Domain: google.com)
    // ----------------------------------------------------
    try {
      const input = page.locator('input[placeholder*="Enter website URL"]').first();
      await input.fill('https://google.com');

      const apiResponsePromise = page.waitForResponse(
        (res) => res.url().includes('/api/analyze') && res.request().method() === 'POST',
        { timeout: 7000 }
      );

      const submitBtn = page.locator('button:has-text("Analyze Website")').first();
      await submitBtn.click();

      const apiRes = await apiResponsePromise;
      const apiData = await apiRes.json();
      recordTest('Backend API', 'POST /api/analyze responds successfully for google.com', apiData.success === true, `API Classification: ${apiData.classification}, Score: ${apiData.risk_score}`);

      // Wait for UI results dashboard
      await page.waitForSelector('text=SAFE', { timeout: 6000 });

      const safeBadgeVisible = await page.locator('text=SAFE').first().isVisible();
      recordTest('Results Dashboard', 'SAFE status badge displayed in UI', safeBadgeVisible);

      const riskScoreText = await page.locator(`text=${apiData.risk_score}/100`).first().isVisible();
      recordTest('Results Dashboard', 'UI Risk Score matches backend response', riskScoreText, `Score: ${apiData.risk_score}/100`);

      const charTable = await page.locator('table').first().isVisible();
      recordTest('Results Dashboard', 'Characteristics Table is rendered', charTable);

      const httpsRow = await page.locator('td:has-text("HTTPS")').first().isVisible();
      recordTest('Results Dashboard', 'HTTPS characteristic evaluated', httpsRow);
    } catch (e: any) {
      recordTest('Results Dashboard', 'Safe URL analysis flow', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 5: Phishing URL Analysis & Deceptive Lure Detection
    // ----------------------------------------------------
    try {
      await page.locator('button:has-text("URL Scanner"), button:has-text("Scanner")').first().click();
      await page.waitForTimeout(400);

      const scannerInput = page.locator('input[placeholder*="Enter website URL"]').first();
      await scannerInput.fill('http://paypal-security-update-account.com/login.php');

      const apiResponsePromise = page.waitForResponse(
        (res) => res.url().includes('/api/analyze') && res.request().method() === 'POST',
        { timeout: 7000 }
      );

      const submitBtn = page.locator('button:has-text("Analyze Website")').first();
      await submitBtn.click();

      const apiRes = await apiResponsePromise;
      const apiData = await apiRes.json();
      recordTest('Backend API', 'POST /api/analyze identifies phishing attack', apiData.classification === 'PHISHING', `Classification: ${apiData.classification}, Score: ${apiData.risk_score}`);

      await page.waitForSelector('text=PHISHING', { timeout: 6000 });
      const phishingBadge = await page.locator('text=PHISHING').first().isVisible();
      recordTest('Results Dashboard', 'PHISHING status badge displayed in UI', phishingBadge);

      const brandWarning = await page.locator('text=/paypal|Brand Impersonation/i').first().isVisible();
      recordTest('Results Dashboard', 'Brand impersonation indicator flagged', brandWarning, 'PayPal spoofing warned');
    } catch (e: any) {
      recordTest('Results Dashboard', 'Phishing URL analysis flow', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 6: Private IP Address Hostname (Requirement 8)
    // ----------------------------------------------------
    try {
      const scannerInput = page.locator('input[placeholder*="Enter website URL"]').first();
      await scannerInput.fill('http://192.168.1.104/banking/auth');

      const apiResponsePromise = page.waitForResponse(
        (res) => res.url().includes('/api/analyze') && res.request().method() === 'POST',
        { timeout: 7000 }
      );

      const submitBtn = page.locator('button:has-text("Analyze Website")').first();
      await submitBtn.click();

      const apiRes = await apiResponsePromise;
      const apiData = await apiRes.json();

      const notPhishing = apiData.classification !== 'PHISHING';
      recordTest('Requirement 8', 'Private IP (192.168.1.104) is NOT classified as PHISHING', notPhishing, `Classification: ${apiData.classification}, Score: ${apiData.risk_score} (Max allowed: 30)`);

      const isSafeOrSuspicious = apiData.classification === 'SAFE' && apiData.risk_score <= 30;
      recordTest('Requirement 8', 'Private IP receives Low Risk / SAFE classification', isSafeOrSuspicious, `Risk Score: ${apiData.risk_score}/100`);

      await page.waitForTimeout(500);
      const privateIpText = await page.locator('text=/Private IP|192\\.168/i').first().isVisible();
      recordTest('Requirement 8', 'Characteristics table explicitly labels Private IP', privateIpText, 'Detected (Private IP)');
    } catch (e: any) {
      recordTest('Requirement 8', 'Private IP analysis check', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 7: Navigation Bar Tabs
    // ----------------------------------------------------
    const tabsToTest = [
      { name: 'History', expectedText: 'Scan History' },
      { name: 'Security Tips', expectedText: 'Security Tips' },
      { name: 'About', expectedText: 'About' },
      { name: 'Viva Guide', expectedText: 'Viva' },
      { name: 'Home', expectedText: 'Is This Website Safe?' }
    ];

    for (const tab of tabsToTest) {
      try {
        const tabBtn = page.locator(`button:has-text("${tab.name}"), a:has-text("${tab.name}")`).first();
        await tabBtn.click();
        await page.waitForTimeout(400);

        const contentVisible = await page.locator(`text=${tab.expectedText}`).first().isVisible();
        recordTest('Navigation', `Navigate to ${tab.name} tab`, contentVisible, `Expected heading "${tab.expectedText}" found`);
      } catch (e: any) {
        recordTest('Navigation', `Navigate to ${tab.name} tab`, false, undefined, e.message);
      }
    }

    // ----------------------------------------------------
    // TEST 8: Scan History Persistence & Clearing
    // ----------------------------------------------------
    try {
      await page.locator('button:has-text("History"), a:has-text("History")').first().click();
      await page.waitForTimeout(500);

      const initialRows = await page.locator('tbody tr').count();
      const hasHistory = initialRows > 0;
      recordTest('Scan History', 'Scan history displays past scans', hasHistory, `Found ${initialRows} history table items`);

      // Reload page and verify history survives page refresh
      await page.reload({ waitUntil: 'networkidle' });
      await page.locator('button:has-text("History"), a:has-text("History")').first().click();
      await page.waitForTimeout(500);

      const refreshedRows = await page.locator('tbody tr').count();
      const survivedRefresh = refreshedRows > 0;
      recordTest('Scan History', 'Scan history survives page reload (persistence)', survivedRefresh, `Preserved ${refreshedRows} items after reload`);

      // Test "Clear History" button
      const clearBtn = page.locator('button:has-text("Clear History")').first();
      if (await clearBtn.isVisible()) {
        const clearResponsePromise = page.waitForResponse(
          (res) => res.url().includes('/api/history/clear') && res.request().method() === 'POST',
          { timeout: 5000 }
        );
        await clearBtn.click();
        await clearResponsePromise;
        await page.waitForTimeout(500);

        const emptyMessageVisible = await page.locator('text=/No URLs scanned yet|No scan records/i').first().isVisible();
        recordTest('Scan History', 'Clearing history successfully empties records', emptyMessageVisible, 'Empty log message displayed');
      } else {
        recordTest('Scan History', 'Clear History button visible', false, 'Button not found');
      }
    } catch (e: any) {
      recordTest('Scan History', 'Scan history flow', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 9: Preset Demo Chips in Scanner
    // ----------------------------------------------------
    try {
      await page.locator('button:has-text("URL Scanner"), button:has-text("Scanner")').first().click();
      await page.waitForTimeout(400);

      const presetChip = page.locator('button:has-text("Google"), button:has-text("PayPal")').first();
      if (await presetChip.isVisible()) {
        const analyzeResponsePromise = page.waitForResponse(
          (res) => res.url().includes('/api/analyze') && res.request().method() === 'POST',
          { timeout: 7000 }
        );
        await presetChip.click();
        await analyzeResponsePromise;
        await page.waitForTimeout(800);

        const resultPresent = await page.locator('text=/WEBSITE SECURITY ANALYSIS|Risk Score/i').first().isVisible();
        recordTest('Demo Presets', 'Clicking preset sample chip triggers analysis', resultPresent, 'Preset analyzed directly');
      }
    } catch (e: any) {
      recordTest('Demo Presets', 'Preset chip functionality', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 10: Responsive Layout Testing (Mobile Viewport)
    // ----------------------------------------------------
    try {
      await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE viewport
      await page.waitForTimeout(400);

      const mobileInput = await page.locator('input[placeholder*="Enter website URL"]').first().isVisible();
      const mobileBtn = await page.locator('button:has-text("Analyze Website")').first().isVisible();
      const headerVisible = await page.locator('header').first().isVisible();

      recordTest('Mobile Responsiveness', 'URL Scanner and controls adapt to mobile viewport (375x667)', mobileInput && mobileBtn && headerVisible, 'Mobile layout renders cleanly');

      // Reset viewport back to desktop
      await page.setViewportSize({ width: 1280, height: 800 });
    } catch (e: any) {
      recordTest('Mobile Responsiveness', 'Mobile layout check', false, undefined, e.message);
    }

    // ----------------------------------------------------
    // TEST 11: Browser Console Errors & Failed Requests
    // ----------------------------------------------------
    const noSevereConsoleErrors = consoleErrors.length === 0;
    recordTest('Console & Network', 'Browser console has zero runtime exceptions', noSevereConsoleErrors, consoleErrors.length === 0 ? 'Clean console' : `Errors: ${consoleErrors.join('; ')}`);

    const noFailedRequests = failedRequests.length === 0;
    recordTest('Console & Network', 'Network requests completed without failures', noFailedRequests, failedRequests.length === 0 ? 'Zero failed requests' : `Failed: ${failedRequests.join('; ')}`);

    await browser.close();
  } catch (globalErr: any) {
    console.error('Fatal test error:', globalErr);
    recordTest('Global Suite', 'Playwright Browser Automation Execution', false, undefined, globalErr.message);
    if (browser) await browser.close();
  }

  // Summary
  console.log('\n' + '='.repeat(75));
  console.log('BROWSER GUI TEST SUITE SUMMARY');
  console.log('='.repeat(75));
  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.filter((r) => !r.passed).length;

  console.log(`Total Browser Checks Executed: ${results.length}`);
  console.log(`Passed: ${passedCount}`);
  console.log(`Failed: ${failedCount}`);
  console.log(`Pass Rate: ${((passedCount / results.length) * 100).toFixed(1)}%`);
  console.log('='.repeat(75));

  if (failedCount > 0) {
    process.exit(1);
  }
}

runBrowserTests();
