/**
 * PhishGuard Automated Test Suite
 * Tests 12 required test scenarios:
 * 1. Normal HTTPS URL
 * 2. HTTP URL
 * 3. Very long URL
 * 4. URL containing multiple subdomains
 * 5. URL containing suspicious keywords
 * 6. URL containing an IP address as its hostname
 * 7. URL containing the @ symbol
 * 8. URL with numerous special characters
 * 9. Invalid URL
 * 10. Empty input
 * 11. URL with query parameters
 * 12. URL with a misleading subdomain
 */

import { execFileSync } from 'child_process';
import path from 'path';

interface TestCase {
  id: number;
  description: string;
  url: string;
  shouldSucceed: boolean;
  expectedClassification?: 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'UNKNOWN';
  expectedRiskRange?: [number, number];
  checkFeature?: (result: any) => boolean;
}

const TEST_CASES: TestCase[] = [
  // 1. Normal HTTPS URL
  {
    id: 1,
    description: 'Normal HTTPS URL',
    url: 'https://example.com',
    shouldSucceed: true,
    expectedClassification: 'SAFE',
    expectedRiskRange: [0, 30],
    checkFeature: (res) => {
      const httpsRow = res.characteristics_table.find((r: any) => r.feature === 'HTTPS');
      return httpsRow && httpsRow.actualResult === 'Enabled';
    }
  },
  // 2. HTTP URL
  {
    id: 2,
    description: 'HTTP URL',
    url: 'http://example.org',
    shouldSucceed: true,
    expectedClassification: 'SAFE',
    expectedRiskRange: [10, 30],
    checkFeature: (res) => {
      const httpsRow = res.characteristics_table.find((r: any) => r.feature === 'HTTPS');
      return httpsRow && httpsRow.actualResult === 'Not Enabled';
    }
  },
  // 3. Very long URL
  {
    id: 3,
    description: 'Very long URL',
    url: 'https://example.com/' + 'a'.repeat(90),
    shouldSucceed: true,
    expectedRiskRange: [0, 60],
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'URL Length');
      return row && row.actualResult.includes('Very Long');
    }
  },
  // 4. URL containing multiple subdomains
  {
    id: 4,
    description: 'URL containing multiple subdomains',
    url: 'https://portal.secure.auth.gateway.example.com',
    shouldSucceed: true,
    expectedRiskRange: [15, 60],
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'Number of Subdomains');
      return row && parseInt(row.actualResult, 10) >= 3;
    }
  },
  // 5. URL containing suspicious keywords
  {
    id: 5,
    description: 'URL containing suspicious keywords',
    url: 'https://service-portal.com/login-verify-account-password-update',
    shouldSucceed: true,
    expectedRiskRange: [20, 60],
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'Suspicious Keywords');
      return row && row.actualResult.includes('login') && row.actualResult.includes('verify');
    }
  },
  // 6. URL containing a private IP address as its hostname (Requirement 8: not treated as proof of phishing)
  {
    id: 6,
    description: 'URL containing a private IP address as its hostname (RFC 1918)',
    url: 'http://192.168.1.104/banking/auth',
    shouldSucceed: true,
    expectedClassification: 'SAFE',
    expectedRiskRange: [0, 30],
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'IP Address');
      return row && row.actualResult.includes('Detected') && row.actualResult.includes('Private');
    }
  },
  // 6b. Public IP address alone (SUSPICIOUS, not PHISHING by itself)
  {
    id: 62,
    description: 'URL containing a public IP address without phishing lure (SUSPICIOUS, not PHISHING)',
    url: 'http://93.184.216.34/index.html',
    shouldSucceed: true,
    expectedClassification: 'SUSPICIOUS',
    expectedRiskRange: [31, 60],
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'IP Address');
      return row && row.actualResult.includes('Public IP');
    }
  },
  // 6c. Public IP with compounding phishing lure (PHISHING)
  {
    id: 63,
    description: 'URL containing a public IP address with brand spoofing and lure keywords (PHISHING)',
    url: 'http://198.51.100.22/paypal-login/verify.php',
    shouldSucceed: true,
    expectedClassification: 'PHISHING',
    expectedRiskRange: [61, 100],
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'IP Address');
      return row && row.actualResult.includes('Detected');
    }
  },
  // 7. URL containing the @ symbol
  {
    id: 7,
    description: 'URL containing the @ symbol',
    url: 'http://legitimate-bank.com@malicious-phishing-host.xyz/login',
    shouldSucceed: true,
    expectedClassification: 'PHISHING',
    expectedRiskRange: [61, 100],
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'Presence of @ Symbol');
      return row && row.actualResult === 'Detected';
    }
  },
  // 8. URL with numerous special characters
  {
    id: 8,
    description: 'URL with numerous special characters',
    url: 'https://example.com/path?a=1&b=2&c=3&d=4;e=5!f=6*g=7~h=8',
    shouldSucceed: true,
    checkFeature: (res) => {
      const row = res.characteristics_table.find((r: any) => r.feature === 'Special Characters');
      return row && (row.actualResult.includes('Medium') || row.actualResult.includes('High'));
    }
  },
  // 9. Invalid URL
  {
    id: 9,
    description: 'Invalid URL (unsupported protocol)',
    url: 'ftp://unsupported-protocol-site.org',
    shouldSucceed: false
  },
  // 10. Empty input
  {
    id: 10,
    description: 'Empty input',
    url: '   ',
    shouldSucceed: false
  },
  // 11. URL with query parameters
  {
    id: 11,
    description: 'URL with query parameters',
    url: 'https://search.engine.com/search?q=cybersecurity+defense&source=chrome',
    shouldSucceed: true,
    expectedClassification: 'SAFE',
    expectedRiskRange: [0, 30],
    checkFeature: (res) => {
      return res.features.num_question >= 1 && res.features.num_equal >= 2;
    }
  },
  // 12. URL with a misleading subdomain
  {
    id: 12,
    description: 'URL with a misleading subdomain',
    url: 'http://paypal.com.account-update.xyz/login.php',
    shouldSucceed: true,
    expectedClassification: 'PHISHING',
    expectedRiskRange: [61, 100],
    checkFeature: (res) => {
      const brandInd = res.indicators.some((ind: string) => ind.toLowerCase().includes('paypal') || ind.toLowerCase().includes('brand'));
      return brandInd;
    }
  }
];

function runTests() {
  console.log('='.repeat(70));
  console.log('Running PhishGuard 12-Point Automated URL Analysis Tests');
  console.log('='.repeat(70));

  const pythonScript = path.resolve('backend', 'predict.py');
  let passed = 0;
  let failed = 0;

  for (const tc of TEST_CASES) {
    process.stdout.write(`Test ${tc.id}: ${tc.description}... `);

    try {
      const output = execFileSync(
        'python3',
        [pythonScript, '--url', tc.url, '--json'],
        { encoding: 'utf-8', timeout: 5000 }
      );
      const res = JSON.parse(output);

      if (!tc.shouldSucceed) {
        if (!res.success) {
          console.log('PASSED (Correctly caught error/invalid)');
          passed++;
        } else {
          console.log(`FAILED: Expected error but got success.`);
          failed++;
        }
        continue;
      }

      if (!res.success) {
        console.log(`FAILED: Expected success but got error: ${res.error}`);
        failed++;
        continue;
      }

      if (res.risk_score < 0 || res.risk_score > 100) {
        console.log(`FAILED: Risk score out of bounds (${res.risk_score})`);
        failed++;
        continue;
      }

      if (tc.expectedRiskRange) {
        const [min, max] = tc.expectedRiskRange;
        if (res.risk_score < min || res.risk_score > max) {
          console.log(`FAILED: Risk score ${res.risk_score} not in expected [${min}, ${max}]`);
          failed++;
          continue;
        }
      }

      if (tc.expectedClassification && res.classification !== tc.expectedClassification) {
        console.log(`FAILED: Expected classification ${tc.expectedClassification} but got ${res.classification}`);
        failed++;
        continue;
      }

      if (tc.checkFeature && !tc.checkFeature(res)) {
        console.log('FAILED: Characteristic check failed.');
        failed++;
        continue;
      }

      console.log(`PASSED [Score: ${res.risk_score}/100, Class: ${res.classification}]`);
      passed++;
    } catch (err: any) {
      if (!tc.shouldSucceed) {
        console.log('PASSED (Rejected as expected)');
        passed++;
      } else {
        console.log(`FAILED with exception: ${err.message}`);
        failed++;
      }
    }
  }

  console.log('='.repeat(70));
  console.log(`Test Results Summary: ${passed} Passed, ${failed} Failed out of ${TEST_CASES.length} total.`);
  console.log('='.repeat(70));

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
