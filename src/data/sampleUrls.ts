export interface PresetUrl {
  name: string;
  url: string;
  expected: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
  description: string;
}

export const SAMPLE_URLS: PresetUrl[] = [
  {
    name: 'Google (Legitimate)',
    url: 'https://google.com',
    expected: 'SAFE',
    description: 'Valid SSL, clean domain structure, official search engine'
  },
  {
    name: 'GitHub (Legitimate)',
    url: 'https://github.com/torvalds/linux',
    expected: 'SAFE',
    description: 'Standard code repository URL with safe lexical features'
  },
  {
    name: 'PayPal Spoof (Phishing)',
    url: 'http://paypal-security-update-account.com/login.php',
    expected: 'PHISHING',
    description: 'Impersonates PayPal, plaintext HTTP, multiple hyphens, lure keywords'
  },
  {
    name: 'IP Address Banking (Phishing)',
    url: 'http://192.168.1.104/secure-banking/verify.html',
    expected: 'PHISHING',
    description: 'Raw IPv4 address instead of domain, plaintext HTTP, banking keyword'
  },
  {
    name: 'Shortened Link (Suspicious)',
    url: 'http://bit.ly/secure-wallet-update-2024',
    expected: 'SUSPICIOUS',
    description: 'URL shortening masks destination, urgent wallet keyword'
  },
  {
    name: 'Chase Bank Lookalike (Phishing)',
    url: 'http://chase-bank-verify-identity.xyz/login',
    expected: 'PHISHING',
    description: 'Suspicious .xyz TLD, brand impersonation, credential harvesting path'
  }
];
