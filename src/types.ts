export type ClassificationType = 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'UNKNOWN';

export type RiskLevelType = 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN';

export interface UrlCharacteristicItem {
  feature: string;
  actualResult: string;
  category: 'normal' | 'warning' | 'danger' | 'neutral';
  detail?: string;
}

export interface ExtractedFeatures {
  url_length: number;
  domain_length: number;
  num_dots: number;
  num_hyphens: number;
  num_subdomains: number;
  num_special_chars: number;
  num_digits: number;
  has_at_symbol: number;
  is_ip_address: number;
  is_shortened: number;
  has_unusual_port: number;
  has_https: number;
  num_slash: number;
  num_question: number;
  num_equal: number;
  num_percent: number;
  suspicious_keyword_count: number;
  domain_depth: number;
  excessive_subdomains: number;
  misleading_brand_count: number;
}

export interface ScoreComponent {
  factor: string;
  points: number;
  reason: string;
}

export interface ScanResult {
  success: boolean;
  url: string;
  classification: ClassificationType;
  status: ClassificationType;
  classification_label: string;
  risk_level: RiskLevelType;
  risk_score: number;
  confidence: number;
  analysis_type: string;
  score_breakdown: ScoreComponent[];
  characteristics_table: UrlCharacteristicItem[];
  features: ExtractedFeatures;
  indicators: string[]; // Warning indicators
  positive_indicators: string[]; // Positive indicators
  recommendations: string[];
  hostname?: string;
  disclaimer: string;
}

export interface ScanHistoryItem {
  id: number;
  url: string;
  risk_score: number;
  classification: ClassificationType;
  risk_level: RiskLevelType;
  confidence: number;
  scanned_at: string;
  main_indicators?: string[];
}

export interface ConfusionMatrix {
  true_negative: number;
  false_positive: number;
  false_negative: number;
  true_positive: number;
}

export interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  framework?: string;
  total_samples?: number;
  confusion_matrix: ConfusionMatrix;
}
