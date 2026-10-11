"""
PhishGuard - URL Prediction Pipeline
College CSE Mini Project: Phishing Website Detection System

Performs complete URL analysis, calculates 0-100 risk score with transparent
scoring breakdown, evaluates ML and heuristic evidence, and returns structured findings.
"""

import os
import sys
import json
import pickle
import argparse
from feature_extractor import (
    validate_and_normalize_url,
    extract_features,
    generate_indicators_and_recs,
    FEATURE_NAMES
)

MODEL_PKL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
MODEL_JSON_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.json")


def load_model():
    """Loads the trained model from pickle or falls back to JSON definition."""
    if os.path.exists(MODEL_PKL_PATH):
        try:
            with open(MODEL_PKL_PATH, "rb") as f:
                return pickle.load(f), "Random Forest Classifier (phishing_model.pkl)"
        except Exception:
            pass

    if os.path.exists(MODEL_JSON_PATH):
        try:
            with open(MODEL_JSON_PATH, "r", encoding="utf-8") as f:
                return json.load(f), "Random Forest JSON Ensemble (phishing_model.json)"
        except Exception:
            pass

    return None, "Rule-Based Heuristic Analysis Engine"


def predict_proba_from_json(json_model, sample):
    """Predicts probability using exported tree structures from JSON."""
    trees = json_model.get("model", {}).get("trees", [])
    if not trees:
        return 0.5

    def eval_node(node, s):
        if node["leaf"]:
            return node["prob"]
        f_idx = node["feature"]
        if s[f_idx] <= node["threshold"]:
            return eval_node(node["left"], s)
        else:
            return eval_node(node["right"], s)

    tree_probs = [eval_node(t, sample) for t in trees]
    return sum(tree_probs) / len(tree_probs) if tree_probs else 0.5


def predict_url(raw_url: str, model_tuple=None) -> dict:
    """
    Main prediction pipeline:
    Analyzes URL characteristics, calculates risk score, returns full results.
    """
    # 1. Validation & normalization
    normalized_url, validation_err = validate_and_normalize_url(raw_url)
    if validation_err:
        return {
            "success": False,
            "error": validation_err,
            "classification": "UNKNOWN",
            "classification_label": "UNKNOWN / NEEDS VERIFICATION",
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "confidence": 0.0,
            "disclaimer": "This tool provides a risk assessment, not a guarantee of website safety."
        }

    # 2. Extract features and characteristics table
    extraction = extract_features(normalized_url)
    features_dict = extraction["features"]
    characteristics_table = extraction["characteristics_table"]
    meta = extraction["meta"]

    # 3. Generate explainable indicators and safety recommendations
    warnings, positives, recommendations = generate_indicators_and_recs(features_dict, meta)

    # 4. Transparent Heuristic Scoring Breakdown (Avoids double-counting)
    score_breakdown = []
    heuristic_points = 0

    # Factor A: Protocol (HTTP unencrypted is a minor risk signal, but alone does NOT make it phishing)
    if features_dict["has_https"] == 0:
        pts = 15
        heuristic_points += pts
        score_breakdown.append({
            "factor": "Insecure Protocol (HTTP)",
            "points": pts,
            "reason": "Traffic is unencrypted and susceptible to interception."
        })

    # Factor B: Host identification (Mutually exclusive primary host check)
    is_priv = meta.get("is_private_ip", False)
    if features_dict["is_ip_address"] == 1:
        if is_priv:
            pts = 5
            heuristic_points += pts
            score_breakdown.append({
                "factor": "Private/Local Network IP Address",
                "points": pts,
                "reason": "Address belongs to a private network (RFC 1918/loopback). Not an indicator of public phishing."
            })
        else:
            pts = 25
            heuristic_points += pts
            score_breakdown.append({
                "factor": "Raw Public IP Address Hostname",
                "points": pts,
                "reason": "Host uses a raw public IP instead of a registered domain name."
            })
    elif features_dict["is_shortened"] == 1:
        pts = 25
        heuristic_points += pts
        score_breakdown.append({
            "factor": "URL Shortener Service",
            "points": pts,
            "reason": "Shortened URLs obscure destination and prevent upfront domain inspection."
        })

    # Factor C: Brand Spoofing (Strong indicator)
    if features_dict["misleading_brand_count"] > 0:
        pts = 30
        heuristic_points += pts
        brands = ", ".join(meta["matched_brands"])
        score_breakdown.append({
            "factor": "Brand Impersonation / Typosquatting",
            "points": pts,
            "reason": f"URL mimics popular brand '{brands}' outside legitimate domain registry."
        })

    # Factor D: Suspicious Lure Keywords (Capped to prevent double-counting with brand spoofing)
    if features_dict["suspicious_keyword_count"] > 0:
        kw_count = features_dict["suspicious_keyword_count"]
        # If brand spoofing is already triggered, cap keywords at 10 to prevent double penalty
        pts = 10 if (features_dict["misleading_brand_count"] > 0 or kw_count == 1) else min(20, kw_count * 10)
        heuristic_points += pts
        matched_kw = ", ".join(meta["matched_keywords"])
        score_breakdown.append({
            "factor": "Phishing Lure Keywords",
            "points": pts,
            "reason": f"Contains security/account action keywords: {matched_kw}."
        })

    # Factor E: Structure & Subdomain Depth
    if features_dict["excessive_subdomains"] == 1:
        pts = 15
        heuristic_points += pts
        score_breakdown.append({
            "factor": "Excessive Nested Subdomains",
            "points": pts,
            "reason": f"Detected {features_dict['num_subdomains']} subdomains, often used to disguise domains."
        })

    if features_dict["num_hyphens"] >= 3:
        pts = 10
        heuristic_points += pts
        score_breakdown.append({
            "factor": "Multiple Hyphens in URL",
            "points": pts,
            "reason": f"Detected {features_dict['num_hyphens']} hyphens, characteristic of deceptive domain names."
        })

    # Factor F: Obfuscation Delimiters (@ symbol, unusual port, suspicious TLD)
    if features_dict["has_at_symbol"] == 1:
        pts = 25
        heuristic_points += pts
        score_breakdown.append({
            "factor": "@ Symbol in URL",
            "points": pts,
            "reason": "May cause browsers to ignore userinfo text prior to the @ symbol."
        })

    if features_dict["has_unusual_port"] == 1:
        pts = 15
        heuristic_points += pts
        score_breakdown.append({
            "factor": "Non-Standard Port",
            "points": pts,
            "reason": f"Port {meta.get('port')} is non-standard for public web applications."
        })

    if meta.get("tld") in {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "cc", "club", "vip", "work"}:
        pts = 15
        heuristic_points += pts
        score_breakdown.append({
            "factor": "High-Abuse Top-Level Domain",
            "points": pts,
            "reason": f"The .{meta['tld']} TLD is disproportionately associated with spam and short-lived phishing."
        })

    heuristic_score = min(100, heuristic_points)

    # 5. ML Model Inference
    if model_tuple is None:
        model, framework_name = load_model()
    else:
        model, framework_name = model_tuple

    sample_vector = [features_dict[name] for name in FEATURE_NAMES]
    ml_prob = None
    if model is not None:
        try:
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba([sample_vector])[0]
                ml_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            elif hasattr(model, "trees"):
                probs = model.predict_proba([sample_vector])
                ml_prob = float(probs[0])
            elif isinstance(model, dict) and "model" in model:
                ml_prob = float(predict_proba_from_json(model, sample_vector))
        except Exception:
            ml_prob = None

    # Guardrail Enforcement (Requirement 8):
    # 1. Neither private IP addresses, HTTP, URL length, nor suspicious keywords can be treated as proof of phishing by themselves.
    # 2. PHISHING (risk score 61–100) strictly requires compounding evidence of malicious deception:
    #    - Brand spoofing / typosquatting (e.g. imitating popular brand on unauthorized host)
    #    - Obfuscated redirection (@ symbol)
    #    - URL shortening with phishing lure keywords
    #    - Public IP combined with phishing lure keywords or unusual ports
    #    - Multiple compounding structural deceptions (excessive subdomains + multiple hyphens + high-risk TLD or multiple keywords)
    has_strong_phishing_proof = (
        features_dict["misleading_brand_count"] > 0 or
        features_dict["has_at_symbol"] == 1 or
        (features_dict["is_shortened"] == 1 and features_dict["suspicious_keyword_count"] >= 2) or
        (features_dict["is_ip_address"] == 1 and not is_priv and (features_dict["suspicious_keyword_count"] >= 1 or features_dict["has_unusual_port"] == 1)) or
        (features_dict["suspicious_keyword_count"] >= 2 and features_dict["num_hyphens"] >= 3 and features_dict["excessive_subdomains"] == 1) or
        (features_dict["excessive_subdomains"] == 1 and features_dict["num_hyphens"] >= 3 and meta.get("tld") in {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "cc", "club", "vip", "work"})
    )

    is_benign_pattern = (
        features_dict["is_ip_address"] == 0 and
        features_dict["has_at_symbol"] == 0 and
        features_dict["is_shortened"] == 0 and
        features_dict["misleading_brand_count"] == 0 and
        features_dict["suspicious_keyword_count"] <= 1 and
        features_dict["excessive_subdomains"] == 0 and
        features_dict["num_hyphens"] < 3 and
        (meta.get("tld") not in {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "cc", "club", "vip", "work"})
    )

    if is_priv and features_dict["misleading_brand_count"] == 0:
        # Private IPs on internal networks (RFC 1918) cannot be public phishing sites
        risk_score = min(30, heuristic_score)
        analysis_type = "Rule-Based Heuristic Analysis & URL Lexical Inspection"
        confidence = 0.96
    elif is_benign_pattern or not has_strong_phishing_proof:
        # If no severe compounding proof is present, cap score at 60 (SAFE or SUSPICIOUS, never PHISHING)
        if is_benign_pattern:
            risk_score = min(30, heuristic_score)
            analysis_type = "Rule-Based Heuristic Analysis & URL Lexical Inspection"
            confidence = 0.95
        else:
            if ml_prob is not None:
                ml_score = int(ml_prob * 100)
                risk_score = min(60, max(heuristic_score, int(round(heuristic_score * 0.7 + ml_score * 0.3))))
                analysis_type = f"Hybrid ML Ensemble ({framework_name}) & Rule-Based Heuristics"
                confidence = round(max(0.72, min(0.95, abs(ml_prob - 0.5) * 1.5 + 0.65)), 2)
            else:
                risk_score = min(60, heuristic_score)
                analysis_type = "Rule-Based Heuristic Analysis & URL Lexical Inspection"
                confidence = round(max(0.72, min(0.92, 0.70 + len(score_breakdown) * 0.05)), 2)
    elif ml_prob is not None:
        ml_score = int(ml_prob * 100)
        risk_score = max(heuristic_score, ml_score)
        risk_score = max(61, min(100, risk_score))
        analysis_type = f"Hybrid ML Ensemble ({framework_name}) & Rule-Based Heuristics"
        confidence = round(max(0.85, min(0.99, abs(ml_prob - 0.5) * 1.5 + 0.75)), 2)
    else:
        risk_score = max(61, min(100, heuristic_score))
        analysis_type = "Rule-Based Heuristic Analysis & URL Lexical Inspection"
        confidence = round(max(0.80, min(0.95, 0.75 + len(score_breakdown) * 0.05)), 2)

    # 6. Classification & Risk Level according to Section 2 & 3
    # 0–30: Low Risk -> SAFE
    # 31–60: Medium Risk -> SUSPICIOUS
    # 61–100: High Risk -> PHISHING
    if risk_score <= 30:
        classification = "SAFE"
        classification_label = "SAFE — LOW DETECTED RISK"
        risk_level = "LOW"
    elif risk_score <= 60:
        classification = "SUSPICIOUS"
        classification_label = "SUSPICIOUS — FURTHER VERIFICATION RECOMMENDED"
        risk_level = "MEDIUM"
    else:
        classification = "PHISHING"
        classification_label = "PHISHING — STRONG PHISHING INDICATORS"
        risk_level = "HIGH"

    return {
        "success": True,
        "url": normalized_url,
        "classification": classification,
        "status": classification,
        "classification_label": classification_label,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence": confidence,
        "analysis_type": analysis_type,
        "score_breakdown": score_breakdown,
        "characteristics_table": characteristics_table,
        "features": features_dict,
        "indicators": warnings,
        "positive_indicators": positives,
        "recommendations": recommendations,
        "hostname": meta["hostname"],
        "disclaimer": (
            "This tool provides a risk assessment based on structural and lexical URL characteristics, "
            "not a guarantee of website safety. Positive indicators do not prove that a website is legitimate. "
            "Safe URL analysis only."
        )
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishGuard Complete URL Predictor")
    parser.add_argument("--url", type=str, required=True, help="URL to analyze")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    res = predict_url(args.url)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"URL: {res.get('url')}")
        print(f"Classification: {res.get('classification_label')}")
        print(f"Risk Score: {res.get('risk_score')}/100 ({res.get('risk_level')})")
        print(f"Analysis Type: {res.get('analysis_type')}")
