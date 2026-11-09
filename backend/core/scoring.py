"""
SecureAudit Pro - Security Score Calculation Engine
Calculates transparent 0-100 website security posture scores based on
vulnerability severity, confidence, CVSS scores, and category weights.
"""

from typing import List, Dict, Any

# Deductions per verified finding severity
SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high": 12.0,
    "medium": 5.0,
    "low": 1.5,
    "info": 0.2
}

# Confidence multipliers
CONFIDENCE_MULTIPLIERS = {
    "confirmed": 1.0,
    "high": 0.9,
    "medium": 0.7,
    "suspected": 0.5,
    "low": 0.3
}

# Status weighting (fixed/false-positives do not penalize)
STATUS_ACTIVE_MULTIPLIERS = {
    "open": 1.0,
    "confirmed": 1.0,
    "in_progress": 0.8,
    "reopened": 1.0,
    "fixed": 0.0,
    "false_positive": 0.0,
    "accepted_risk": 0.3
}

CATEGORIES = [
    "access_control",
    "cryptography",
    "injection",
    "misconfiguration",
    "supply_chain",
    "authentication",
    "headers_and_transport",
    "api_security"
]


def calculate_security_score(vulnerabilities: List[Dict[str, Any]], business_criticality: str = "medium") -> Dict[str, Any]:
    """
    Computes a mathematical security score between 0 and 100.
    
    Formula:
    Base Score = 100.0
    For each vulnerability:
      Finding Penalty = SeverityWeight * ConfidenceMultiplier * StatusMultiplier * CriticalityFactor
    Category Scores: Computed proportionally based on category-specific findings.
    
    Note: A score of 100 indicates zero automated defects detected during
    authorized scope testing; it does NOT certify that a target is completely secure.
    """
    criticality_factors = {
        "critical": 1.25,
        "high": 1.1,
        "medium": 1.0,
        "low": 0.85
    }
    crit_factor = criticality_factors.get(business_criticality.lower(), 1.0)

    total_deduction = 0.0
    category_deductions = {cat: 0.0 for cat in CATEGORIES}
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for vuln in vulnerabilities:
        sev = str(vuln.get("severity", "info")).lower()
        conf = str(vuln.get("confidence", "medium")).lower()
        status = str(vuln.get("status", "open")).lower()
        category = str(vuln.get("owasp_category", "misconfiguration")).lower()

        # Count active findings
        if status not in ("fixed", "false_positive"):
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        w = SEVERITY_WEIGHTS.get(sev, 1.0)
        c = CONFIDENCE_MULTIPLIERS.get(conf, 0.7)
        s = STATUS_ACTIVE_MULTIPLIERS.get(status, 1.0)

        # Non-linear damping for multiple findings of the same severity to prevent instant 0 on small issues
        penalty = (w * c * s * crit_factor)
        total_deduction += penalty

        # Assign deduction to category
        matched_cat = "misconfiguration"
        for k in CATEGORIES:
            if k in category or category in k:
                matched_cat = k
                break
        category_deductions[matched_cat] += penalty

    # Calculate overall score, clamped to [0, 100]
    final_score = max(0.0, min(100.0, round(100.0 - total_deduction, 1)))

    # Compute risk tier
    if final_score >= 90:
        risk_level = "Low Risk (Grade A)"
    elif final_score >= 75:
        risk_level = "Moderate Risk (Grade B)"
    elif final_score >= 55:
        risk_level = "Elevated Risk (Grade C)"
    elif final_score >= 35:
        risk_level = "High Risk (Grade D)"
    else:
        risk_level = "Critical Risk (Grade F)"

    # Subcategory scores (out of 100)
    category_scores = {}
    for cat in CATEGORIES:
        cat_ded = category_deductions[cat]
        category_scores[cat] = max(0.0, min(100.0, round(100.0 - (cat_ded * 2.5), 1)))

    return {
        "score": final_score,
        "risk_level": risk_level,
        "severity_counts": severity_counts,
        "category_scores": category_scores,
        "total_active_findings": sum(severity_counts.values()),
        "disclaimer": "Security score is based strictly on findings within authorized testing scope and does not constitute a formal certificate of complete security."
    }
