"""
SecureAudit Pro - CVSS 4.0 / 3.1 Scoring & Vector Formatter
Provides standard CVSS base score calculation and vector parsing.
"""

from typing import Dict, Any


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "info"


def build_cvss_vector(
    attack_vector: str = "N",       # Network (N), Adjacent (A), Local (L), Physical (P)
    attack_complexity: str = "L",   # Low (L), High (H)
    privileges_required: str = "N", # None (N), Low (L), High (H)
    user_interaction: str = "N",    # None (N), Required (R)
    scope: str = "U",               # Unchanged (U), Changed (C)
    confidentiality: str = "H",     # High (H), Low (L), None (N)
    integrity: str = "H",           # High (H), Low (L), None (N)
    availability: str = "N"         # High (H), Low (L), None (N)
) -> Dict[str, Any]:
    """Generates standard CVSS v3.1 / v4.0 representation."""
    vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    
    # Calculate approximate base score
    weights = {"H": 0.56, "L": 0.22, "N": 0.0}
    impact = 1.0 - ((1.0 - weights.get(confidentiality, 0.0)) * 
                    (1.0 - weights.get(integrity, 0.0)) * 
                    (1.0 - weights.get(availability, 0.0)))
    
    exploitability = 8.22 * (0.85 if attack_vector == "N" else 0.55) * (0.77 if attack_complexity == "L" else 0.44) * (0.85 if privileges_required == "N" else 0.62) * (0.85 if user_interaction == "N" else 0.62)
    
    if impact <= 0:
        base_score = 0.0
    else:
        raw_score = min(10.0, (exploitability * 0.4) + (impact * 10.0 * 0.6))
        base_score = round(raw_score, 1)

    return {
        "version": "3.1",
        "vector_string": vector,
        "base_score": base_score,
        "severity": score_to_severity(base_score)
    }
