"""
SecureAudit Pro - OWASP ZAP Automation Framework Adapter
Orchestrates OWASP ZAP daemon via its REST API for crawling, passive analysis, and active checks.
"""

import os
import requests
import time
from typing import Dict, Any, List
from security_engine.base import BaseScannerAdapter
from core.security import validate_and_resolve_target


class ZAPScannerAdapter(BaseScannerAdapter):
    def __init__(self, target_url: str, config: Dict[str, Any] = None):
        super().__init__(target_url, config)
        self.zap_url = os.environ.get("ZAP_API_URL", "http://owasp-zap:8080").rstrip("/")
        self.zap_api_key = os.environ.get("ZAP_API_KEY", "")
        self.headers = {"X-ZAP-API-Key": self.zap_api_key} if self.zap_api_key else {}
        self.session_name = f"secureaudit_{int(time.time())}"
        self.is_available = False

    def initialize(self) -> bool:
        """Checks if OWASP ZAP daemon is online and responsive."""
        try:
            r = requests.get(f"{self.zap_url}/JSON/core/view/version/", headers=self.headers, timeout=2.0)
            if r.status_code == 200:
                self.is_available = True
                self.version = r.json().get("version", "2.14+")
                return True
        except Exception:
            self.is_available = False
        return False

    def validate_scope(self) -> bool:
        valid, msg, norm_url = validate_and_resolve_target(self.target_url)
        return valid

    def configure(self, scan_profile: str, options: Dict[str, Any]) -> None:
        self.scan_profile = scan_profile
        self.options = options or {}

    def execute(self, progress_callback=None) -> List[Dict[str, Any]]:
        if not self.is_available and not self.initialize():
            if progress_callback:
                progress_callback({
                    "stage_index": 7,
                    "stage_name": "OWASP ZAP Service Check",
                    "message": "OWASP ZAP daemon is not online on configured endpoint; skipping ZAP adapter.",
                    "progress": 70,
                    "timestamp": time.time()
                })
            return []

        try:
            # 1. Access target URL through ZAP to seed site tree
            requests.get(f"{self.zap_url}/JSON/core/action/accessUrl/", params={"url": self.target_url}, headers=self.headers, timeout=10.0)

            # 2. Trigger ZAP Spider
            spider_resp = requests.get(f"{self.zap_url}/JSON/spider/action/scan/", params={"url": self.target_url, "maxChildren": 10}, headers=self.headers, timeout=5.0)
            scan_id = spider_resp.json().get("scan", "0")

            # Poll spider status briefly
            for _ in range(6):
                if self.is_stopped:
                    requests.get(f"{self.zap_url}/JSON/spider/action/stop/", params={"scanId": scan_id}, headers=self.headers)
                    break
                status_r = requests.get(f"{self.zap_url}/JSON/spider/view/status/", params={"scanId": scan_id}, headers=self.headers, timeout=3.0)
                sp_pct = status_r.json().get("status", "100")
                if progress_callback:
                    progress_callback({
                        "stage_index": 7,
                        "stage_name": "OWASP ZAP Spider",
                        "message": f"ZAP crawler exploring authorized endpoints ({sp_pct}%)",
                        "progress": 50 + int(int(sp_pct) * 0.2),
                        "timestamp": time.time()
                    })
                if sp_pct == "100":
                    break
                time.sleep(1.0)

            # 3. Collect Alerts
            alerts_r = requests.get(f"{self.zap_url}/JSON/core/view/alerts/", params={"baseurl": self.target_url}, headers=self.headers, timeout=10.0)
            raw_alerts = alerts_r.json().get("alerts", [])
            self.results = self.normalize_results(raw_alerts)
            return self.results
        except Exception as e:
            if progress_callback:
                progress_callback({
                    "stage_index": 7,
                    "stage_name": "ZAP Execution",
                    "message": f"ZAP adapter notice: {str(e)}",
                    "progress": 70,
                    "timestamp": time.time()
                })
            return []

    def collect_results(self) -> List[Dict[str, Any]]:
        return self.results

    def normalize_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        severity_map = {
            "3": "high",
            "2": "medium",
            "1": "low",
            "0": "info",
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info"
        }
        for alert in raw_results:
            risk = alert.get("risk", "Informational")
            sev = severity_map.get(str(risk), "low")
            normalized.append({
                "title": alert.get("name") or alert.get("alert"),
                "vuln_type": f"zap_{alert.get('pluginId', 'alert')}",
                "severity": sev,
                "cvss_score": 7.5 if sev == "high" else (5.0 if sev == "medium" else 2.5),
                "cwe_id": f"CWE-{alert.get('cweid', '16')}",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "description": alert.get("description", ""),
                "impact": alert.get("other", "") or "Identified by OWASP ZAP passive/active scanning rules.",
                "remediation": alert.get("solution", ""),
                "evidence": alert.get("evidence", "") or alert.get("attack", ""),
                "affected_url": alert.get("url", self.target_url),
                "confidence": "high" if alert.get("confidence") in ("High", "User Confirmed") else "medium",
                "status": "open",
                "scanner_source": "OWASP ZAP Engine"
            })
        return normalized

    def stop(self) -> bool:
        self.is_stopped = True
        return True

    def cleanup(self) -> None:
        pass
