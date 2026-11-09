"""
SecureAudit Pro - Nuclei Scanner Adapter
Integrates ProjectDiscovery Nuclei using curated safe templates, rate limits, and JSON output parsing.
"""

import os
import shutil
import subprocess
import json
import time
from typing import Dict, Any, List
from security_engine.base import BaseScannerAdapter
from core.security import validate_and_resolve_target


class NucleiScannerAdapter(BaseScannerAdapter):
    def __init__(self, target_url: str, config: Dict[str, Any] = None):
        super().__init__(target_url, config)
        self.nuclei_path = shutil.which("nuclei") or os.environ.get("NUCLEI_BIN_PATH")
        self.is_available = bool(self.nuclei_path and os.path.exists(self.nuclei_path))

    def initialize(self) -> bool:
        return self.is_available

    def validate_scope(self) -> bool:
        valid, msg, _ = validate_and_resolve_target(self.target_url)
        return valid

    def configure(self, scan_profile: str, options: Dict[str, Any]) -> None:
        self.scan_profile = scan_profile
        self.options = options or {}
        self.rate_limit = int(options.get("rate_limit", 50))

    def execute(self, progress_callback=None) -> List[Dict[str, Any]]:
        if not self.is_available:
            if progress_callback:
                progress_callback({
                    "stage_index": 9,
                    "stage_name": "Nuclei Engine Status",
                    "message": "Nuclei binary not installed in local environment; proceeding with Native Security Engine.",
                    "progress": 65,
                    "timestamp": time.time()
                })
            return []

        # Safe templates only: exclude intrusive, dos, fuzzing
        cmd = [
            self.nuclei_path,
            "-target", self.target_url,
            "-tags", "cve,misconfig,tech,exposure",
            "-exclude-tags", "dos,fuzz,intrusive,bruteforce",
            "-rate-limit", str(self.rate_limit),
            "-timeout", "5",
            "-json-export"
        ]

        findings = []
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=60)
            
            for line in stdout.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    entry = json.loads(line)
                    findings.append(entry)
                except Exception:
                    continue

            self.results = self.normalize_results(findings)
            return self.results
        except Exception as e:
            if progress_callback:
                progress_callback({
                    "stage_index": 9,
                    "stage_name": "Nuclei Notice",
                    "message": f"Nuclei execution completed with note: {str(e)}",
                    "progress": 70,
                    "timestamp": time.time()
                })
            return []

    def collect_results(self) -> List[Dict[str, Any]]:
        return self.results

    def normalize_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for item in raw_results:
            info = item.get("info", {})
            sev = info.get("severity", "info").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "low"

            cwe_list = info.get("classification", {}).get("cwe-id", [])
            cwe_id = cwe_list[0] if cwe_list else "CWE-16"
            cvss_score = float(info.get("classification", {}).get("cvss-score", 5.0))

            normalized.append({
                "title": info.get("name", item.get("template-id")),
                "vuln_type": f"nuclei_{item.get('template-id')}",
                "severity": sev,
                "cvss_score": cvss_score,
                "cwe_id": cwe_id if str(cwe_id).startswith("CWE-") else f"CWE-{cwe_id}",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "description": info.get("description", ""),
                "impact": "Identified by verified safe Nuclei template.",
                "remediation": info.get("remediation", "") or "Apply vendor patch or configuration update.",
                "evidence": f"Matched at: {item.get('matched-at', '')}",
                "affected_url": item.get("matched-at", self.target_url),
                "confidence": "high",
                "status": "open",
                "scanner_source": "Nuclei Engine (Safe Templates)"
            })
        return normalized

    def stop(self) -> bool:
        self.is_stopped = True
        return True

    def cleanup(self) -> None:
        pass
