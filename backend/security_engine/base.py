"""
SecureAudit Pro - Base Scanner Adapter Interface
Defines the standard contract for all security scanning engines.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class BaseScannerAdapter(ABC):
    def __init__(self, target_url: str, config: Dict[str, Any] = None):
        self.target_url = target_url
        self.config = config or {}
        self.is_running = False
        self.is_stopped = False
        self.results = []
        self.events = []

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize adapter environment, verify tools and parameters."""
        pass

    @abstractmethod
    def validate_scope(self) -> bool:
        """Enforces domain and network boundary authorization."""
        pass

    @abstractmethod
    def configure(self, scan_profile: str, options: Dict[str, Any]) -> None:
        """Configures scanner intensity, modules, and rate limits."""
        pass

    @abstractmethod
    def execute(self, progress_callback=None) -> List[Dict[str, Any]]:
        """Executes the security scan, invoking progress callback on stage events."""
        pass

    @abstractmethod
    def collect_results(self) -> List[Dict[str, Any]]:
        """Extracts raw findings from the scanner."""
        pass

    @abstractmethod
    def normalize_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Converts raw findings into standard SecureAudit Pro vulnerability schema."""
        pass

    @abstractmethod
    def stop(self) -> bool:
        """Gracefully aborts any ongoing active scanning tasks."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Cleans up temporary files, sessions, or processes."""
        pass
