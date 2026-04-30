"""migration-paranoid: static analyzer for risky database migrations."""

from .finding import Finding, Severity
from .scanner import scan_path

__version__ = "0.1.0"
__all__ = ["Finding", "Severity", "scan_path", "__version__"]
