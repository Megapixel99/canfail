"""canfail — break the thing on purpose, and check that your check notices.

A guard that has never failed may be incapable of failing. `blind` is the finding.
"""

from .core import (
    Outcome,
    Report,
    RestoreFailed,
    load_config,
    run_check,
    run_config,
)

__all__ = ["run_config", "run_check", "load_config", "Report", "Outcome", "RestoreFailed"]
__version__ = "0.1.0"
