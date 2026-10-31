"""Prompt-injection guard (docs/architecture/chain.md section 5).

Layers: scanner (detect), sanitize (untrusted_data wrapper + redaction), actions (strict
validation of the model's action JSON), taskguard (tripwire per task).
"""
from sw_analyst.guard.scanner import GUARD_VERSION, Detection, rule_count, scan

__all__ = ["GUARD_VERSION", "Detection", "rule_count", "scan"]

try:  # the remaining modules are added step by step
    from sw_analyst.guard.sanitize import SYSTEM_RULES_EN, SanitizedBlock, sanitize_untrusted
    __all__ += ["SYSTEM_RULES_EN", "SanitizedBlock", "sanitize_untrusted"]
except ImportError:  # pragma: no cover
    pass
try:
    from sw_analyst.guard.actions import ActionResult, validate_action
    __all__ += ["ActionResult", "validate_action"]
except ImportError:  # pragma: no cover
    pass
try:
    from sw_analyst.guard.taskguard import GuardVerdict, TaskGuard
    __all__ += ["GuardVerdict", "TaskGuard"]
except ImportError:  # pragma: no cover
    pass
