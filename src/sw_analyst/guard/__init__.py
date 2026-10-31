"""Prompt-injection guard (docs/architecture/chain.md section 5).

Layers: scanner (detect), sanitize (untrusted_data wrapper + redaction), actions (strict
validation of the model's action JSON), taskguard (tripwire per task).
"""
from sw_analyst.guard.actions import ActionResult, action_json_schema, validate_action
from sw_analyst.guard.sanitize import SYSTEM_RULES_EN, SanitizedBlock, sanitize_untrusted
from sw_analyst.guard.scanner import GUARD_VERSION, Detection, rule_count, scan
from sw_analyst.guard.taskguard import GuardVerdict, TaskGuard

__all__ = [
    "GUARD_VERSION", "rule_count", "Detection", "scan",
    "SanitizedBlock", "sanitize_untrusted", "SYSTEM_RULES_EN",
    "ActionResult", "action_json_schema", "validate_action", "TaskGuard", "GuardVerdict",
]
