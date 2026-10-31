"""Shared data model of the analysis chain.

These types are the contract between orchestrator, store, API and report.
All free-text fields that the AI produces are English ("*_en"); the German
counterpart ("*_de") is filled by the translation pipeline.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    PARTIAL = "partial"      # budget exhausted, not everything resolved
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"      # stopped by the prompt-injection guard


class TaskOrigin(str, Enum):
    TRIAGE = "triage"
    RECIPE = "recipe"
    QUESTION = "question"
    SPLIT = "split"          # decomposition of a larger task
    EVALUATOR = "evaluator"  # derived by self-evaluation (logical follow-up)
    PRIORITIZER = "prioritizer"
    USER = "user"
    ARTIFACT = "artifact"    # derived file that needs its own analysis (recursion)


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"      # evidence id and verbatim quote verified
    HYPOTHESIS = "hypothesis"    # plausible, not (fully) verified
    OPEN = "open"
    REJECTED = "rejected"        # failed verification, kept for the audit trail


class StepKind(str, Enum):
    PROMPT = "prompt"      # LLM call
    TOOL = "tool"          # gateway call
    GUARD = "guard"        # injection scan / action validation
    VERIFY = "verify"      # grounding check of claims
    EVALUATE = "evaluate"  # self-evaluation
    PRIORITIZE = "prioritize"
    TRANSLATE = "translate"
    SYSTEM = "system"


class TargetQuestion(BaseModel):
    id: str                                    # "Q1", "Q2", ...
    text_orig: str                             # as typed by the user (German or English)
    text_en: str = ""                          # translation used by the AI
    expected: Optional[str] = None             # optional expected answer (CTF flag, regex via "re:" prefix)


class JobSpec(BaseModel):
    """What the user submits in the dashboard."""
    title: str
    description: str = ""                      # what is this about
    context_info: str = ""                     # further information (origin, scenario, hints)
    target_questions: list[TargetQuestion] = Field(default_factory=list)
    focus: str = ""
    emulation_opt_in: bool = False             # always False in this phase
    budget_max_tasks: int = 60
    budget_max_steps: int = 600
    budget_max_minutes: int = 120
    # English versions used by the AI (filled by the translation pipeline at job start)
    title_en: str = ""
    description_en: str = ""
    context_info_en: str = ""
    focus_en: str = ""


class ToolSpec(BaseModel):
    name: str
    description: str
    params: dict[str, Any] = Field(default_factory=dict)   # name -> {"type","required","description"}
    read_only: bool = True


class ToolResult(BaseModel):
    ok: bool
    text: str                                  # bounded text result (what the AI and the UI see)
    tool_version: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)      # structured extras, e.g. {"file": ..., "line_start": ...}
    error: str = ""
    truncated: bool = False
