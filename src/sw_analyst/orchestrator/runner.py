"""Executes ONE task: the agent loop (model -> JSON action -> guard -> tool -> evidence -> ... -> finish).

Every turn is stored as a Step with what / how / why / duration. All sample-derived text reaches the model
only through sanitize_untrusted() and every model action passes validate_action() and the TaskGuard.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from sw_analyst.common.models import StepKind, ToolSpec
from sw_analyst.common.store import Store
from sw_analyst.common.util import preview
from sw_analyst.gateway.base import ToolGateway
from sw_analyst.guard import (SYSTEM_RULES_EN, TaskGuard, sanitize_untrusted, validate_action)
from sw_analyst.llm.base import ChatMessage, LLMClient, LLMError
from sw_analyst.orchestrator.verifier import answer_values_grounded, verify_finding
from sw_analyst.prompts.registry import ACTION_SCHEMA, SYSTEM_BASE, get_prompt

MAX_TURNS = 10
MAX_INVALID = 3
PROMPT_EVIDENCE_CHARS = 6000
CONTEXT_CHAR_BUDGET = 36000   # rough guard for 16k-token contexts (about 4 chars per token incl. reserve)


@dataclass
class TaskOutcome:
    status: str                        # done | failed | blocked
    summary: str = ""
    finding_ids: list[str] = field(default_factory=list)
    confirmed_ids: list[str] = field(default_factory=list)
    subtasks: list[dict] = field(default_factory=list)
    answer_text: str = ""
    error: str = ""


def _tools_block(tools: list[ToolSpec]) -> str:
    lines = []
    for t in tools:
        params = ", ".join(f"{k}:{v.get('type', 'str')}{'*' if v.get('required') else ''}" for k, v in t.params.items())
        lines.append(f"- {t.name}({params}): {t.description}")
    return "\n".join(lines)


class TaskRunner:
    def __init__(self, store: Store, llm: LLMClient, gateway: ToolGateway):
        self.store, self.llm, self.gateway = store, llm, gateway

    # ---- prompt building -------------------------------------------------------------------
    def known_findings_text(self, job_id: str, limit: int = 25) -> str:
        rows = self.store.list_findings(job_id, "confirmed")[-limit:]
        if not rows:
            return "(nothing confirmed yet)"
        return "\n".join(f"- {f['id']}: {f['statement_en']} [evidence: {', '.join(f['evidence_ids'])}]" for f in rows)

    def render_task_prompt(self, job: dict, task: dict, tools: list[ToolSpec]) -> tuple[str, str, str, str]:
        spec = job["spec"]
        qs = "\n".join(f"- {q['id']}: {q.get('text_en') or q['text_orig']}" for q in spec["target_questions"]) or "(none)"
        common = dict(
            goal=task["goal"], title=task["title"], reason=task["reason"] or "part of the recipe",
            detected_type=job["detected_type"] or "unknown", sample_sha256=job["sample_sha256"],
            recipe=job["recipe"] or "generic",
            description=spec.get("description_en") or spec.get("description") or "(none)",
            context_info=spec.get("context_info_en") or spec.get("context_info") or "(none)",
            focus=spec.get("focus_en") or spec.get("focus") or "(none)",
            questions=qs, known=self.known_findings_text(job["id"]),
            action_schema=ACTION_SCHEMA, tools=_tools_block(tools))
        if task["kind"] == "question":
            p = get_prompt("task.question")
            qid = task["params"].get("question_id", "")
            ans = self.store.get_answer(job["id"], qid) or {}
            body = p.render(question_id=qid, question_text=ans.get("text_en") or ans.get("text_orig", ""),
                            expected_hint="exact value" if ans.get("expected") else "free text", **common)
        else:
            p = get_prompt("task.analyze")
            body = p.render(**common)
        return p.id, p.version, p.sha256, body

    # ---- loop ------------------------------------------------------------------------------
    def run(self, job: dict, task: dict) -> TaskOutcome:
        job_id, task_id = job["id"], task["id"]
        tools = self.gateway.list_tools()
        pid, pver, psha, body = self.render_task_prompt(job, task, tools)
        self.store.update_task(task_id, prompt_id=pid, prompt_version=pver, prompt_sha256=psha, prompt_text=body)
        system = SYSTEM_BASE + "\n" + SYSTEM_RULES_EN
        messages = [ChatMessage(role="system", content=system), ChatMessage(role="user", content=body)]
        guard = TaskGuard(task_id)
        seen_calls: set[str] = set()
        invalid = 0
        # keep sample-relative context for the user-visible log
        for turn in range(1, MAX_TURNS + 1):
            self._compact(messages)
            sid = self.store.begin_step(job_id, task_id, StepKind.PROMPT.value, f"model turn {turn}",
                                        how=f"model={self.llm.model}, json_mode, think=on",
                                        why="decide next action (tool call or finish)",
                                        input_preview=messages[-1].content)
            t0 = time.monotonic()
            try:
                resp = self.llm.chat(messages, json_mode=True, think=True, max_tokens=2048)
            except LLMError as e:
                self.store.finish_step(sid, status="error", duration_ms=int((time.monotonic() - t0) * 1000),
                                       output_preview=str(e))
                return TaskOutcome("failed", error=f"LLM error: {e}")
            ms = int((time.monotonic() - t0) * 1000)
            raw = resp.text
            res = validate_action(raw, tools)
            verdict = guard.check_output(res, raw)
            for ev in verdict.events:
                self.store.add_guard_event(job_id, task_id, ev.get("stage", "output"), ev.get("rule", ""),
                                           ev.get("severity", "medium"), ev.get("action", "flagged"),
                                           ev.get("snippet", ""))
            if verdict.blocked:
                self.store.finish_step(sid, status="blocked", duration_ms=ms, output_preview=raw,
                                       how=f"model={self.llm.model}; tokens in/out={resp.prompt_tokens}/{resp.completion_tokens}",
                                       why=f"blocked by prompt guard: {verdict.reason}")
                return TaskOutcome("blocked", error=verdict.reason)
            why = (res.action or {}).get("why", "") if res.ok else "invalid action"
            self.store.finish_step(sid, status="ok" if res.ok else "error", duration_ms=ms, output_preview=raw,
                                   how=f"model={self.llm.model}; tokens in/out={resp.prompt_tokens}/{resp.completion_tokens}",
                                   why=why or "model chose action")
            if not res.ok:
                invalid += 1
                if invalid >= MAX_INVALID:
                    return TaskOutcome("failed", error=f"model produced {invalid} invalid actions: {res.error}")
                messages += [ChatMessage(role="assistant", content=preview(raw, 1500)),
                             ChatMessage(role="user", content=f"INVALID ACTION: {res.error}. Reply with exactly one valid JSON object as specified.")]
                continue
            action = res.action
            if res.kind == "finish":
                return self._finish(job, task, action)
            # ---- tool action
            key = json.dumps([action["tool"], action.get("args", {})], sort_keys=True)
            if key in seen_calls:
                messages += [ChatMessage(role="assistant", content=raw),
                             ChatMessage(role="user", content="You already made this exact call. Use its result, try different arguments, or finish.")]
                invalid += 1
                if invalid >= MAX_INVALID + 2:
                    return TaskOutcome("failed", error="loop: repeated identical tool calls")
                continue
            seen_calls.add(key)
            tsid = self.store.begin_step(job_id, task_id, StepKind.TOOL.value, f"tool {action['tool']}",
                                         how=json.dumps(action.get("args", {}), sort_keys=True),
                                         why=action.get("why", ""), tool=action["tool"],
                                         input_preview=json.dumps(action.get("args", {})))
            t1 = time.monotonic()
            result = self.gateway.call(job_id, action["tool"], action.get("args", {}))
            tms = int((time.monotonic() - t1) * 1000)
            ev = self.store.add_evidence(job_id, task_id, action["tool"], result.tool_version, action.get("args", {}),
                                         result.text if result.ok else f"[tool error] {result.error}",
                                         source_ref=result.meta)
            block = sanitize_untrusted(ev["text"], ev["id"], max_chars=PROMPT_EVIDENCE_CHARS)
            guard.observe_input(block)
            for d in block.detections:
                self.store.add_guard_event(job_id, task_id, "input", d.rule, d.severity,
                                           "redacted" if (block.redacted and d.severity == "high") else "flagged",
                                           d.snippet)
            self.store.finish_step(tsid, status="ok" if result.ok else "error", duration_ms=tms,
                                   output_preview=ev["text"], evidence_id=ev["id"])
            suffix = " (output truncated)" if result.truncated else ""
            messages += [ChatMessage(role="assistant", content=raw),
                         ChatMessage(role="user", content=f"Result of {action['tool']} is stored as {ev['id']}{suffix}.\n{block.text}")]
        return TaskOutcome("failed", error=f"no final answer after {MAX_TURNS} turns")

    # ---- finish handling ---------------------------------------------------------------------
    def _finish(self, job: dict, task: dict, action: dict) -> TaskOutcome:
        job_id, task_id = job["id"], task["id"]
        vsid = self.store.begin_step(job_id, task_id, StepKind.VERIFY.value, "verify findings against evidence",
                                     how="quotes must occur verbatim in the cited evidence",
                                     why="prevent unsupported claims")
        t0 = time.monotonic()
        ids, confirmed = [], []
        for raw in action.get("findings", []):
            vf = verify_finding(self.store, job_id, raw)
            f = self.store.add_finding(job_id, task_id, vf.statement, vf.status, vf.evidence_ids, vf.quotes,
                                       vf.reject_reason)
            ids.append(f["id"])
            if vf.status == "confirmed":
                confirmed.append(f["id"])
        for a in action.get("annotations", []):
            ev_id = a.get("evidence_id")
            if ev_id:
                ev = self.store.get_evidence(ev_id)
                if not ev or ev["job_id"] != job_id:
                    ev_id = None
            self.store.add_annotation(job_id, task_id, a["file"], a["line_start"], a["line_end"], a["text"],
                                      kind=a.get("kind", "note"), evidence_id=ev_id,
                                      finding_id=ids[0] if ids and a.get("kind") == "finding" else None)
        n_rej = sum(1 for fid in ids if self.store.get_finding(fid)["status"] == "rejected")
        self.store.finish_step(vsid, status="ok", duration_ms=int((time.monotonic() - t0) * 1000),
                               output_preview=f"{len(ids)} findings: {len(confirmed)} confirmed, {n_rej} rejected")
        answer_text = ((action.get("answer") or {}).get("text") or "").strip()
        return TaskOutcome("done", summary=action.get("summary", ""), finding_ids=ids, confirmed_ids=confirmed,
                           subtasks=action.get("subtasks", []), answer_text=answer_text)

    # ---- context hygiene ---------------------------------------------------------------------
    @staticmethod
    def _compact(messages: list[ChatMessage]) -> None:
        """Shrink old tool results to short previews when the context grows too large."""
        total = sum(len(m.content) for m in messages)
        i = 2
        while total > CONTEXT_CHAR_BUDGET and i < len(messages) - 2:
            m = messages[i]
            if m.role == "user" and "<untrusted_data" in m.content and len(m.content) > 600:
                head = m.content.split("\n", 1)[0]
                new = head + "\n[older tool output shortened to save context; full text stored as evidence]"
                total -= len(m.content) - len(new)
                messages[i] = ChatMessage(role="user", content=new)
            i += 1


def check_answer_grounding(store: Store, job_id: str, answer_text: str) -> tuple[bool, str]:
    ok, missing = answer_values_grounded(store, job_id, answer_text)
    return ok, ("" if ok else "value(s) not found in any evidence: " + ", ".join(missing))
