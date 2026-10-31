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
from sw_analyst.guard import (SYSTEM_RULES_EN, TaskGuard, action_json_schema, sanitize_untrusted, validate_action)
from sw_analyst.llm.base import ChatMessage, LLMClient, LLMError
from sw_analyst.orchestrator.agents import MODEL_ORIGINS, task_text
from sw_analyst.orchestrator.verifier import MIN_QUOTE, answer_values_grounded, norm, verify_finding
from sw_analyst.prompts.registry import ACTION_SCHEMA, DEFAULT_DONE_WHEN, SYSTEM_BASE, get_prompt

MAX_TURNS = 10
MAX_INVALID = 3
MAX_REPAIRS = 2               # chances to fix findings the checker refused before they are stored
REPLY_TOKENS = 3000           # thinking counts against this budget
REPLY_TOKENS_MAX = 4096       # after a cut-off reply; more does not fit next to the context in num_ctx 16384
PROMPT_EVIDENCE_CHARS = 6000
KNOWN_CHARS = 6000
OPEN_POINTS_CHARS = 2000
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
    described: set[str] = set()   # a parameter text shared by many tools (path) is printed once
    for t in tools:
        lines.append(f"- {t.name}: {t.description}")
        for k, v in t.params.items():
            line = f"    {k}:{v.get('type', 'str')}{' required' if v.get('required') else ''}"
            if v.get("default") is not None:
                line += f" default={v['default']}"
            if "min" in v or "max" in v:
                line += f" range={v.get('min', '')}..{v.get('max', '')}"
            text = v.get("description", "")
            if text and text not in described:
                described.add(text)
                line += f" - {text}"
            lines.append(line)
    return "\n".join(lines)


class TaskRunner:
    def __init__(self, store: Store, llm: LLMClient, gateway: ToolGateway):
        self.store, self.llm, self.gateway = store, llm, gateway

    # ---- prompt building -------------------------------------------------------------------
    def known_findings_text(self, job_id: str, limit: int = 25) -> str:
        """Newest confirmed findings with a quote to re-cite. Model text about the sample stays marked as data."""
        lines: list[str] = []
        used = 0
        confirmed = self.store.list_findings(job_id, "confirmed")
        for f in reversed(confirmed[-limit:]):
            q = (f["quotes"] or [{}])[0]
            line = (f"- {f['id']}: {f['statement_en']} [evidence: {', '.join(f['evidence_ids'])}; "
                    f"quote from {q.get('evidence_id', '-')}: \"{preview(q.get('quote', ''), 160)}\"]")
            if used + len(line) > KNOWN_CHARS:
                break
            lines.append(line)
            used += len(line)
        if not lines:
            return "(nothing confirmed yet)"
        if len(lines) < len(confirmed):
            lines.append(f"({len(confirmed) - len(lines)} older confirmed findings not shown)")
        return sanitize_untrusted("\n".join(reversed(lines)), "known-findings", max_chars=KNOWN_CHARS + 200).text

    def open_points_text(self, job_id: str, limit: int = 10) -> str:
        """Unproven findings a later task can test. GAP needs dynamic analysis; GUARD would send a task back into an attack."""
        rows = [f for f in self.store.list_findings(job_id)
                if f["status"] in ("hypothesis", "open") and not f["statement_en"].startswith(("GAP:", "GUARD:"))][-limit:]
        if not rows:
            return "(none)"
        return sanitize_untrusted("\n".join(f"- {f['id']}: {preview(f['statement_en'], 200)}" for f in rows),
                                  "open-points", max_chars=OPEN_POINTS_CHARS).text

    def _evidence_index_text(self, job_id: str) -> str:
        rows = self.store.evidence_index(job_id)
        if not rows:
            return "(none)"
        text = "\n".join(f"- {e['id']}: {e['tool']} {preview(json.dumps(e['params'], sort_keys=True), 100)}" for e in rows)
        return sanitize_untrusted(text, "evidence-index", max_chars=2000).text

    def render_task_prompt(self, job: dict, task: dict, tools: list[ToolSpec]) -> tuple[str, str, str, str]:
        spec = job["spec"]
        qs = "\n".join(f"- {q['id']}: {q.get('text_en') or q['text_orig']}" for q in spec["target_questions"]) or "(none)"
        params = task["params"]
        last = task.get("summary_en") or ""
        previous = ""
        if task["attempts"] > 1 and last:   # a retry must know what failed, otherwise it fails the same way
            previous = ("The previous attempt at this task failed. Change the approach.\n"
                        + sanitize_untrusted(last, "previous-attempt", max_chars=600).text + "\n")
        common = dict(
            guide=params.get("guide") or "No specific procedure; work from the goal.",
            tools_hint=", ".join(params.get("tools_hint") or []) or "(choose from the list)",
            input_file=params.get("path") or "sample", evidence_index=self._evidence_index_text(job["id"]),
            previous=previous, max_turns=MAX_TURNS,
            goal=task_text(task, task["goal"], "task-goal"), title=task_text(task, task["title"], "task-title"),
            reason=task_text(task, task["reason"], "task-reason") if task["reason"] else "part of the recipe",
            detected_type=job["detected_type"] or "unknown", sample_sha256=job["sample_sha256"],
            recipe=job["recipe"] or "generic",
            description=spec.get("description_en") or spec.get("description") or "(none)",
            context_info=spec.get("context_info_en") or spec.get("context_info") or "(none)",
            focus=spec.get("focus_en") or spec.get("focus") or "(none)",
            questions=qs, known=self.known_findings_text(job["id"]),
            hypotheses=self.open_points_text(job["id"]),
            done_when=task_text(task, params.get("done_when") or DEFAULT_DONE_WHEN, "task-done-when"),
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
        # What the task itself names is no sign of a hijack, even when a sample mentions the same word.
        guard = TaskGuard(task_id, guard_task_text(task))
        seen_calls: set[str] = set()
        invalid = repairs = 0
        reply_tokens = REPLY_TOKENS
        # keep sample-relative context for the user-visible log
        for turn in range(1, MAX_TURNS + 1):
            if turn == MAX_TURNS:
                messages.append(ChatMessage(role="user", content="LAST TURN. Reply with \"finish\" now: report what the "
                                            "evidence shows so far and name what stays open."))
            self._compact(messages)
            sid = self.store.begin_step(job_id, task_id, StepKind.PROMPT.value, f"model turn {turn}",
                                        how=f"model={self.llm.model}, json_mode, think=on, "
                                            f"seed={getattr(self.llm, 'seed', None)}, max_tokens={reply_tokens}",
                                        why="decide next action (tool call or finish)",
                                        input_preview=messages[-1].content)
            t0 = time.monotonic()
            try:
                resp = self.llm.chat(messages, json_mode=action_json_schema(tools), think=True, max_tokens=reply_tokens)
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
                msg = f"INVALID ACTION: {res.error}. Reply with exactly one valid JSON object as specified."
                if resp.done_reason == "length" or not raw.strip():
                    reply_tokens = REPLY_TOKENS_MAX
                    msg = ("Your reply was cut off by the token limit or empty. Think less and reply with one short "
                           "JSON object: fewer findings, short statements.")
                messages += [ChatMessage(role="assistant", content=preview(raw, 1500) or "(no output)"),
                             ChatMessage(role="user", content=msg)]
                continue
            action = res.action
            if res.kind == "finish":
                problems = self._finish_problems(job_id, task, action)
                if problems and repairs < MAX_REPAIRS and turn < MAX_TURNS:
                    repairs += 1
                    self.store.log(job_id, f"task {task_id}: checker refused the result, repair {repairs}",
                                   level="warn", problems=problems)
                    messages += [ChatMessage(role="assistant", content=raw),
                                 ChatMessage(role="user", content=(
                                     "CHECK FAILED, nothing was stored yet:\n" + "\n".join(f"- {p}" for p in problems)
                                     + "\nCopy each quote character by character from the cited tool result, cite the "
                                     "evidence that really holds it, or set status \"hypothesis\" and say what is "
                                     "missing. Reply with the corrected finish object."))]
                    continue
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
            args = action.get("args", {})
            stored = self.store.find_evidence(job_id, action["tool"], args)  # tools are deterministic, the sample is fixed
            tsid = self.store.begin_step(job_id, task_id, StepKind.TOOL.value, f"tool {action['tool']}",
                                         how=json.dumps(args, sort_keys=True) + (f"; reused {stored['id']}" if stored else ""),
                                         why=action.get("why", ""), tool=action["tool"],
                                         input_preview=json.dumps(args))
            t1 = time.monotonic()
            if stored:
                ev, ok, cut = stored, True, "[output truncated" in stored["text"]
            else:
                result = self.gateway.call(job_id, action["tool"], args)
                ok, cut = result.ok, result.truncated
                ev = self.store.add_evidence(job_id, task_id, action["tool"], result.tool_version, args,
                                             result.text if result.ok else f"[tool error] {result.error}",
                                             source_ref=result.meta)
            tms = int((time.monotonic() - t1) * 1000)
            block = sanitize_untrusted(ev["text"], ev["id"], max_chars=PROMPT_EVIDENCE_CHARS)
            guard.observe_input(block)
            self._record_injection(job_id, task_id, ev, block)
            for d in block.detections:
                self.store.add_guard_event(job_id, task_id, "input", d.rule, d.severity,
                                           "redacted" if (block.redacted and d.severity == "high") else "flagged",
                                           d.snippet)
            self.store.finish_step(tsid, status="ok" if ok else "error", duration_ms=tms,
                                   output_preview=ev["text"], evidence_id=ev["id"])
            suffix = " (output truncated)" if cut else ""
            messages += [ChatMessage(role="assistant", content=raw),
                         ChatMessage(role="user", content=f"Result of {action['tool']} is stored as {ev['id']}{suffix} "
                                                          f"[turn {turn} of {MAX_TURNS}, {MAX_TURNS - turn} left].\n{block.text}")]
        return TaskOutcome("failed", error=f"no final answer after {MAX_TURNS} turns")

    # ---- injection record ----------------------------------------------------------------------
    def _record_injection(self, job_id: str, task_id: str, ev: dict, block) -> None:
        """A hijack attempt is a forensic result. The platform records it, the model never has to repeat the text."""
        known = {f["statement_en"] for f in self.store.list_findings(job_id)}
        for d in block.detections:
            statement = f"Prompt injection attempt in sample (guard rule {d.rule})."
            if d.severity != "high" or statement in known:
                continue
            known.add(statement)
            quote = norm(d.snippet)
            ok = len(quote) >= MIN_QUOTE and quote in norm(ev["text"])
            self.store.add_finding(job_id, task_id, statement, "confirmed" if ok else "hypothesis", [ev["id"]],
                                   [{"evidence_id": ev["id"], "quote": quote}] if ok else [], "")

    # ---- finish handling ---------------------------------------------------------------------
    def _finish_problems(self, job_id: str, task: dict, action: dict) -> list[str]:
        """What the checker would refuse, without storing anything, so the model can still repair it."""
        out, confirmed = [], 0
        for i, raw in enumerate(action.get("findings", []), 1):
            vf = verify_finding(self.store, job_id, raw)
            confirmed += vf.status == "confirmed"
            if vf.reject_reason:
                out.append(f"finding {i}: {vf.reject_reason}")
        answer = ((action.get("answer") or {}).get("text") or "").strip()
        if task["kind"] == "question" and answer and not answer.upper().startswith("UNRESOLVED"):
            if not confirmed:
                out.append('the answer needs at least one finding with status "confirmed" in this reply')
            ok, why = check_answer_grounding(self.store, job_id, answer)
            if not ok:
                out.append(f"answer: {why}")
        return out

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


def guard_task_text(task: dict) -> str:
    """What may appear in tool calls without looking hijacked. A goal the model wrote can carry sample text itself."""
    own = [] if task["origin"] in MODEL_ORIGINS else [task["title"], task["goal"]]
    return " ".join([*own, task["params"].get("path") or "sample", *(task["params"].get("tools_hint") or [])])


def check_answer_grounding(store: Store, job_id: str, answer_text: str) -> tuple[bool, str]:
    ok, missing = answer_values_grounded(store, job_id, answer_text)
    return ok, ("" if ok else "value(s) not found in any evidence: " + ", ".join(missing))
