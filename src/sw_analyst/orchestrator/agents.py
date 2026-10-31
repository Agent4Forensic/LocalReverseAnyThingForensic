"""Helper agents around the task loop: self-evaluation, prioritisation, decomposition.

All three ask the model for ONE JSON object, validate it strictly, and return plain data.
The engine applies the result; nothing here can delete tasks or call tools.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from sw_analyst.common.models import StepKind
from sw_analyst.common.store import Store
from sw_analyst.guard import SYSTEM_RULES_EN, sanitize_untrusted
from sw_analyst.llm.base import ChatMessage, LLMClient, LLMError
from sw_analyst.orchestrator.jsonutil import extract_json_object
from sw_analyst.prompts.registry import SYSTEM_BASE, get_prompt

MAX_FOLLOWUPS = 4
MAX_NEW_FROM_PRIORITIZER = 3
PRIO_MIN, PRIO_MAX = 1, 999


def _clip(s, n):
    return str(s or "").strip()[:n]


class HelperAgents:
    def __init__(self, store: Store, llm: LLMClient):
        self.store, self.llm = store, llm

    def _ask(self, job_id: str, task_id: str | None, kind: StepKind, what: str, why: str, prompt_id: str,
             think: bool = True, **fields) -> dict | None:
        p = get_prompt(prompt_id)
        body = p.render(**fields)
        sid = self.store.begin_step(job_id, task_id or "", kind.value, what,
                                    how=f"prompt={p.id}@{p.version} sha256={p.sha256[:12]}; model={self.llm.model}",
                                    why=why, input_preview=body)
        t0 = time.monotonic()
        try:
            resp = self.llm.chat([ChatMessage(role="system", content=SYSTEM_BASE + "\n" + SYSTEM_RULES_EN),
                                  ChatMessage(role="user", content=body)], json_mode=True, think=think, max_tokens=2000)
        except LLMError as e:
            self.store.finish_step(sid, status="error", duration_ms=int((time.monotonic() - t0) * 1000),
                                   output_preview=str(e))
            return None
        obj = extract_json_object(resp.text)
        self.store.finish_step(sid, status="ok" if obj else "error", duration_ms=int((time.monotonic() - t0) * 1000),
                               output_preview=resp.text)
        return obj

    # ---- self-evaluation ------------------------------------------------------------------
    def evaluate(self, job: dict, task: dict, summary: str, finding_ids: list[str], pending_titles: list[str],
                 known: str) -> dict:
        findings = [self.store.get_finding(f) for f in finding_ids]
        tf = "\n".join(f"- {f['id']} [{f['status']}]: {f['statement_en']}" for f in findings if f) or "(none)"
        qs = "\n".join(f"- {q['id']}: {q.get('text_en') or q['text_orig']}" for q in job["spec"]["target_questions"]) or "(none)"
        obj = self._ask(job["id"], task["id"], StepKind.EVALUATE, f"self-evaluate task {task['id']}",
                        "check goal, find gaps, derive logical follow-ups backed by findings", "agent.evaluate",
                        title=task["title"], goal=task["goal"],
                        task_result=sanitize_untrusted(f"Summary: {summary or '(none)'}\nFindings:\n{tf}", "task-result",
                                                       max_chars=4000).text,
                        questions=qs, known=known, pending="; ".join(pending_titles[:30]) or "(none)")
        out = {"goal_reached": None, "assessment": "", "gaps": [], "followups": []}
        if not obj:
            return out
        out["goal_reached"] = bool(obj.get("goal_reached")) if "goal_reached" in obj else None
        out["assessment"] = _clip(obj.get("assessment"), 800)
        out["gaps"] = [_clip(g, 300) for g in (obj.get("gaps") or [])[:6]]
        valid_ids = {f["id"] for f in self.store.list_findings(job["id"])}
        for f in (obj.get("followups") or [])[:MAX_FOLLOWUPS]:
            title, goal = _clip(f.get("title"), 120), _clip(f.get("goal"), 500)
            rel = _clip(f.get("related_finding"), 20)
            reason = _clip(f.get("reason"), 400)
            # A follow-up must be anchored: an existing finding or an explicitly named gap (chain.md section 2).
            anchored = (rel in valid_ids) or bool(out["gaps"] and reason)
            if title and goal and anchored:
                out["followups"].append({"title": title, "goal": goal,
                                         "reason": (f"[{rel}] " if rel in valid_ids else "[gap] ") + reason})
        return out

    # ---- prioritisation -------------------------------------------------------------------
    def prioritize(self, job: dict, pending: list[dict], known: str, budget: str) -> dict:
        qs = "\n".join(f"- {q['id']}: {q.get('text_en') or q['text_orig']}" for q in job["spec"]["target_questions"]) or "(none)"
        plist = "\n".join(f"- {t['id']} prio={t['priority']} [{t['origin']}] {t['title']}: {t['goal'][:160]}"
                          for t in pending)
        obj = self._ask(job["id"], None, StepKind.PRIORITIZE, "re-order queue by information gain",
                        "react to current knowledge", "agent.prioritize", think=False,
                        pending=plist, questions=qs, known=known, budget=budget)
        out = {"changes": [], "new_tasks": []}
        if not obj:
            return out
        ids = {t["id"]: t for t in pending}
        for c in (obj.get("changes") or [])[:40]:
            tid = _clip(c.get("task_id"), 20)
            try:
                prio = int(c.get("priority"))
            except (TypeError, ValueError):
                continue
            if tid in ids and PRIO_MIN <= prio <= PRIO_MAX:
                # Question tasks stay in the late band unless the model lowers within it (never above 800 floor rule).
                if (ids[tid]["kind"] == "question" or ids[tid]["params"].get("synthesis")) and prio < 800:
                    prio = 800
                out["changes"].append({"task_id": tid, "priority": prio, "reason": _clip(c.get("reason"), 300)})
        for n in (obj.get("new_tasks") or [])[:MAX_NEW_FROM_PRIORITIZER]:
            title, goal = _clip(n.get("title"), 120), _clip(n.get("goal"), 500)
            try:
                prio = min(max(int(n.get("priority", 500)), PRIO_MIN), 790)
            except (TypeError, ValueError):
                prio = 500
            if title and goal:
                out["new_tasks"].append({"title": title, "goal": goal, "priority": prio,
                                         "reason": _clip(n.get("reason"), 300)})
        return out

    # ---- decomposition --------------------------------------------------------------------
    def split(self, job: dict, task: dict, known: str) -> list[dict]:
        obj = self._ask(job["id"], task["id"], StepKind.SYSTEM, f"split task {task['id']}",
                        "task too large for one loop", "agent.split", goal=task["goal"],
                        description=job["spec"].get("description_en") or job["spec"].get("description", ""),
                        known=known)
        subs = []
        for s in ((obj or {}).get("subtasks") or [])[:6]:
            title, goal = _clip(s.get("title"), 120), _clip(s.get("goal"), 500)
            if title and goal:
                subs.append({"title": title, "goal": goal, "reason": _clip(s.get("reason"), 300)})
        return subs
