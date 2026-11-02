"""Job engine: triage -> plan -> queue loop -> evaluate/prioritise -> answers -> finalise.

One job at a time (the Worker calls run_job sequentially). Everything the engine decides is stored with
its reason, so the dashboard and the report can show what was done, why and how long it took.
"""
from __future__ import annotations

import json
import re
import threading
import time
import traceback

from sw_analyst.common.models import JobSpec, StepKind
from sw_analyst.common.store import Store
from sw_analyst.common.util import utcnow
from sw_analyst.gateway.base import ToolGateway
from sw_analyst.guard import scan
from sw_analyst.llm.base import LLMClient
from sw_analyst.orchestrator.agents import HelperAgents
from sw_analyst.orchestrator.recipes import load_recipe, recipe_id_for
from sw_analyst.orchestrator.runner import TaskOutcome, TaskRunner, check_answer_grounding
from sw_analyst.prompts.registry import SYNTHESIS_GOAL, SYNTHESIS_GUIDE

MAX_ATTEMPTS = 2
MAX_DEPTH = 3
MAX_ARTIFACT_TASKS = 6
MAX_LLM_ERRORS = 3
MAX_FOLLOWUPS_JOB = 8         # model-derived tasks per job; without a cap "verify it again" eats the whole budget
MAX_EVALUATED_DEPTH = 1       # follow-ups of follow-ups are not evaluated again
MAX_OPEN_POINTS_JOB = 12
BUDGET_RESERVE_FROM = 0.75    # from here on the rest of the budget belongs to target questions, then synthesis
# Derived files of these types get their own task. Text and data stay with the task that decoded them.
RECURSE_TYPES = {"pe", "elf", "apk", "jar", "zip", "dex", "pdf", "macho", "ole2",
                 "powershell", "vbscript", "javascript", "python", "bash", "batch", "html"}
_NORM = re.compile(r"\s+")


def _norm_title(t: str) -> str:
    return _NORM.sub(" ", t.lower()).strip()


class JobEngine:
    def __init__(self, store: Store, llm: LLMClient, gateway: ToolGateway, translator=None,
                 use_prioritizer: bool = True, host_guard=None):
        self.store, self.llm, self.gateway, self.translator = store, llm, gateway, translator
        self.runner = TaskRunner(store, llm, gateway)
        self.agents = HelperAgents(store, llm)
        self.use_prioritizer = use_prioritizer
        self.host_guard = host_guard

    # ---- public --------------------------------------------------------------------------------
    def _minutes(self, spec: dict) -> int:
        """The time budget for this engine: a slow engine gets the same work done, not a cut-off job (ADR-0012)."""
        return spec["budget_max_minutes"] * getattr(self.llm, "budget_factor", 1)

    def run_job(self, job_id: str) -> str:
        t_job = time.monotonic()
        job = self.store.update_job(job_id, status="running", started_at=utcnow())
        self.store.log(job_id, "job started", sample_sha256=job["sample_sha256"])
        if hasattr(self.llm, "should_cancel"):   # a reply can take hours: the client looks at this while it waits
            worker = threading.get_ident()       # a translation for the dashboard shares the client and is not this job's work
            self.llm.should_cancel = lambda: (threading.get_ident() == worker
                                              and bool((self.store.get_job(job_id) or {}).get("cancel_requested")))
        try:
            self._translate_inputs(job_id)
            self._triage(job_id)
            self._plan(job_id)
            status = self._loop(job_id, t_job)
        except Exception as e:  # noqa: BLE001 - a job must end in a stored state, never crash the worker
            self.store.log(job_id, f"job crashed: {e}", level="error", trace=traceback.format_exc()[-1500:])
            status = "failed"
        finally:
            if hasattr(self.llm, "should_cancel"):
                self.llm.should_cancel = None    # the report and later translations of a cancelled job must still run
        return self._finalize(job_id, status, t_job)

    # ---- translation of inputs ----------------------------------------------------------------------
    def _tr(self, job_id: str, text: str, what: str, direction: str = "en") -> str:
        if not self.translator or not text.strip():
            return text
        sid = self.store.begin_step(job_id, "", StepKind.TRANSLATE.value, what,
                                    how="translation pipeline with protected tokens and glossary",
                                    why="AI works in English" if direction == "en" else "interface and report are German",
                                    input_preview=text)
        t0 = time.monotonic()
        res = self.translator.to_en(text) if direction == "en" else self.translator.to_de(text)
        self.store.finish_step(sid, status="ok" if res.ok else "error", duration_ms=int((time.monotonic() - t0) * 1000),
                               output_preview=res.text)
        return res.text

    def _translate_inputs(self, job_id: str) -> None:
        job = self.store.get_job(job_id)
        spec = JobSpec.model_validate(job["spec"])
        spec.title_en = self._tr(job_id, spec.title, "translate title to English")
        spec.description_en = self._tr(job_id, spec.description, "translate description to English")
        spec.context_info_en = self._tr(job_id, spec.context_info, "translate further information to English")
        spec.focus_en = self._tr(job_id, spec.focus, "translate focus to English")
        for q in spec.target_questions:
            q.text_en = self._tr(job_id, q.text_orig, f"translate question {q.id} to English")
        self.store.update_spec(job_id, spec)

    # ---- triage (deterministic, no AI) -------------------------------------------------------------
    def _triage(self, job_id: str) -> None:
        group = self.store.add_task(job_id, title="Triage", goal="Identify the sample and record hashes", kind="group",
                                    origin="triage", priority=1, reason="every job starts with deterministic triage")
        detected = "unknown"
        for tool in ("sample_info", "hash_file", "identify_type"):
            r = self._triage_tool(job_id, group["id"], tool, {"path": "sample"} if tool == "hash_file" else {},
                                  f"Triage: {tool}", f"Run {tool} on the sample")
            if tool == "identify_type" and r.ok:
                detected = str(r.meta.get("type") or "unknown").lower()
        recipe = recipe_id_for(detected)
        self.store.update_job(job_id, detected_type=detected, recipe=recipe)
        self.store.update_task(group["id"], status="done", finished_at=utcnow())

    def _triage_tool(self, job_id: str, parent_id: str, tool: str, args: dict, title: str, goal: str):
        t = self.store.add_task(job_id, title=title, goal=goal, kind="triage", origin="triage", priority=1,
                                parent_id=parent_id, reason="deterministic first look, no model involved")
        self.store.update_task(t["id"], status="running", started_at=utcnow(), attempts=1)
        sid = self.store.begin_step(job_id, t["id"], StepKind.TOOL.value, f"tool {tool}", how=str(args or "{}"),
                                    why="triage", tool=tool)
        t0 = time.monotonic()
        r = self.gateway.call(job_id, tool, args)
        ms = int((time.monotonic() - t0) * 1000)
        ev = self.store.add_evidence(job_id, t["id"], tool, r.tool_version, args,
                                     r.text if r.ok else f"[tool error] {r.error}", source_ref=r.meta)
        self.store.finish_step(sid, status="ok" if r.ok else "error", duration_ms=ms, output_preview=ev["text"],
                               evidence_id=ev["id"])
        self.store.update_task(t["id"], status="done" if r.ok else "failed", finished_at=utcnow(), duration_ms=ms,
                               summary_en=(ev["text"].splitlines() or [""])[0][:200])
        return r

    def _triage_artifacts(self, job_id: str, parent: dict) -> None:
        """Every new derived file gets hashes and a type (no model). Code and containers get their own task."""
        job = self.store.get_job(job_id)
        for f in self.gateway.list_files(job_id):
            path = f["path"]
            title = f"Triage artifact: {path}"
            if f["kind"] != "derived" or self.store.has_similar_task(job_id, _norm_title(title)):
                continue
            r = self._triage_tool(job_id, parent["id"], "identify_type", {"path": path}, title,
                                  f"Identify {path}, derived during {parent['id']}")
            self._triage_tool(job_id, parent["id"], "hash_file", {"path": path}, f"Hash artifact: {path}", f"Hash {path}")
            kind = str(r.meta.get("type") or "unknown").lower() if r.ok else "unknown"
            self.store.log(job_id, f"artifact {path}: type {kind}", sha256=f["sha256"], parent=parent["id"])
            recipe_id = recipe_id_for(kind)
            depth = int(parent["params"].get("depth", 0)) + 1
            # A script inside a script is what the script recipe handles anyway ("final readable layer").
            if kind not in RECURSE_TYPES or depth > MAX_DEPTH or (recipe_id == "script" and job["recipe"] == "script"):
                continue
            n = sum(1 for t in self.store.list_tasks(job_id) if t["origin"] == "artifact")
            if n >= MAX_ARTIFACT_TASKS or self._task_budget_full(job_id):
                self.store.log(job_id, f"artifact {path} not analysed: limit reached", level="warn")
                continue
            steps = self._usable_steps(load_recipe(recipe_id))
            self.store.add_task(
                job_id, title=f"Analyse artifact {path} ({kind})",
                goal=f"Analyse {path} as a new object of type {kind} (sha256 {f['sha256']}). Keep its findings apart "
                     f"from the parent file. Cover: " + "; ".join(st["title"] for st in steps) + ".",
                kind="analyze", origin="artifact", priority=min(max(parent["priority"] - 1, 2), 790),
                parent_id=parent["id"], reason=f"derived file of type {kind} found after task {parent['id']}",
                params={"path": path, "depth": depth,
                        "guide": " ".join(st.get("guide", "") for st in steps)[:1500],
                        "tools_hint": sorted({h for st in steps for h in st.get("tools_hint", [])})})

    # ---- planning ------------------------------------------------------------------------------------------
    def _usable_steps(self, recipe: dict) -> list[dict]:
        """Steps whose required tools exist. Container tools are absent when Docker is stopped or an image is not built."""
        tools = {t.name for t in self.gateway.list_tools()}
        return [st for st in recipe["steps"] if set(st.get("requires_tools", [])) <= tools]

    def _plan(self, job_id: str) -> None:
        job = self.store.get_job(job_id)
        recipe = load_recipe(job["recipe"])
        grp = self.store.add_task(job_id, title=f"Recipe: {recipe['id']}", goal=recipe.get("description", ""),
                                  kind="group", origin="recipe", priority=100,
                                  reason=f"sample type '{job['detected_type']}' selects recipe '{recipe['id']}'")
        usable = self._usable_steps(recipe)
        for st in recipe["steps"]:
            if st not in usable:
                self.store.log(job_id, f"recipe step '{st['id']}' skipped: tools not available "
                                       f"({', '.join(st.get('requires_tools', []))})", level="warn")
        for st in usable:
            self.store.add_task(job_id, title=st["title"], goal=st["goal"], kind="analyze", origin="recipe",
                                priority=int(st.get("priority", 200)), parent_id=grp["id"],
                                reason=f"required step '{st['id']}' of recipe '{recipe['id']}'",
                                params={"tools_hint": st.get("tools_hint", []), "guide": st.get("guide", ""), "depth": 0,
                                        "done_when": st.get("done_when", "")})
        standard = "\n".join(f"- {q}" for q in recipe.get("required_questions", [])) or "(none)"
        self.store.add_task(job_id, title="Synthesis: findings, contradictions, standard questions",
                            goal=SYNTHESIS_GOAL.format(questions=standard), kind="analyze", origin="recipe", priority=850,
                            parent_id=grp["id"], reason=f"synthesis step of recipe '{recipe['id']}'",
                            params={"guide": SYNTHESIS_GUIDE, "synthesis": True, "depth": MAX_DEPTH})
        spec = JobSpec.model_validate(job["spec"])
        qgrp = self.store.add_task(job_id, title="Target questions", goal="Answer the questions given with the job",
                                   kind="group", origin="question", priority=900,
                                   reason="questions are answered last, from confirmed findings")
        for i, q in enumerate(spec.target_questions):
            self.store.add_task(job_id, title=f"Answer {q.id}: {(q.text_en or q.text_orig)[:80]}",
                                goal=q.text_en or q.text_orig, kind="question", origin="question",
                                priority=900 + i, parent_id=qgrp["id"], params={"question_id": q.id},
                                reason="target question from the job definition")
        self.store.log(job_id, "plan created", recipe=recipe["id"], tasks=len(self.store.list_tasks(job_id)))

    # ---- main loop ------------------------------------------------------------------------------------------
    def _budget_left(self, job_id: str, t_job: float) -> str | None:
        spec = self.store.get_job(job_id)["spec"]
        if self._counted_tasks(job_id) > spec["budget_max_tasks"] + 3:
            return "task budget exhausted"
        if self.store.count_steps(job_id) >= spec["budget_max_steps"]:
            return "step budget exhausted"
        if (time.monotonic() - t_job) / 60 >= self._minutes(spec):
            return "time budget exhausted"
        return None

    def _counted_tasks(self, job_id: str) -> int:
        return sum(1 for t in self.store.list_tasks(job_id) if t["kind"] not in ("group", "triage"))

    def _followups_used(self, job_id: str) -> int:
        return sum(1 for t in self.store.list_tasks(job_id) if t["origin"] in ("split", "evaluator", "prioritizer"))

    def _task_budget_full(self, job_id: str) -> bool:
        return self._counted_tasks(job_id) >= self.store.get_job(job_id)["spec"]["budget_max_tasks"]

    def _budget_used(self, job_id: str, t_job: float) -> float:
        spec = self.store.get_job(job_id)["spec"]
        return max(self.store.count_steps(job_id) / spec["budget_max_steps"],
                   (time.monotonic() - t_job) / 60 / self._minutes(spec))

    def _keep_reserve(self, job_id: str, t_job: float) -> None:
        """Target questions must get an answer or a reason, so optional work gives way before the budget ends."""
        if self._budget_used(job_id, t_job) < BUDGET_RESERVE_FROM:
            return
        pending = [t for t in self.store.queue(job_id) if t["status"] == "pending"]
        questions_wait = any(t["kind"] == "question" for t in pending)
        for t in pending:
            # Target questions come first, synthesis only runs from the reserve when none are waiting.
            if t["kind"] != "question" and (questions_wait or not t["params"].get("synthesis")):
                self.store.update_task(t["id"], status="skipped", finished_at=utcnow(),
                                       summary_en="skipped: remaining budget is reserved for target questions")
                self.store.log(job_id, f"task {t['id']} skipped to keep the budget reserve", level="warn")

    def _host_blocked(self, job_id: str) -> str | None:
        """Pause while the host is in the danger zone. Returns a reason when waiting did not help."""
        if not self.host_guard:
            return None
        waited = 0.0
        while problems := self.host_guard.problems():
            why = "; ".join(problems)
            if waited >= self.host_guard.limits.max_pause_s:
                return why
            if self.store.get_job(job_id)["cancel_requested"]:
                return None
            self.store.log(job_id, f"host protection: job paused ({why})", level="warn")
            time.sleep(self.host_guard.limits.pause_s)
            waited += self.host_guard.limits.pause_s
        return None

    def _loop(self, job_id: str, t_job: float) -> str:
        known_ids = {t["id"] for t in self.store.list_tasks(job_id)}
        offload_checked = False
        llm_errors = 0
        goal_planned = False
        while True:
            if self.store.get_job(job_id)["cancel_requested"]:
                return "cancelled"
            blocked = self._host_blocked(job_id)
            if blocked:
                self.store.log(job_id, f"stopping: host protection: {blocked}", level="warn")
                return "partial"
            self._keep_reserve(job_id, t_job)
            why_stop = self._budget_left(job_id, t_job)
            task = self.store.next_pending_task(job_id)
            if why_stop and task:
                self.store.log(job_id, f"stopping: {why_stop}", level="warn")
                return "partial"
            if not task:
                if not why_stop and self._reopen_questions(job_id):
                    continue
                return "done"
            # The recipe is done: plan what the job goal still needs before the synthesis or the first question.
            if not goal_planned and (task["params"].get("synthesis") or task["kind"] == "question"):
                goal_planned = True
                if self._plan_from_goal(job_id, task, t_job):
                    continue
            self._run_task(job_id, task)
            # A dead model server fails every task the same way; stop instead of marking the whole queue as failed.
            if (self.store.get_task(task["id"])["summary_en"] or "").find("LLM error") >= 0:
                llm_errors += 1
                if llm_errors >= MAX_LLM_ERRORS:
                    self.store.log(job_id, "stopping: model not reachable", level="error")
                    return "partial"
            else:
                llm_errors = 0
            self._triage_artifacts(job_id, task)
            self._refresh_groups(job_id)
            if self.host_guard and not offload_checked:   # the model is loaded only after the first task
                offload_checked = True
                warning = self.host_guard.offload_warning()
                if warning:
                    self.store.log(job_id, f"host protection: {warning}", level="warn")
            ids_now = {t["id"] for t in self.store.list_tasks(job_id)}
            # The order only needs new thought when the queue changed; this saves a model call per task.
            if self.use_prioritizer and ids_now - known_ids:
                self._prioritize(job_id, t_job)
                ids_now = {t["id"] for t in self.store.list_tasks(job_id)}
            known_ids = ids_now

    def _plan_from_goal(self, job_id: str, task: dict, t_job: float) -> bool:
        if self._budget_used(job_id, t_job) >= BUDGET_RESERVE_FROM:
            return False
        tasks = self.store.list_tasks(job_id)
        subs = self.agents.split(self.store.get_job(job_id), task["id"], self.runner.known_findings_text(job_id),
                                 self.runner.open_points_text(job_id), [t["title"] for t in tasks if t["kind"] != "group"])
        self._add_subtasks(job_id, task, subs, "planner", 0)
        return len(self.store.list_tasks(job_id)) > len(tasks)

    def _reopen_questions(self, job_id: str) -> bool:
        """A question left open gets one more try once later work confirmed something new."""
        confirmed = len(self.store.list_findings(job_id, "confirmed"))
        reopened = False
        for t in self.store.list_tasks(job_id):
            p = t["params"]
            if (t["kind"] == "question" and t["status"] == "done" and "confirmed_at_answer" in p and not p.get("reopened")
                    and confirmed > p["confirmed_at_answer"]
                    and self.store.get_answer(job_id, p["question_id"])["status"] == "unresolved"):
                self.store.update_task(t["id"], status="pending", params_json=json.dumps({**p, "reopened": True}))
                self.store.log(job_id, f"question task {t['id']} reopened: new confirmed findings", task=t["id"])
                reopened = True
        return reopened

    def _run_task(self, job_id: str, task: dict) -> None:
        job = self.store.get_job(job_id)
        t0 = time.monotonic()
        task = self.store.update_task(task["id"], status="running", started_at=utcnow(),
                                      attempts=task["attempts"] + 1)
        self.store.log(job_id, f"task start {task['id']}: {task['title']}", task=task["id"], origin=task["origin"])
        outcome = self.runner.run(job, task)
        ms = int((time.monotonic() - t0) * 1000)
        if outcome.status == "blocked":
            self.store.update_task(task["id"], status="blocked", finished_at=utcnow(), duration_ms=ms,
                                   summary_en=f"blocked by prompt guard: {outcome.error}")
            self.store.add_finding(job_id, task["id"],
                                   f"GUARD: the analysed data contained instructions aimed at the AI; processing of task "
                                   f"{task['id']} was stopped by the prompt guard ({outcome.error}).",
                                   "open", [], [], "")
            return
        if outcome.status == "failed":
            if task["attempts"] < MAX_ATTEMPTS:
                self.store.update_task(task["id"], status="pending", priority=task["priority"] + 5, duration_ms=ms,
                                       summary_en=f"attempt {task['attempts']} failed: {outcome.error}")
            else:
                self.store.update_task(task["id"], status="failed", finished_at=utcnow(), duration_ms=ms,
                                       summary_en=f"failed: {outcome.error}")
            return
        summary_de = self._tr(job_id, outcome.summary, "translate task summary to German", "de") if outcome.summary else ""
        self.store.update_task(task["id"], status="done", finished_at=utcnow(), duration_ms=ms,
                               summary_en=outcome.summary, summary_de=summary_de)
        self._translate_new(job_id, task["id"])
        depth = int(task["params"].get("depth", 0))
        self._add_subtasks(job_id, task, outcome.subtasks, "split", depth)
        if task["kind"] == "question":
            self._apply_answer(job_id, task, outcome)
        synthesis = task["params"].get("synthesis")
        # A reopened question has no later try, so follow-ups could not reach its answer.
        if task["params"].get("reopened") or (depth > MAX_EVALUATED_DEPTH and not synthesis):
            return
        ev = self.agents.evaluate(job, task, outcome.summary, outcome.finding_ids,
                                  [t["title"] for t in self.store.queue(job_id)], self.runner.known_findings_text(job_id),
                                  self.runner.open_points_text(job_id))
        if ev["assessment"]:
            self.store.log(job_id, f"evaluation {task['id']}: {ev['assessment']}", gaps=ev["gaps"],
                           goal_reached=ev["goal_reached"])
        self._record_evaluation(job_id, task["id"], ev)
        # The synthesis gets one gap round; its follow-ups are not evaluated again.
        self._add_subtasks(job_id, task, ev["followups"], "evaluator", MAX_EVALUATED_DEPTH if synthesis else depth)

    def _record_evaluation(self, job_id: str, task_id: str, ev: dict) -> None:
        if ev["goal_reached"] is None and not ev["assessment"] and not ev["gaps"]:
            return
        t = self.store.get_task(task_id)
        self.store.update_task(task_id, params_json=json.dumps({**t["params"], "goal_reached": ev["goal_reached"]}))
        points = ev["gaps"] or ([f"Goal of task {task_id} not reached: {ev['assessment']}"]
                                if ev["goal_reached"] is False and ev["assessment"] else [])
        findings = self.store.list_findings(job_id)
        known = {f["statement_en"] for f in findings}
        open_count = sum(1 for f in findings if f["status"] == "open")
        for point in points:
            if point in known or self._injected(job_id, task_id, point):
                continue
            if open_count >= MAX_OPEN_POINTS_JOB:
                self.store.log(job_id, f"open point limit reached, not recorded: {point}", level="warn")
                continue
            self.store.add_finding(job_id, task_id, point, "open", [], [], "")
            open_count += 1
            known.add(point)
        self._translate_new(job_id, task_id)

    def _add_subtasks(self, job_id: str, parent: dict, subs: list[dict], origin: str, depth: int) -> None:
        if depth >= MAX_DEPTH:
            return
        for s in subs:
            title = s["title"]
            if self._injected(job_id, parent["id"], title, s["goal"], s.get("reason") or "", s.get("done_when") or ""):
                continue
            if self.store.has_similar_task(job_id, _norm_title(title)):
                self.store.log(job_id, f"duplicate task ignored: {title}", level="debug")
                continue
            if self._task_budget_full(job_id) or (origin != "planner" and self._followups_used(job_id) >= MAX_FOLLOWUPS_JOB):
                self.store.log(job_id, f"follow-up limit reached, not added: {title}", level="warn")
                continue
            # Behind all recipe steps (100-199): "parent - 1" let follow-ups starve the recipe and the target questions.
            self.store.add_task(job_id, title=title, goal=s["goal"], kind="analyze", origin=origin,
                                priority=min(max(parent["priority"] + 1, 200), 790), parent_id=parent["id"],
                                reason=s.get("reason") or f"derived from {parent['id']}",
                                params={"depth": depth + 1, "done_when": s.get("done_when") or ""})

    def _injected(self, job_id: str, task_id: str | None, *texts: str) -> bool:
        """Goals written by the model reach later prompts as instructions. Sample text must not travel that way."""
        hits = [d for d in scan("\n".join(texts)) if d.severity in ("medium", "high")]
        for d in hits:
            self.store.add_guard_event(job_id, task_id, "plan", d.rule, d.severity, "dropped", d.snippet)
        return bool(hits)

    def _prioritize(self, job_id: str, t_job: float) -> None:
        pending = [t for t in self.store.queue(job_id) if t["status"] == "pending"]
        if len(pending) < 2:
            return
        job = self.store.get_job(job_id)
        spec = job["spec"]
        budget = f"{spec['budget_max_tasks']} tasks, {spec['budget_max_steps']} steps, {self._minutes(spec)} min"
        res = self.agents.prioritize(job, pending, self.runner.known_findings_text(job_id), budget)
        for c in res["changes"]:
            self.store.update_task(c["task_id"], priority=c["priority"])  # task reason keeps its origin
            self.store.log(job_id, f"priority of {c['task_id']} set to {c['priority']}", reason=c["reason"])
        for n in res["new_tasks"]:
            if (not self.store.has_similar_task(job_id, _norm_title(n["title"])) and not self._task_budget_full(job_id)
                    and self._followups_used(job_id) < MAX_FOLLOWUPS_JOB
                    and not self._injected(job_id, None, n["title"], n["goal"], n["reason"], n["done_when"])):
                self.store.add_task(job_id, title=n["title"], goal=n["goal"], kind="analyze", origin="prioritizer",
                                    priority=n["priority"], reason=n["reason"] or "suggested by prioritizer",
                                    params={"depth": 1, "done_when": n["done_when"]})

    # ---- answers ---------------------------------------------------------------------------------------------
    def _apply_answer(self, job_id: str, task: dict, outcome: TaskOutcome) -> None:
        qid = task["params"].get("question_id")
        ans = self.store.get_answer(job_id, qid)
        if not ans:
            return
        text = outcome.answer_text
        reason = ""
        if not text or text.upper().startswith("UNRESOLVED"):
            reason = text or "no answer produced"
        elif not outcome.confirmed_ids:
            reason = "the answer is not backed by any confirmed finding"
        else:
            ok, why = check_answer_grounding(self.store, job_id, text)
            if not ok:
                reason = why
        status = "answered" if not reason else "unresolved"
        match = None
        exp = ans.get("expected")
        if exp and status == "answered":
            if exp.startswith("re:"):
                match = 1 if re.search(exp[3:], text) else 0
            else:
                match = 1 if exp in text else 0
        elif exp:
            match = 0
        evaluation = (f"Answer rejected: {reason}" if reason else
                      ("Matches the expected value." if match == 1 else
                       ("Does NOT match the expected value." if match == 0 else "No expected value was given.")))
        answer_de = self._tr(job_id, text, f"translate answer {qid} to German", "de") if (text and status == "answered") else ""
        self.store.update_answer(job_id, qid, answer_en=text if status == "answered" else "", answer_de=answer_de,
                                 status=status, finding_ids=outcome.confirmed_ids, evaluation_en=evaluation,
                                 evaluation_de=self._tr(job_id, evaluation, "translate evaluation", "de"), match=match)
        if status == "unresolved":
            fresh = self.store.get_task(task["id"])
            self.store.update_task(task["id"], params_json=json.dumps(
                {**fresh["params"], "confirmed_at_answer": len(self.store.list_findings(job_id, "confirmed"))}))

    # ---- translation of results ----------------------------------------------------------------------------
    def _translate_new(self, job_id: str, task_id: str) -> None:
        if not self.translator:
            return
        for f in self.store.list_findings(job_id):
            if f["task_id"] == task_id and not f["statement_de"]:
                self.store.set_finding_de(f["id"], self._tr(job_id, f["statement_en"],
                                                            f"translate finding {f['id']} to German", "de"))
        for a in self.store.list_annotations(job_id):
            if a["task_id"] == task_id and not a["text_de"]:
                self.store.set_annotation_de(a["id"], self._tr(job_id, a["text_en"], "translate annotation to German", "de"))

    # ---- groups, finalisation ----------------------------------------------------------------------------------
    def _refresh_groups(self, job_id: str) -> None:
        tasks = self.store.list_tasks(job_id)
        for g in [t for t in tasks if t["kind"] == "group"]:
            kids = [t for t in tasks if t["parent_id"] == g["id"]]
            if not kids:
                continue
            states = {k["status"] for k in kids}
            new = "running" if "running" in states else ("pending" if "pending" in states else "done")
            if new != g["status"]:
                self.store.update_task(g["id"], status=new)

    def _finalize(self, job_id: str, status: str, t_job: float) -> str:
        for a in self.store.list_answers(job_id):
            if a["status"] == "pending":
                self.store.update_answer(job_id, a["question_id"], status="unresolved",
                                         evaluation_en="Not answered: the job ended before this question was processed.",
                                         evaluation_de=self._tr(job_id, "Not answered: the job ended before this question was processed.",
                                                                "translate evaluation", "de"))
        answers = self.store.list_answers(job_id)
        work = [t for t in self.store.list_tasks(job_id) if t["kind"] != "group" and t["origin"] != "triage"]
        finished = [t for t in work if t["status"] == "done"]
        evaluated = [t["params"]["goal_reached"] for t in work if t["params"].get("goal_reached") is not None]
        if status in ("done", "partial") and work and not finished:
            status = "failed"              # nothing was analysed, e.g. the model was unreachable
        elif status == "done" and (len(finished) < len(work) or any(a["status"] != "answered" for a in answers)):
            status = "partial"
        prog = self.store.progress(job_id)
        summary = (f"{prog['done']} of {prog['tasks_total']} tasks done, {prog['failed']} failed, "
                   f"{prog['blocked']} blocked; {sum(1 for a in answers if a['status'] == 'answered')} of "
                   f"{len(answers)} questions answered; {len(self.store.list_findings(job_id, 'confirmed'))} confirmed findings. "
                   f"Coverage: {len(finished)} of {len(work)} analysis tasks done, "
                   f"{sum(1 for t in work if t['origin'] == 'artifact' and t['status'] == 'done')} artifacts analysed, "
                   f"{sum(1 for t in work if t['status'] == 'skipped')} skipped for budget. "
                   f"Goals reached by the model's own assessment in {sum(evaluated)} of {len(evaluated)} evaluated tasks.")
        self.store.update_job(job_id, status=status, finished_at=utcnow(),
                              duration_ms=int((time.monotonic() - t_job) * 1000), summary_en=summary,
                              summary_de=self._tr(job_id, summary, "translate job summary", "de"))
        self.store.log(job_id, f"job finished: {status}", summary=summary)
        return status
