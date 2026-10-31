"""Job engine: triage -> plan -> queue loop -> evaluate/prioritise -> answers -> finalise.

One job at a time (the Worker calls run_job sequentially). Everything the engine decides is stored with
its reason, so the dashboard and the report can show what was done, why and how long it took.
"""
from __future__ import annotations

import re
import time
import traceback

from sw_analyst.common.models import JobSpec, StepKind
from sw_analyst.common.store import Store
from sw_analyst.common.util import utcnow
from sw_analyst.gateway.base import ToolGateway
from sw_analyst.llm.base import LLMClient
from sw_analyst.orchestrator.agents import HelperAgents
from sw_analyst.orchestrator.recipes import load_recipe, recipe_id_for
from sw_analyst.orchestrator.runner import TaskOutcome, TaskRunner, check_answer_grounding

MAX_ATTEMPTS = 2
MAX_DEPTH = 3
_NORM = re.compile(r"\s+")


def _norm_title(t: str) -> str:
    return _NORM.sub(" ", t.lower()).strip()


class JobEngine:
    def __init__(self, store: Store, llm: LLMClient, gateway: ToolGateway, translator=None,
                 use_prioritizer: bool = True):
        self.store, self.llm, self.gateway, self.translator = store, llm, gateway, translator
        self.runner = TaskRunner(store, llm, gateway)
        self.agents = HelperAgents(store, llm)
        self.use_prioritizer = use_prioritizer

    # ---- public --------------------------------------------------------------------------------
    def run_job(self, job_id: str) -> str:
        t_job = time.monotonic()
        job = self.store.update_job(job_id, status="running", started_at=utcnow())
        self.store.log(job_id, "job started", sample_sha256=job["sample_sha256"])
        try:
            self._translate_inputs(job_id)
            self._triage(job_id)
            self._plan(job_id)
            status = self._loop(job_id, t_job)
        except Exception as e:  # noqa: BLE001 - a job must end in a stored state, never crash the worker
            self.store.log(job_id, f"job crashed: {e}", level="error", trace=traceback.format_exc()[-1500:])
            status = "failed"
        self._finalize(job_id, status, t_job)
        return status

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
            t = self.store.add_task(job_id, title=f"Triage: {tool}", goal=f"Run {tool} on the sample", kind="triage",
                                    origin="triage", priority=1, parent_id=group["id"],
                                    reason="deterministic first look, no model involved")
            self.store.update_task(t["id"], status="running", started_at=utcnow(), attempts=1)
            sid = self.store.begin_step(job_id, t["id"], StepKind.TOOL.value, f"tool {tool}", how="{}",
                                        why="triage", tool=tool)
            t0 = time.monotonic()
            args = {"path": "sample"} if tool == "hash_file" else {}
            r = self.gateway.call(job_id, tool, args)
            ms = int((time.monotonic() - t0) * 1000)
            ev = self.store.add_evidence(job_id, t["id"], tool, r.tool_version, args,
                                         r.text if r.ok else f"[tool error] {r.error}", source_ref=r.meta)
            self.store.finish_step(sid, status="ok" if r.ok else "error", duration_ms=ms, output_preview=ev["text"],
                                   evidence_id=ev["id"])
            if tool == "identify_type" and r.ok:
                detected = str(r.meta.get("type") or "unknown").lower()
            self.store.update_task(t["id"], status="done" if r.ok else "failed", finished_at=utcnow(), duration_ms=ms,
                                   summary_en=(ev["text"].splitlines() or [""])[0][:200])
        recipe = recipe_id_for(detected)
        self.store.update_job(job_id, detected_type=detected, recipe=recipe)
        self.store.update_task(group["id"], status="done", finished_at=utcnow())

    # ---- planning ------------------------------------------------------------------------------------------
    def _plan(self, job_id: str) -> None:
        job = self.store.get_job(job_id)
        recipe = load_recipe(job["recipe"])
        grp = self.store.add_task(job_id, title=f"Recipe: {recipe['id']}", goal=recipe.get("description", ""),
                                  kind="group", origin="recipe", priority=100,
                                  reason=f"sample type '{job['detected_type']}' selects recipe '{recipe['id']}'")
        for st in recipe["steps"]:
            self.store.add_task(job_id, title=st["title"], goal=st["goal"], kind="analyze", origin="recipe",
                                priority=int(st.get("priority", 200)), parent_id=grp["id"],
                                reason=f"required step '{st['id']}' of recipe '{recipe['id']}'",
                                params={"tools_hint": st.get("tools_hint", []), "depth": 0})
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
        if len([t for t in self.store.list_tasks(job_id) if t["kind"] != "group"]) > spec["budget_max_tasks"] + 3:
            return "task budget exhausted"
        if self.store.count_steps(job_id) >= spec["budget_max_steps"]:
            return "step budget exhausted"
        if (time.monotonic() - t_job) / 60 >= spec["budget_max_minutes"]:
            return "time budget exhausted"
        return None

    def _loop(self, job_id: str, t_job: float) -> str:
        while True:
            if self.store.get_job(job_id)["cancel_requested"]:
                return "cancelled"
            why_stop = self._budget_left(job_id, t_job)
            task = self.store.next_pending_task(job_id)
            if why_stop and task:
                self.store.log(job_id, f"stopping: {why_stop}", level="warn")
                return "partial"
            if not task:
                return "done"
            self._run_task(job_id, task)
            self._refresh_groups(job_id)
            if self.use_prioritizer:
                self._prioritize(job_id, t_job)

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
                                   f"The analysed data contained instructions aimed at the AI; processing of task "
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
        ev = self.agents.evaluate(job, task, outcome.summary, outcome.finding_ids,
                                  [t["title"] for t in self.store.queue(job_id)], self.runner.known_findings_text(job_id))
        if ev["assessment"]:
            self.store.log(job_id, f"evaluation {task['id']}: {ev['assessment']}", gaps=ev["gaps"],
                           goal_reached=ev["goal_reached"])
        self._add_subtasks(job_id, task, ev["followups"], "evaluator", depth)

    def _add_subtasks(self, job_id: str, parent: dict, subs: list[dict], origin: str, depth: int) -> None:
        if depth >= MAX_DEPTH:
            return
        for s in subs:
            title = s["title"]
            if self.store.has_similar_task(job_id, _norm_title(title)):
                self.store.log(job_id, f"duplicate task ignored: {title}", level="debug")
                continue
            self.store.add_task(job_id, title=title, goal=s["goal"], kind="analyze", origin=origin,
                                priority=min(max(parent["priority"] - 1, 2), 790), parent_id=parent["id"],
                                reason=s.get("reason") or f"derived from {parent['id']}",
                                params={"depth": depth + 1})

    def _prioritize(self, job_id: str, t_job: float) -> None:
        pending = [t for t in self.store.queue(job_id) if t["status"] == "pending"]
        if len(pending) < 2:
            return
        job = self.store.get_job(job_id)
        spec = job["spec"]
        budget = f"{spec['budget_max_tasks']} tasks, {spec['budget_max_steps']} steps, {spec['budget_max_minutes']} min"
        res = self.agents.prioritize(job, pending, self.runner.known_findings_text(job_id), budget)
        for c in res["changes"]:
            self.store.update_task(c["task_id"], priority=c["priority"], reason=f"prioritizer: {c['reason']}")
        for n in res["new_tasks"]:
            if not self.store.has_similar_task(job_id, _norm_title(n["title"])):
                self.store.add_task(job_id, title=n["title"], goal=n["goal"], kind="analyze", origin="prioritizer",
                                    priority=n["priority"], reason=n["reason"] or "suggested by prioritizer",
                                    params={"depth": 1})

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

    def _finalize(self, job_id: str, status: str, t_job: float) -> None:
        for a in self.store.list_answers(job_id):
            if a["status"] == "pending":
                self.store.update_answer(job_id, a["question_id"], status="unresolved",
                                         evaluation_en="Not answered: the job ended before this question was processed.",
                                         evaluation_de=self._tr(job_id, "Not answered: the job ended before this question was processed.",
                                                                "translate evaluation", "de"))
        answers = self.store.list_answers(job_id)
        if status == "done" and any(a["status"] != "answered" for a in answers):
            status = "partial"
        prog = self.store.progress(job_id)
        summary = (f"{prog['done']} of {prog['tasks_total']} tasks done, {prog['failed']} failed, "
                   f"{prog['blocked']} blocked; {sum(1 for a in answers if a['status'] == 'answered')} of "
                   f"{len(answers)} questions answered; {len(self.store.list_findings(job_id, 'confirmed'))} confirmed findings.")
        self.store.update_job(job_id, status=status, finished_at=utcnow(),
                              duration_ms=int((time.monotonic() - t_job) * 1000), summary_en=summary,
                              summary_de=self._tr(job_id, summary, "translate job summary", "de"))
        self.store.log(job_id, f"job finished: {status}", summary=summary)
