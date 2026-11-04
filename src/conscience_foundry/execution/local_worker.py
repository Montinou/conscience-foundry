"""Fixed local worker bootstrap. Durable authority reconstruction is added by T5."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import psutil

from conscience_foundry.contracts.execution import ExecutionPlan, StageAttempt
from conscience_foundry.execution.local_executor import _exclusive, _grant, _read, local_staged_refs


def main() -> int:
    """Handshake only for a pinned private job; refuse before any input access."""
    try:
        if len(sys.argv) != 2:
            return 2
        job_path = Path(sys.argv[1])
        if job_path.name != "job.json" or not job_path.is_absolute():
            return 2
        job = _read(job_path.parent, job_path.name)
        if set(job) != {
            "project_id",
            "attempt_id",
            "nonce",
            "plan_digest",
            "config_digest",
            "runtime_digest",
            "store_root",
            "grant",
            "staged_refs",
            "plan",
            "attempt",
            "journal_root",
        }:
            return 2
        intent = _read(job_path.parent, "intent.json")
        if {k: v for k, v in job.items() if k != "journal_root"} != intent:
            return 2
        plan = ExecutionPlan.model_validate(job["plan"])
        attempt = StageAttempt.model_validate(job["attempt"])
        grant = _grant(job["grant"])
        expected = hashlib.sha256(
            plan.model_dump_json(by_alias=True, exclude_none=True).encode()
        ).hexdigest()
        if (
            job_path.parent != Path(job["journal_root"]) / attempt.attempt_id
            or job["project_id"] != plan.project_id
            or job["attempt_id"] != attempt.attempt_id
            or job["plan_digest"] != expected
            or grant.plan_digest != expected
            or grant.project_id != plan.project_id
            or grant.run_id != plan.run_id
            or grant.attempt_id != attempt.attempt_id
            or attempt.plan_id != plan.plan_id
            or attempt.operation_key != plan.operation_key
            or job["config_digest"] != plan.execution_config_ref.digest
            or job["staged_refs"]
            != [
                r.model_dump(mode="json", by_alias=True, exclude_none=True)
                for r in local_staged_refs(plan)
            ]
            or type(job["nonce"]) is not str
            or not job["nonce"]
            or type(job["runtime_digest"]) is not str
            or type(job["store_root"]) is not str
        ):
            return 2
        pid = os.getpid()
        _exclusive(
            job_path.parent,
            "handshake.json",
            {"pid": pid, "create_time": psutil.Process(pid).create_time(), "nonce": job["nonce"]},
        )
    except Exception:
        return 2
    # No allocator is reconstructible yet. T5 supplies a trusted journal/policy binding.
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
