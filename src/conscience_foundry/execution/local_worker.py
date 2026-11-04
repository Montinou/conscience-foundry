"""Fixed local worker bootstrap. Durable authority reconstruction is added by T5."""

from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast

import psutil

from conscience_foundry.contracts.common import ContractError, Digest, Instant
from conscience_foundry.contracts.execution import ExecutionPlan, StageAttempt
from conscience_foundry.execution.evidence import encoded
from conscience_foundry.execution.local_executor import _exclusive, _grant, _read, local_staged_refs
from conscience_foundry.execution.worker import run_worker
from conscience_foundry.storage.local import ObjectStore
from conscience_foundry.storage.local_attempt import LocalAttemptStore

if TYPE_CHECKING:
    from conscience_foundry.cli.local_authority import LocalWorkerBootstrap
    from conscience_foundry.execution.local_allocation import LocalAllocator


def reconstruct_authority(
    path: Path, digest: Digest, clock: Callable[[], Instant]
) -> tuple[LocalAllocator, LocalWorkerBootstrap]:
    from conscience_foundry.cli.local_authority import LocalWorkerBootstrap, bootstrap_policy_reader
    from conscience_foundry.execution.local_allocation import LocalAllocator
    from conscience_foundry.execution.worker import _bootstrap
    from conscience_foundry.storage.local import ObjectStore

    raw, _ = LocalAllocator._bootstrap_file(path)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ContractError("hash_mismatch")
    bootstrap = LocalWorkerBootstrap.from_wire(raw, _bootstrap(len(raw)))
    for directory, device, inode in (
        (bootstrap.allocator_root, bootstrap.allocator_device, bootstrap.allocator_inode),
        (bootstrap.output_root, bootstrap.output_device, bootstrap.output_inode),
        (bootstrap.operator_store_root, bootstrap.operator_device, bootstrap.operator_inode),
    ):
        try:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                held = os.fstat(fd)
                current = os.stat(directory, follow_symlinks=False)
                if (str(held.st_dev), str(held.st_ino)) != (device, inode) or (
                    held.st_dev,
                    held.st_ino,
                ) != (current.st_dev, current.st_ino):
                    raise ContractError("forbidden")
            finally:
                os.close(fd)
        except OSError:
            raise ContractError("forbidden") from None
    # This child never receives an operator-store capability; the allocator only
    # uses its store for parent-side import, which is unavailable in this process.
    allocator = LocalAllocator(
        Path(bootstrap.allocator_root),
        bootstrap.allocation_policy(),
        cast(ObjectStore, object()),
        clock,
        operator_store_id=bootstrap.operator_store_id,
        operator_store_root=Path(bootstrap.operator_store_root),
        policy_reader=bootstrap_policy_reader(bootstrap, clock),
    )
    if allocator.verify_worker_bootstrap(path, digest) != raw:
        raise ContractError("forbidden")
    return allocator, bootstrap


def main() -> int:
    """Handshake only for a pinned private job; refuse before any input access."""
    try:
        if len(sys.argv) not in (2, 4):
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
        if len(sys.argv) == 2:
            return 3
        from conscience_foundry.cli.config import now

        authority, bootstrap = reconstruct_authority(Path(sys.argv[2]), sys.argv[3], now)
        if bootstrap.output_root != job["store_root"] or bootstrap.project_id != plan.project_id:
            return 2

        class Clock:
            def now(self) -> Instant:
                return now()

        store = LocalAttemptStore(
            Path(bootstrap.output_root),
            plan.project_id,
            attempt.attempt_id,
            cast("ObjectStore", object()),
            local_staged_refs(plan),
            grant,
            Clock(),
            authority,
        )
        result = run_worker(
            encoded(plan),
            encoded(attempt),
            grant,
            store,
            Clock(),
            lease=store,
            nonce=grant.nonce,
            local_authority=authority,
            expected_runtime_digest=job["runtime_digest"],
        )
        from conscience_foundry.contracts.common import Ref

        return 0 if type(result) is Ref else 3
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
