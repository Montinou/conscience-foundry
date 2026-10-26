"""Stub SDK client and fault doubles exercise the S3 staging boundary offline.

No network, credential or provider payload is used; every bucket, key and token
below is synthetic. Real conditional-create, grant and cost behavior of a
compatible provider remains live preflight evidence, not asserted here.
"""

from __future__ import annotations

import base64
import hashlib
import io
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from conscience_foundry.contracts.common import ArtifactRef, ContractError
from conscience_foundry.contracts.execution import ExecutionPlan, StageAttempt
from conscience_foundry.execution.evidence import encoded
from conscience_foundry.execution.ports import TransportGrants
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import ObjectStore
from conscience_foundry.storage.staging_s3 import (
    CredentialRequest,
    S3StagingStore,
    StagingConfig,
)

PROJECT = "00000000-0000-0000-0000-000000000001"
ACTOR = "00000000-0000-0000-0000-000000000002"
OTHER_PROJECT = "00000000-0000-0000-0000-000000000003"
BUCKET = "synthetic-staging"
CONTEXT = AccessContext(PROJECT, ACTOR, frozenset({"read", "remoteTransfer"}))


class FakeClientError(Exception):
    """Mimics the SDK error shape: a response mapping, never a message with payload."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class FakeBody:
    def __init__(self, data: bytes, fail_after: int | None = None) -> None:
        self._data = io.BytesIO(data)
        self._fail_after = fail_after
        self._served = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._data.read(size)
        self._served += len(chunk)
        if self._fail_after is not None and self._served > self._fail_after:
            # the connection resets while the body is being read: the partial bytes are lost
            raise ConnectionError("synthetic mid-stream reset")
        return chunk

    def close(self) -> None:
        return None


class FakeS3:
    """Conditional-create object store double with scriptable faults; logs ops and keys only."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.calls: list[tuple[str, str]] = []
        self.put_kwargs: list[dict[str, Any]] = []
        self.lose_put_response = False  # store, then raise a timeout
        self.fail_put_before_store: Exception | None = None
        self.corrupt_stored = False
        self.get_faults: list[Exception | int] = []  # per get call: raise, or truncate after n
        self.head_error: Exception | None = None
        self.echo_checksum = False  # head reports ChecksumSHA256 only when ChecksumMode=ENABLED
        self.head_kwargs: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]:
        key = kwargs["Key"]
        self.calls.append(("put", key))
        self.put_kwargs.append({k: v for k, v in kwargs.items() if k != "Body"})
        if self.fail_put_before_store is not None:
            raise self.fail_put_before_store
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise FakeClientError("PreconditionFailed", 412)
        body = kwargs["Body"]
        self.objects[key] = b"X" * len(body) if self.corrupt_stored else bytes(body)
        if self.lose_put_response:
            raise TimeoutError("synthetic lost response")
        return {"ETag": '"synthetic"'}

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]:
        key = kwargs["Key"]
        self.calls.append(("head", key))
        if self.head_error is not None:
            raise self.head_error
        self.head_kwargs.append(dict(kwargs))
        if key not in self.objects:
            raise FakeClientError("NotFound", 404)
        found: dict[str, Any] = {"ContentLength": len(self.objects[key])}
        if self.echo_checksum and kwargs.get("ChecksumMode") == "ENABLED":
            found["ChecksumSHA256"] = base64.b64encode(
                hashlib.sha256(self.objects[key]).digest()
            ).decode("ascii")
        return found

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]:
        key = kwargs["Key"]
        self.calls.append(("get", key))
        fault = self.get_faults.pop(0) if self.get_faults else None
        if isinstance(fault, Exception):
            raise fault
        if key not in self.objects:
            raise FakeClientError("NoSuchKey", 404)
        data = self.objects[key]
        window = kwargs.get("Range")
        total = len(data)
        if window is not None:
            start, end = (int(part) for part in window.removeprefix("bytes=").split("-"))
            data = data[start : end + 1]
            span = {"ContentRange": f"bytes {start}-{start + len(data) - 1}/{total}"}
        else:
            span = {}
        return {"Body": FakeBody(data, fault if isinstance(fault, int) else None)} | span

    def puts(self) -> list[str]:
        return [key for op, key in self.calls if op == "put"]


def allow(_ref: ArtifactRef, _context: AccessContext, _effect: str) -> None:
    return None


def ref_for(data: bytes, project: str = PROJECT) -> ArtifactRef:
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id=project,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="text/plain",
        artifact_schema="kf.raw-original.v1",
        locations=(),
    )


def config(**overrides: Any) -> StagingConfig:
    values: dict[str, Any] = {
        "destination_id": "synthetic.destination",
        "store_id": "synthetic-staging",
        "endpoint_id": "synthetic-endpoint",
        "bucket": BUCKET,
        "prefix": "staging/f1",
        "region": "synthetic-region-1",
        "credential_source": "synthetic-source",
        "max_object_bytes": 4096,
        "transfer_chunk_bytes": 16,
        "max_read_resumes": 2,
        "max_parts": 4,
        "grant_ttl_seconds": 300,
    }
    return StagingConfig(**(values | overrides))


NOW = "2030-01-01T00:00:00.000Z"


def make_store(
    client: FakeS3,
    *,
    reserved: Callable[[ArtifactRef, AccessContext], bool] | None = None,
    issuer: Callable[[CredentialRequest], tuple[bytes, ...]] | None = None,
    **config_overrides: Any,
) -> S3StagingStore:
    return S3StagingStore(
        config(**config_overrides),
        client,
        authorize=allow,
        storage_reserved=reserved or (lambda _ref, _context: True),
        clock=lambda: NOW,
        credential_issuer=issuer,
    )


def test_exclusive_upload_and_unknown_response() -> None:
    data = b"synthetic staged bytes"
    expected = ref_for(data)

    # put_uses_exclusive_condition: conditional create, size and checksum bound to the bytes
    client = FakeS3()
    store: ObjectStore = make_store(client)
    assert store.put_verified(io.BytesIO(data), expected, CONTEXT) == expected
    (kwargs,) = client.put_kwargs
    assert kwargs["IfNoneMatch"] == "*"
    assert kwargs["Bucket"] == BUCKET
    assert kwargs["ContentLength"] == len(data)
    assert kwargs["ChecksumSHA256"] == base64.b64encode(hashlib.sha256(data).digest()).decode()
    assert kwargs["Key"].startswith(f"staging/f1/{PROJECT}/")
    assert expected.digest in kwargs["Key"]
    # an existing identical object is reconciled by hash, never overwritten
    assert store.put_verified(io.BytesIO(data), expected, CONTEXT) == expected
    assert len(client.puts()) == 2
    assert list(client.objects.values()) == [data]

    # lost_put_response_reconciles_hash_not_overwrite: stored but the response was lost
    lost = FakeS3()
    lost.lose_put_response = True
    reconciled = make_store(lost).put_verified(io.BytesIO(data), expected, CONTEXT)
    assert reconciled == expected
    assert len(lost.puts()) == 1  # no second put

    # unknown outcome with nothing visible is not a proven failure and is not retried
    absent = FakeS3()
    absent.fail_put_before_store = TimeoutError("synthetic")
    blocked = make_store(absent)
    with pytest.raises(ContractError) as unknown:
        blocked.put_verified(io.BytesIO(data), expected, CONTEXT)
    assert unknown.value.code == "dispatch_unknown"
    absent.fail_put_before_store = None
    with pytest.raises(ContractError) as refused:
        blocked.put_verified(io.BytesIO(data), expected, CONTEXT)
    assert refused.value.code == "dispatch_unknown"
    assert len(absent.puts()) == 1  # a write retry needs explicit reconciliation first
    assert blocked.reconcile(expected, CONTEXT) == "absent"
    assert blocked.put_verified(io.BytesIO(data), expected, CONTEXT) == expected
    assert len(absent.puts()) == 2

    # a stored object with different content is a hash mismatch, never overwritten
    corrupt = FakeS3()
    corrupt.corrupt_stored = True
    corrupt.lose_put_response = True
    with pytest.raises(ContractError) as mismatch:
        make_store(corrupt).put_verified(io.BytesIO(data), expected, CONTEXT)
    assert mismatch.value.code == "hash_mismatch"
    assert len(corrupt.puts()) == 1


def test_write_time_verification_never_trusts_size_alone() -> None:
    data = b"synthetic staged bytes"
    expected = ref_for(data)

    # same-size corrupt store and no checksum on head: read back and hash, never "verified"
    plain = FakeS3()
    plain.corrupt_stored = True
    with pytest.raises(ContractError) as mismatch:
        make_store(plain).put_verified(io.BytesIO(data), expected, CONTEXT)
    assert mismatch.value.code == "hash_mismatch"
    assert plain.puts() and [op for op, _ in plain.calls].count("get") >= 1

    # a correct object without a checksum echo is confirmed by the same read-back
    honest = FakeS3()
    assert make_store(honest).put_verified(io.BytesIO(data), expected, CONTEXT) == expected
    assert [op for op, _ in honest.calls].count("get") >= 1

    # head asks the provider for its stored checksum; an echoed checksum needs no read-back
    echo = FakeS3()
    echo.echo_checksum = True
    assert make_store(echo).put_verified(io.BytesIO(data), expected, CONTEXT) == expected
    assert all(kwargs.get("ChecksumMode") == "ENABLED" for kwargs in echo.head_kwargs)
    assert "get" not in [op for op, _ in echo.calls]
    corrupt_echo = FakeS3()
    corrupt_echo.echo_checksum = True
    corrupt_echo.corrupt_stored = True
    with pytest.raises(ContractError) as echoed:
        make_store(corrupt_echo).put_verified(io.BytesIO(data), expected, CONTEXT)
    assert echoed.value.code == "hash_mismatch"
    assert "get" not in [op for op, _ in corrupt_echo.calls]

    # a failed read-back is an unknown outcome: no "verified", no blind rewrite
    flaky = FakeS3()
    flaky.get_faults = [ConnectionError("a"), ConnectionError("b"), ConnectionError("c")]
    store = make_store(flaky)
    with pytest.raises(ContractError) as unknown:
        store.put_verified(io.BytesIO(data), expected, CONTEXT)
    assert unknown.value.code == "dispatch_unknown"
    with pytest.raises(ContractError) as blocked:
        store.put_verified(io.BytesIO(data), expected, CONTEXT)
    assert blocked.value.code == "dispatch_unknown"
    assert len(flaky.puts()) == 1


def test_denied_read_is_forbidden_without_retries() -> None:
    data = b"synthetic staged bytes"
    expected = ref_for(data)
    client = FakeS3()
    store = make_store(client)
    store.put_verified(io.BytesIO(data), expected, CONTEXT)
    client.calls.clear()
    client.get_faults = [FakeClientError("AccessDenied", 403)]
    with pytest.raises(ContractError) as denied:
        store.read_verified(expected, CONTEXT, len(data))
    assert denied.value.code == "forbidden"
    assert [op for op, _ in client.calls] == ["get"]


@pytest.mark.parametrize("code", ["NoSuchBucket", "NoSuchUpload"])
def test_missing_bucket_is_unknown_not_absent(code: str) -> None:
    data = b"synthetic staged bytes"
    expected = ref_for(data)
    client = FakeS3()
    client.fail_put_before_store = TimeoutError("synthetic")
    store = make_store(client)
    with pytest.raises(ContractError):
        store.put_verified(io.BytesIO(data), expected, CONTEXT)
    client.head_error = FakeClientError(code, 404)
    with pytest.raises(ContractError) as unknown:
        store.reconcile(expected, CONTEXT)
    assert unknown.value.code == "dispatch_unknown"
    # a plain missing key stays a proven absence
    client.head_error = None
    assert store.reconcile(expected, CONTEXT) == "absent"


def test_put_rejects_wrong_bytes_and_bounds_before_any_request() -> None:
    data = b"synthetic staged bytes"
    client = FakeS3()
    store = make_store(client, max_object_bytes=len(data))
    with pytest.raises(ContractError) as wrong:
        store.put_verified(
            io.BytesIO(b"other bytes of the same!"[: len(data)]), ref_for(data), CONTEXT
        )
    assert wrong.value.code == "hash_mismatch"
    big = b"x" * (len(data) + 1)
    with pytest.raises(ContractError) as large:
        store.put_verified(io.BytesIO(big), ref_for(big), CONTEXT)
    assert large.value.code == "limit_exceeded"
    with pytest.raises(ContractError) as foreign:
        store.put_verified(io.BytesIO(data), ref_for(data, OTHER_PROJECT), CONTEXT)
    assert foreign.value.code == "forbidden"
    assert client.calls == []


def test_denied_upload_is_forbidden_not_unknown() -> None:
    data = b"synthetic staged bytes"
    client = FakeS3()
    client.fail_put_before_store = FakeClientError("AccessDenied", 403)
    store = make_store(client)
    with pytest.raises(ContractError) as denied:
        store.put_verified(io.BytesIO(data), ref_for(data), CONTEXT)
    assert denied.value.code == "forbidden"
    assert [op for op, _ in client.calls] == ["put"]  # denial is definitive: no reconcile


def test_verified_reads_resume_and_reject_tampering() -> None:
    data = bytes(range(64)) * 2
    expected = ref_for(data)
    client = FakeS3()
    store = make_store(client)
    store.put_verified(io.BytesIO(data), expected, CONTEXT)

    with store.open_verified(expected, CONTEXT) as handle:
        assert handle.read() == data
    assert store.read_verified(expected, CONTEXT, len(data)).data == data
    with pytest.raises(ContractError) as small:
        store.read_verified(expected, CONTEXT, len(data) - 1)
    assert small.value.code == "limit_exceeded"

    # a reset mid-stream resumes from the verified offset within the configured bound
    client.get_faults = [5, ConnectionError("synthetic reset")]
    before = len([1 for op, _ in client.calls if op == "get"])
    assert store.read_verified(expected, CONTEXT, len(data)).data == data

    assert len([1 for op, _ in client.calls if op == "get"]) - before == 8 + 2  # 2 real resets

    # more resets than the configured bound is unavailable, not a partial result
    client.get_faults = [ConnectionError("a"), ConnectionError("b"), ConnectionError("c")]
    with pytest.raises(ContractError) as exhausted:
        store.read_verified(expected, CONTEXT, len(data))
    assert exhausted.value.code == "unavailable"

    # tampered remote content never verifies
    (key,) = client.objects
    client.objects[key] = b"\x00" * len(data)
    with pytest.raises(ContractError) as tampered:
        store.read_verified(expected, CONTEXT, len(data))
    assert tampered.value.code == "hash_mismatch"

    missing = ref_for(b"never uploaded")
    with pytest.raises(ContractError) as absent:
        store.read_verified(missing, CONTEXT, 64)
    assert absent.value.code == "artifact_missing"
    with pytest.raises(ContractError) as foreign:
        store.read_verified(ref_for(data, OTHER_PROJECT), CONTEXT, len(data))
    assert foreign.value.code == "forbidden"


def test_manifest_is_written_last_and_only_after_every_part() -> None:
    parts = [b"part one", b"part two"]
    manifest = b'{"synthetic":"manifest"}'
    client = FakeS3()
    store = make_store(client)
    refs = store.put_with_manifest(
        [(ref_for(part), io.BytesIO(part)) for part in parts],
        (ref_for(manifest), io.BytesIO(manifest)),
        CONTEXT,
    )
    assert refs == tuple(ref_for(item) for item in (*parts, manifest))
    written = client.puts()
    assert written[-1].endswith(ref_for(manifest).digest)
    assert len(written) == 3

    failing = FakeS3()
    failing.fail_put_before_store = FakeClientError("AccessDenied", 403)
    with pytest.raises(ContractError):
        make_store(failing).put_with_manifest(
            [(ref_for(part), io.BytesIO(part)) for part in parts],
            (ref_for(manifest), io.BytesIO(manifest)),
            CONTEXT,
        )
    assert not any(key.endswith(ref_for(manifest).digest) for key in failing.objects)

    with pytest.raises(ContractError) as many:
        make_store(FakeS3(), max_parts=1).put_with_manifest(
            [(ref_for(part), io.BytesIO(part)) for part in parts],
            (ref_for(manifest), io.BytesIO(manifest)),
            CONTEXT,
        )
    assert many.value.code == "limit_exceeded"


SECRET = b"synthetic-secret-token-value"
INPUT = ref_for(b"synthetic staged input")
PLAN_ID = "00000000-0000-0000-0000-0000000000a1"
RUN_ID = "00000000-0000-0000-0000-0000000000a2"
ATTEMPT_ID = "00000000-0000-0000-0000-0000000000a3"
RESERVATION_ID = "00000000-0000-0000-0000-0000000000a4"
LATER = "2030-01-01T01:00:00.000Z"


def synthetic_ref(schema: str, seed: str) -> dict[str, Any]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": hashlib.sha256(seed.encode()).hexdigest(),
        "sizeBytes": 10,
        "mediaType": "application/json",
        "artifactSchema": schema,
        "locations": [],
    }


def make_plan(expires_at: str = LATER, valid_until: str = LATER) -> ExecutionPlan:
    return ExecutionPlan.model_validate(
        {
            "schemaVersion": "kf.execution-plan.v1",
            "projectId": PROJECT,
            "runId": RUN_ID,
            "planId": PLAN_ID,
            "executionConfigRef": synthetic_ref("kf.execution-config.v1", "config"),
            "admissionReportRef": synthetic_ref("kf.admission-report.v1", "report"),
            "extractionSpecRef": synthetic_ref("kf.extraction-spec.v1", "spec"),
            "policyRef": synthetic_ref("kf.policy.v1", "policy"),
            "profileId": "synthetic.profile",
            "profileVersion": "v1",
            "contractSetRef": synthetic_ref("kf.contract-set.v1", "contracts"),
            "limitsRefs": [synthetic_ref("kf.contract-limits.v1", "limits")],
            "inputRefs": [INPUT.model_dump(by_alias=True)],
            "operationKey": hashlib.sha256(b"operation").hexdigest(),
            "resources": {
                "cpuMilli": 100,
                "memoryMiB": 64,
                "gpuCount": 0,
                "maxWallSeconds": 10,
                "maxOutputBytes": 4096,
                "maxConcurrentAttempts": 1,
                "maxAttemptsPerOperation": 1,
                "automaticRetries": 0,
            },
            "budget": {
                "currency": "USD",
                "maxRunCost": "1",
                "maxAttemptCost": "1",
                "tariffRef": synthetic_ref("kf.tariff.v1", "tariff"),
                "authorizationId": "00000000-0000-0000-0000-0000000000a5",
                "validUntil": valid_until,
            },
            "expiresAt": expires_at,
        }
    )


def make_attempt(plan: ExecutionPlan, state: str = "reserved", **overrides: Any) -> StageAttempt:
    values: dict[str, Any] = {
        "schemaVersion": "kf.stage-attempt.v1",
        "projectId": PROJECT,
        "planId": plan.plan_id,
        "operationKey": plan.operation_key,
        "attemptId": ATTEMPT_ID,
        "attemptNumber": 1,
        "reservationId": RESERVATION_ID,
        "state": state,
        "createdAt": NOW,
    }
    return StageAttempt.model_validate(values | overrides)


class Issuer:
    def __init__(self) -> None:
        self.requests: list[CredentialRequest] = []

    def __call__(self, request: CredentialRequest) -> tuple[bytes, ...]:
        self.requests.append(request)
        return (SECRET,)


def test_no_credentials_or_unreserved_upload() -> None:
    data = b"synthetic staged bytes"
    expected = ref_for(data)

    # no_upload_before_storage_reservation: no SDK request of any kind without the gate
    for gate in (
        lambda _ref, _context: False,
        lambda _ref, _context: "yes",  # truthy but not an explicit grant
        lambda _ref, _context: (_ for _ in ()).throw(RuntimeError("synthetic gate outage")),
    ):
        client = FakeS3()
        store = make_store(client, reserved=gate)  # type: ignore[arg-type]
        with pytest.raises(ContractError) as denied:
            store.put_verified(io.BytesIO(data), expected, CONTEXT)
        assert denied.value.code == "forbidden"
        with pytest.raises(ContractError):
            store.reconcile(expected, CONTEXT)
        assert client.calls == []

    # grants_expire_and_are_redacted: scoped, short-lived, never rendered
    plan = make_plan()
    attempt = make_attempt(plan)
    client = FakeS3()
    issuer = Issuer()
    store = make_store(client, issuer=issuer)
    grants = store.grant_transport(plan, attempt, CONTEXT)
    assert type(grants) is TransportGrants
    assert grants.material == (SECRET,)
    assert grants.expires_at == "2030-01-01T00:05:00.000Z"  # now + configured ttl
    assert grants.destination_id == "synthetic.destination"
    assert grants.project_id == PROJECT
    assert grants.attempt_id == ATTEMPT_ID
    assert grants.plan_digest == hashlib.sha256(encoded(plan)).hexdigest()
    assert grants.output_scope == (f"{BUCKET}/staging/f1/{PROJECT}/attempts/{ATTEMPT_ID}/".encode())
    rendered = repr(grants) + str(grants)
    assert SECRET.decode() not in rendered
    assert grants.output_scope.decode() not in rendered
    (request,) = issuer.requests
    assert request.write_prefix == f"staging/f1/{PROJECT}/attempts/{ATTEMPT_ID}/"
    # exact keys of every object the worker reads: input, extraction spec, report and limits
    refs = (INPUT, plan.extraction_spec_ref, plan.admission_report_ref, *plan.limits_refs)
    assert request.read_keys == tuple(
        f"staging/f1/{PROJECT}/sha256/{ref.digest[:2]}/{ref.digest}" for ref in refs
    )
    assert request.expires_at == grants.expires_at
    assert (request.bucket, request.region) == (BUCKET, "synthetic-region-1")
    assert request.credential_source == "synthetic-source"
    assert SECRET.decode() not in repr(request)
    assert client.calls == []  # granting never touches the remote store


def test_grant_expiry_is_capped_by_plan_and_refused_when_expired() -> None:
    short = make_plan(expires_at="2030-01-01T00:01:00.000Z", valid_until="2030-01-01T00:00:30.000Z")
    grants = make_store(FakeS3(), issuer=Issuer()).grant_transport(
        short, make_attempt(short), CONTEXT
    )
    assert grants.expires_at == "2030-01-01T00:00:30.000Z"  # budget validity binds first

    for expires, valid in (
        (NOW, NOW),
        ("2029-12-31T23:59:59.000Z", "2029-12-31T23:59:59.000Z"),
    ):
        issuer = Issuer()
        plan = make_plan(expires_at=expires, valid_until=valid)
        with pytest.raises(ContractError) as expired:
            make_store(FakeS3(), issuer=issuer).grant_transport(plan, make_attempt(plan), CONTEXT)
        assert expired.value.code == "authorization_expired"
        assert issuer.requests == []


def test_grant_refusals_issue_no_credential() -> None:
    plan = make_plan()
    issuer = Issuer()
    store = make_store(FakeS3(), issuer=issuer)
    other_plan = make_plan().model_copy(update={"plan_id": "00000000-0000-0000-0000-0000000000b1"})
    cases: list[tuple[ExecutionPlan, StageAttempt, AccessContext]] = [
        (plan, make_attempt(plan, "planned"), CONTEXT),  # no reservation yet
        (plan, make_attempt(plan, "failed", finishedAt=NOW), CONTEXT),  # terminal
        (plan, make_attempt(plan, "unknown_outcome"), CONTEXT),  # unresolved
        (plan, make_attempt(plan), AccessContext(OTHER_PROJECT, ACTOR, CONTEXT.scopes)),
        (plan, make_attempt(plan), AccessContext(PROJECT, ACTOR, frozenset({"read"}))),
        (other_plan, make_attempt(plan), CONTEXT),  # attempt belongs to another plan
        (plan, make_attempt(plan, operationKey="f" * 64), CONTEXT),
    ]
    for case_plan, case_attempt, case_context in cases:
        with pytest.raises(ContractError) as refused:
            store.grant_transport(case_plan, case_attempt, case_context)
        assert refused.value.code == "forbidden"
    assert issuer.requests == []

    # unreserved input storage: no credential is issued
    unreserved = make_store(FakeS3(), issuer=issuer, reserved=lambda _r, _c: False)
    with pytest.raises(ContractError) as gated:
        unreserved.grant_transport(plan, make_attempt(plan), CONTEXT)
    assert gated.value.code == "forbidden"
    assert issuer.requests == []

    # no registered credential source: blocked, not defaulted
    with pytest.raises(ContractError) as missing:
        make_store(FakeS3()).grant_transport(plan, make_attempt(plan), CONTEXT)
    assert missing.value.code == "unsupported_capability"


@pytest.mark.parametrize(
    "material",
    [(), (b"",), ("text",), (b"x" * 9000,), (b"a",) * 9],  # empty, non-bytes, too big, too many
)
def test_unusable_issuer_material_and_issuer_failure_are_redacted(material: Any) -> None:
    plan = make_plan()
    store = make_store(FakeS3(), issuer=lambda _request: material)
    with pytest.raises(ContractError) as bad:
        store.grant_transport(plan, make_attempt(plan), CONTEXT)
    assert bad.value.code == "forbidden"

    def failing(_request: CredentialRequest) -> tuple[bytes, ...]:
        raise RuntimeError(SECRET.decode())

    with pytest.raises(ContractError) as outage:
        make_store(FakeS3(), issuer=failing).grant_transport(plan, make_attempt(plan), CONTEXT)
    assert outage.value.code == "forbidden"
    assert SECRET.decode() not in repr(outage.value) and outage.value.__cause__ is None


def test_staging_config_resolves_only_registered_destinations() -> None:
    entry = {
        "store_id": "synthetic-staging",
        "endpoint_id": "synthetic-endpoint",
        "bucket": BUCKET,
        "prefix": "staging/f1",
        "region": "synthetic-region-1",
        "credential_source": "synthetic-source",
        "max_object_bytes": 4096,
        "transfer_chunk_bytes": 16,
        "max_read_resumes": 1,
        "max_parts": 4,
        "grant_ttl_seconds": 60,
    }
    registered = {"synthetic.destination": entry}
    resolved = StagingConfig.resolve("synthetic.destination", registered)
    assert resolved.bucket == BUCKET and resolved.max_attempts == 1
    assert resolved.client_options()["max_attempts"] == 1

    with pytest.raises(ContractError) as unknown:
        StagingConfig.resolve("unregistered", registered)
    assert unknown.value.code == "limits_missing"
    partial = {key: value for key, value in entry.items() if key != "max_object_bytes"}
    with pytest.raises(ContractError) as incomplete:
        StagingConfig.resolve("synthetic.destination", {"synthetic.destination": partial})
    assert incomplete.value.code == "limits_missing"
    with pytest.raises(ContractError):
        StagingConfig.resolve("synthetic.destination", {"synthetic.destination": entry | {"x": 1}})

    # URLs, paths and credential values are not accepted where labels belong
    for bad in (
        {"bucket": "https://synthetic.invalid/bucket"},
        {"endpoint_id": "synthetic.invalid:9000/path"},
        {"region": "https://region"},
        {"prefix": "../escape"},
        {"prefix": "a//b"},
        {"credential_source": "key=secret value"},
        {"max_object_bytes": 0},
        {"max_object_bytes": True},
        {"max_attempts": 2},
    ):
        with pytest.raises(ContractError):
            config(**bad)
