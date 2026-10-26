"""Temporary S3-compatible staging behind the ObjectStore protocol.

This is a transient transfer area, never permanent storage. Trust model:

* The SDK client is injected (already bound to an operator-registered endpoint
  and to one transport attempt); this module holds no URL, credential value or
  provider payload, and never imports an SDK.
* PostgreSQL alone owns storage reservations. A trusted control-side gate
  (``storage_reserved``) must confirm the funded ``run_storage`` reservation
  before any request that could create a remote object; the worker has no
  database access.
* Inputs live at shared content-addressed keys; the minted credential reads exactly those keys
  (every object the worker reads) and writes only under its one attempt prefix. A store bound to
  an attempt (``scoped_to``) therefore reads declared inputs from the shared keys and reads and
  writes every other object under that prefix; an unbound store is the control side's, which
  stages inputs at the shared keys.
* Objects are content-addressed and created with a conditional (``If-None-Match``)
  write, so an existing key is never overwritten. A timeout or any ambiguous
  response is an unknown outcome, never a proven failure: it is reconciled by
  reading back and hashing, and the write is not repeated without that
  reconciliation. That block lives in this store instance only: a new process
  starts without it, so durable unknown-outcome accounting stays with the
  control-side ledger, which must record it before any further write.
* A write is "verified" only by a hash: the provider's stored SHA-256 when it
  reports one, otherwise a bounded read-back of the object. Size alone never is.
* Failures surface only as stable ``ContractError`` codes.

Whether a given compatible provider honors conditional creation, scoped
grants or its tariff is live preflight evidence, not asserted here.
"""

from __future__ import annotations

import base64
import hashlib
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, BinaryIO, Literal, Protocol, cast

from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ArtifactLocation,
    ContractError,
    Id,
    Instant,
    Ref,
)
from conscience_foundry.contracts.execution import ExecutionPlan, StageAttempt
from conscience_foundry.execution.ports import TransportGrants
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import VerifiedBytes
from conscience_foundry.storage.locator import Authorizer

_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_MEDIA_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$"
)


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


class S3Client(Protocol):
    """The three SDK operations used; errors expose an SDK-style ``response`` mapping."""

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class CredentialRequest:
    """What a runtime credential issuer may mint: exact reads, one attempt prefix, one expiry.

    ``read_keys`` name every object the worker reads; ``write_prefix`` is where the worker creates
    objects and reads them back to verify, so it is the only place output keys may live.

    Carries no secret; the issuer resolves ``credential_source`` out of band.
    """

    credential_source: str
    region: str
    bucket: str
    read_keys: tuple[str, ...]
    write_prefix: str
    expires_at: Instant


CredentialIssuer = Callable[[CredentialRequest], tuple[bytes, ...]]
"""Trusted runtime-injected issuer of short-lived scoped material for a registered source."""

StorageReservationGate = Callable[[Ref, AccessContext], bool]
"""Trusted control-side check that a funded run_storage reservation covers the object."""


def _attempt_prefix(prefix: str, project_id: str, attempt_id: str) -> str:
    return f"{prefix}/{project_id}/attempts/{attempt_id}/"


def readable_refs(plan: ExecutionPlan) -> tuple[Ref, ...]:
    """Every object the worker reads for this plan: inputs, spec, admission report and limits."""
    refs = (
        *plan.input_refs,
        plan.extraction_spec_ref,
        plan.admission_report_ref,
        *plan.limits_refs,
    )
    return tuple({ref.digest: ref for ref in refs}.values())


def _positive(value: object) -> int:
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        raise ContractError("invalid_schema")
    return value


def _label(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ContractError("invalid_schema")
    return value


@dataclass(frozen=True)
class StagingConfig:
    """Operator-registered staging destination and bounds; labels only, never URLs.

    ``endpoint_id`` and ``credential_source`` are names registered by the
    operator outside the code base; the endpoint address and credential values
    are resolved by whoever builds the injected client and credential issuer.
    ``max_attempts`` is fixed at one transport attempt: the SDK client must be
    built with ``client_options()`` so it never retries paid requests itself.
    """

    destination_id: str
    store_id: str
    endpoint_id: str
    bucket: str
    prefix: str
    region: str
    credential_source: str
    max_object_bytes: int
    transfer_chunk_bytes: int
    max_read_resumes: int
    max_parts: int
    grant_ttl_seconds: int
    request_timeout_seconds: int = 30
    max_attempts: int = 1
    max_grant_pieces: int = 8
    max_grant_material_bytes: int = 8192

    def __post_init__(self) -> None:
        for name in ("destination_id", "store_id", "endpoint_id", "credential_source"):
            _label(getattr(self, name), _LABEL)
        _label(self.bucket, _BUCKET)
        _label(self.region, _REGION)
        if type(self.prefix) is not str or not self.prefix:
            raise ContractError("invalid_schema")
        try:
            ArtifactLocation(store_id=self.store_id, object_key=self.prefix)
        except ValueError:
            raise ContractError("unsafe_path") from None
        for name in (
            "max_object_bytes",
            "transfer_chunk_bytes",
            "max_parts",
            "grant_ttl_seconds",
            "request_timeout_seconds",
            "max_grant_pieces",
            "max_grant_material_bytes",
        ):
            _positive(getattr(self, name))
        if type(self.max_read_resumes) is not int or not 0 <= self.max_read_resumes <= 16:
            raise ContractError("invalid_schema")
        if self.max_attempts != 1:
            raise ContractError("unsupported_capability")

    @classmethod
    def resolve(
        cls, destination_id: str, registered: Mapping[str, Mapping[str, object]]
    ) -> StagingConfig:
        """Select an operator-registered destination by id; unknown or partial entries block."""
        entry = registered.get(destination_id) if isinstance(registered, Mapping) else None
        if not isinstance(entry, Mapping):
            raise ContractError("limits_missing")
        names = {
            "store_id",
            "endpoint_id",
            "bucket",
            "prefix",
            "region",
            "credential_source",
            "max_object_bytes",
            "transfer_chunk_bytes",
            "max_read_resumes",
            "max_parts",
            "grant_ttl_seconds",
        }
        optional = {"request_timeout_seconds", "max_grant_pieces", "max_grant_material_bytes"}
        if not names <= set(entry):
            raise ContractError("limits_missing")
        if set(entry) - names - optional:
            raise ContractError("invalid_schema")
        return cls(destination_id=destination_id, **{key: entry[key] for key in entry})  # type: ignore[arg-type]

    def client_options(self) -> Mapping[str, int]:
        """Single-attempt, bounded-timeout settings for building the injected SDK client."""
        return {
            "max_attempts": self.max_attempts,
            "connect_timeout": self.request_timeout_seconds,
            "read_timeout": self.request_timeout_seconds,
        }


Outcome = Literal["exists", "missing", "denied", "unknown"]


def _classify(error: Exception) -> Outcome:
    """Map an SDK-shaped error to a definitive meaning; everything else is unknown."""
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return "unknown"
    detail = response.get("Error")
    meta = response.get("ResponseMetadata")
    code = detail.get("Code") if isinstance(detail, Mapping) else None
    status = meta.get("HTTPStatusCode") if isinstance(meta, Mapping) else None
    if code in {"NoSuchBucket", "NoSuchUpload"}:
        return "unknown"  # a missing bucket is a misconfiguration, never proof of an absent key
    if code == "PreconditionFailed" or status == 412:
        return "exists"
    if code in {"NoSuchKey", "NotFound", "404"} or status == 404:
        return "missing"
    if code in {"AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch"} or status in {
        401,
        403,
    }:
        return "denied"
    return "unknown"


def _read_exact(stream: BinaryIO, expected: Ref, ceiling: int, chunk_bytes: int) -> bytes:
    """Read a bounded local stream fully and verify its size and digest before any upload."""
    if expected.size_bytes > ceiling:
        raise ContractError("limit_exceeded")
    chunks: list[bytes] = []
    total = 0
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(min(chunk_bytes, expected.size_bytes - total + 1))
        if type(chunk) is not bytes:
            raise ContractError("invalid_schema")
        if not chunk:
            break
        total += len(chunk)
        if total > expected.size_bytes:
            raise ContractError("limit_exceeded")
        digest.update(chunk)
        chunks.append(chunk)
    if total != expected.size_bytes or digest.hexdigest() != expected.digest:
        raise ContractError("hash_mismatch")
    return b"".join(chunks)


@dataclass
class S3StagingStore:
    """ObjectStore over one injected S3-compatible client and one registered destination."""

    config: StagingConfig
    client: S3Client = field(repr=False)
    authorize: Authorizer = field(repr=False)
    storage_reserved: StorageReservationGate = field(repr=False)
    clock: Callable[[], str] = field(repr=False)
    credential_issuer: CredentialIssuer | None = field(default=None, repr=False)
    attempt_id: Id | None = None
    declared_inputs: frozenset[str] = field(default=frozenset(), repr=False)
    _unresolved: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        if not callable(self.authorize) or not callable(self.storage_reserved):
            raise ContractError("invalid_schema")
        if not callable(self.clock):
            raise ContractError("invalid_schema")
        for name in ("put_object", "head_object", "get_object"):
            if not callable(getattr(self.client, name, None)):
                raise ContractError("invalid_schema")

    # -- addressing -----------------------------------------------------------------

    def _key(self, ref: Ref) -> str:
        """Derived only from project and digest; ref.locations are untrusted and ignored."""
        return f"{self.config.prefix}/{ref.project_id}/sha256/{ref.digest[:2]}/{ref.digest}"

    def _attempt_key(self, ref: Ref) -> str:
        """Where an attempt-bound store keeps its own objects: under the credential's prefix."""
        return (
            f"{_attempt_prefix(self.config.prefix, ref.project_id, str(self.attempt_id))}"
            f"sha256/{ref.digest[:2]}/{ref.digest}"
        )

    def _write_key(self, ref: Ref) -> str:
        return self._key(ref) if self.attempt_id is None else self._attempt_key(ref)

    def _read_key(self, ref: Ref) -> str:
        shared = self._key(ref)
        if self.attempt_id is None or shared in self.declared_inputs:
            return shared
        return self._attempt_key(ref)

    def scoped_to(self, plan: ExecutionPlan, attempt_id: Id) -> S3StagingStore:
        """Bind a view to one attempt: plan inputs read shared, all else under its prefix."""
        if type(plan) is not ExecutionPlan:
            raise ContractError("forbidden")
        _label(attempt_id, _LABEL)
        return replace(
            self,
            attempt_id=attempt_id,
            declared_inputs=frozenset(self._key(ref) for ref in readable_refs(plan)),
        )

    def _check(self, ref: Ref, context: AccessContext, effect: str) -> None:
        if type(ref) is not Ref or type(context) is not AccessContext:
            raise ContractError("forbidden")
        if ref.project_id != context.project_id:
            raise ContractError("forbidden")
        try:
            # An authorizer must raise to deny; any returned value is not consent.
            result = cast(Callable[[Ref, AccessContext, str], object], self.authorize)(
                ref, context, effect
            )
            if result is not None:
                raise ContractError("forbidden")
        except ContractError:
            raise
        except Exception:
            raise ContractError("unavailable") from None
        if ref.size_bytes > self.config.max_object_bytes:
            raise ContractError("limit_exceeded")

    def _reserved(self, ref: Ref, context: AccessContext) -> None:
        try:
            granted = self.storage_reserved(ref, context)
        except Exception:
            raise ContractError("forbidden") from None
        if granted is not True:
            raise ContractError("forbidden")

    # -- transport grants -----------------------------------------------------------

    def grant_transport(
        self, plan: ExecutionPlan, attempt: StageAttempt, context: AccessContext
    ) -> TransportGrants:
        """Mint short-lived material scoped to this attempt: exact input reads, one output prefix.

        Only a reserved or dispatching attempt of this plan qualifies, every object the
        worker reads (inputs, extraction spec, admission report and pinned limits) must be
        covered by a funded storage reservation and is granted by exact key, and the expiry
        is the earliest of the configured ttl, the plan expiry and the budget validity.
        The attested scope check stays with the control-side evidence authority.
        """
        if (
            type(plan) is not ExecutionPlan
            or type(attempt) is not StageAttempt
            or type(context) is not AccessContext
        ):
            raise ContractError("forbidden")
        if (
            not plan.project_id == attempt.project_id == context.project_id
            or attempt.plan_id != plan.plan_id
            or attempt.operation_key != plan.operation_key
            or not {"read", "remoteTransfer"} <= context.scopes
            or attempt.state not in {"reserved", "dispatching"}
        ):
            raise ContractError("forbidden")
        if self.credential_issuer is None:
            raise ContractError("unsupported_capability")
        expires_at = self._grant_expiry(plan)
        readable = readable_refs(plan)
        for ref in readable:
            self._check(ref, context, "read")
            self._reserved(ref, context)
        prefix = _attempt_prefix(self.config.prefix, plan.project_id, attempt.attempt_id)
        request = CredentialRequest(
            credential_source=self.config.credential_source,
            region=self.config.region,
            bucket=self.config.bucket,
            read_keys=tuple(self._key(ref) for ref in readable),
            write_prefix=prefix,
            expires_at=expires_at,
        )
        try:
            material = self.credential_issuer(request)
        except Exception:
            raise ContractError("forbidden") from None
        self._validate_material(material)
        return TransportGrants(
            project_id=plan.project_id,
            plan_digest=hashlib.sha256(
                plan.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
            ).hexdigest(),
            attempt_id=attempt.attempt_id,
            destination_id=self.config.destination_id,
            expires_at=expires_at,
            material=material,
            output_scope=f"{self.config.bucket}/{prefix}".encode(),
        )

    def _now(self) -> datetime:
        try:
            return _parse(self.clock())
        except Exception:
            raise ContractError("unavailable") from None

    def _grant_expiry(self, plan: ExecutionPlan) -> Instant:
        now = self._now()
        expiry = min(
            now + timedelta(seconds=self.config.grant_ttl_seconds),
            _parse(plan.expires_at),
            _parse(plan.budget.valid_until),
        )
        if expiry <= now:
            raise ContractError("authorization_expired")
        return expiry.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expiry.microsecond // 1000:03d}Z"

    def _validate_material(self, material: object) -> None:
        if (
            type(material) is not tuple
            or not material
            or len(material) > self.config.max_grant_pieces
            or any(type(piece) is not bytes or not piece for piece in material)
            or sum(len(piece) for piece in material) > self.config.max_grant_material_bytes
        ):
            raise ContractError("forbidden")

    # -- writes ---------------------------------------------------------------------

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        self._check(expected, context, "write")
        self._reserved(expected, context)  # D05: reservation precedes any remote request
        data = _read_exact(
            stream, expected, self.config.max_object_bytes, self.config.transfer_chunk_bytes
        )
        key = self._write_key(expected)
        if key in self._unresolved:
            raise ContractError("dispatch_unknown")  # reconcile() before any further write
        return self._create(expected, key, data)

    def _create(self, expected: Ref, key: str, data: bytes) -> Ref:
        media_type = expected.media_type if _MEDIA_TYPE.fullmatch(expected.media_type) else None
        try:
            self.client.put_object(
                Bucket=self.config.bucket,
                Key=key,
                Body=data,
                ContentLength=len(data),
                ContentType=media_type or "application/octet-stream",
                IfNoneMatch="*",
                ChecksumSHA256=base64.b64encode(hashlib.sha256(data).digest()).decode("ascii"),
            )
            self._verify_written(expected, key)
        except ContractError as error:
            if error.code == "hash_mismatch":
                raise
            # verification could not complete: the stored object is unproven, not "verified"
            self._unresolved.add(key)
            raise ContractError("dispatch_unknown") from None
        except Exception as error:
            outcome = _classify(error)
            if outcome == "denied":
                raise ContractError("forbidden") from None
            # An existing key (412) and every ambiguous result are settled by reading back.
            self._unresolved.add(key)
            if self._reconcile_key(expected, key) != "present":
                raise ContractError("dispatch_unknown") from None
        self._unresolved.discard(key)
        return expected

    def _verify_written(self, expected: Ref, key: str) -> None:
        """Confirm the stored object by hash: the provider's checksum, else a bounded read-back.

        The read-back is bounded by ``max_object_bytes`` and ``max_read_resumes`` and
        runs inside the put the storage reservation already covers.
        """
        head = self.client.head_object(Bucket=self.config.bucket, Key=key, ChecksumMode="ENABLED")
        if head.get("ContentLength") != expected.size_bytes:
            raise ContractError("hash_mismatch")
        checksum = head.get("ChecksumSHA256")
        if checksum is None:
            self._download(expected, key).close()
            return
        wanted = base64.b64encode(bytes.fromhex(expected.digest)).decode("ascii")
        if checksum != wanted:
            raise ContractError("hash_mismatch")

    def put_with_manifest(
        self,
        parts: Sequence[tuple[Ref, BinaryIO]],
        manifest: tuple[Ref, BinaryIO],
        context: AccessContext,
    ) -> tuple[Ref, ...]:
        """Write every part first; the manifest only after all parts verified."""
        if len(parts) > self.config.max_parts:
            raise ContractError("limit_exceeded")
        written = tuple(self.put_verified(stream, ref, context) for ref, stream in parts)
        manifest_ref, manifest_stream = manifest
        return (*written, self.put_verified(manifest_stream, manifest_ref, context))

    def reconcile(self, ref: Ref, context: AccessContext) -> Literal["present", "absent"]:
        """Read back one object by hash after an unknown write; clears the retry block.

        Authorization and the storage reservation are required again: even a
        read-back is a billable request against the destination.
        """
        self._check(ref, context, "read")
        self._reserved(ref, context)
        key = self._write_key(ref)
        state = self._reconcile_key(ref, key)
        if state == "unknown":
            raise ContractError("dispatch_unknown")
        self._unresolved.discard(key)
        return state

    def _reconcile_key(self, ref: Ref, key: str) -> Literal["present", "absent", "unknown"]:
        try:
            head = self.client.head_object(Bucket=self.config.bucket, Key=key)
        except Exception as error:
            return "absent" if _classify(error) == "missing" else "unknown"
        if head.get("ContentLength") != ref.size_bytes:
            raise ContractError("hash_mismatch")
        try:
            self._download(ref, key).close()
        except ContractError as error:
            if error.code == "artifact_missing":
                return "absent"
            if error.code in {"hash_mismatch", "forbidden"}:
                raise
            return "unknown"
        return "present"

    # -- reads ----------------------------------------------------------------------

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        """Return an independent private snapshot; caller owns closing the handle."""
        self._check(ref, context, "read")
        return self._download(ref, self._read_key(ref))

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes:
        if type(limit) is not int or limit <= 0 or limit > MAX_SAFE_INTEGER:
            raise ContractError("invalid_schema")
        if ref.size_bytes > limit:
            raise ContractError("limit_exceeded")
        with self.open_verified(ref, context) as handle:
            data = handle.read(ref.size_bytes + 1)
        if len(data) > limit:
            raise ContractError("limit_exceeded")
        return VerifiedBytes(data, ref.digest)

    def _download(self, ref: Ref, key: str) -> BinaryIO:
        """Ranged, bounded read that resumes from the verified offset a limited number of times."""
        chunk = self.config.transfer_chunk_bytes
        output = tempfile.TemporaryFile(mode="w+b")
        try:
            digest = hashlib.sha256()
            offset = 0
            resumes = 0
            while True:
                want = min(chunk, ref.size_bytes - offset)
                kwargs: dict[str, Any] = {"Bucket": self.config.bucket, "Key": key}
                if ref.size_bytes:
                    kwargs["Range"] = f"bytes={offset}-{offset + want - 1}"
                try:
                    response = self.client.get_object(**kwargs)
                    data = self._body(response, want, ref.size_bytes)
                except ContractError:
                    raise
                except Exception as error:
                    outcome = _classify(error)
                    if outcome == "missing":
                        raise ContractError("artifact_missing") from None
                    if outcome == "denied":
                        raise ContractError("forbidden") from None
                    resumes += 1
                    if resumes > self.config.max_read_resumes:
                        raise ContractError("unavailable") from None
                    continue
                digest.update(data)
                output.write(data)
                offset += len(data)
                if offset >= ref.size_bytes:
                    break
            if digest.hexdigest() != ref.digest:
                raise ContractError("hash_mismatch")
            output.seek(0)
            return output
        except BaseException:
            output.close()
            raise

    def _body(self, response: Mapping[str, Any], want: int, total: int) -> bytes:
        body = response["Body"]
        try:
            data = body.read(want + 1)
        finally:
            closer = getattr(body, "close", None)
            if callable(closer):
                closer()
        if type(data) is not bytes or len(data) > want:
            raise ContractError("hash_mismatch")
        if not data and total:
            raise ConnectionError("empty ranged read")
        span = response.get("ContentRange")
        if span is not None and (type(span) is not str or not span.endswith(f"/{total}")):
            raise ContractError("hash_mismatch")
        return data
