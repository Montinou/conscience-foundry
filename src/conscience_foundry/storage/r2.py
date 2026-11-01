"""Cloudflare R2: split temporary credentials, a client that routes by scope, the SDK factory.

* ``R2CredentialIssuer`` mints two temporary credentials per attempt through the Cloudflare API:
  a read-only one limited to the exact input keys, and a read-write one limited to the attempt's
  one prefix. Neither outlives the grant. The API token is never held here: the injected ``http``
  callable is told only the *name* of the environment variable that carries it, so the value never
  appears in this object, its ``repr`` or any error.
* ``SplitR2Client`` gives the worker one ``S3Client`` over the two credentials. It routes each
  request by key and refuses locally anything outside the two scopes, so a misrouted request
  never reaches the provider. Provider errors are re-raised with only their stable code and
  status, never their message.
* ``R2ObjectStore`` is the independent backup store: an ``ObjectStore`` over one bucket with
  content-addressed keys. Every write is proven by a read-back hash, and an ambiguous write is an
  unknown outcome (``dispatch_unknown``), never a success or a failure.
* ``r2_client`` and ``r2_static_client`` are the only places ``boto3`` is imported, lazily, so
  offline use needs no SDK.

Whether R2 honors a scoped temporary credential is live preflight evidence, not asserted here.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, BinaryIO, cast

from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    ContractLimits,
    Id,
    Instant,
    Ref,
)
from conscience_foundry.contracts.execution import ExecutionPlan
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import VerifiedBytes
from conscience_foundry.storage.locator import IO_CHUNK_BYTES, Authorizer
from conscience_foundry.storage.staging_s3 import (
    _BUCKET,
    _MEDIA_TYPE,
    CredentialRequest,
    S3Client,
    _classify,
    _read_exact,
    credential_scopes,
)

_PERMISSIONS = ("object-read-only", "object-read-write")
_FIELDS = ("accessKeyId", "secretAccessKey", "sessionToken")
_SAFETY_MARGIN_SECONDS = 60


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _contained(key: str, prefix: str) -> bool:
    return key.startswith(prefix) and ".." not in key.split("/")


@dataclass(frozen=True)
class R2CredentialIssuer:
    """Mints the read-only and read-write temporary credentials for one attempt.

    ``prefix`` is the staging prefix the destination is configured with; a request for any other
    bucket or any key outside it is refused, so a mismatched configuration fails at minting
    rather than yielding a credential for the wrong place. ``scopes`` and minting derive from this
    one object, so an attestation that probes ``scopes`` probes what is minted.
    """

    account_id: str
    bucket: str
    prefix: str
    parent_access_key_id: str
    token_env: str = field(repr=False)
    total_bound_seconds: int
    clock: Callable[[], Instant] = field(repr=False)
    http: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] = field(repr=False)

    def scopes(self, plan: ExecutionPlan, attempt_id: Id) -> tuple[frozenset[str], str]:
        """(exact read keys, write prefix) this issuer would grant for the plan and attempt."""
        read_keys, write_prefix = credential_scopes(self.prefix, plan, attempt_id)
        return frozenset(read_keys), write_prefix

    def __call__(self, request: CredentialRequest) -> tuple[bytes, ...]:
        """Two credential pieces, read-only first, as the JSON of ``accessKeyId``, secret, token."""
        self._within_scope(request)
        ttl = self._ttl(request.expires_at)  # an expired grant never reaches the API
        path = f"/accounts/{self.account_id}/r2/temp-access-credentials"
        common: dict[str, Any] = {
            "bucket": self.bucket,
            "parentAccessKeyId": self.parent_access_key_id,
            "ttlSeconds": ttl,
        }
        scoped: tuple[dict[str, Any], dict[str, Any]] = (
            {"permission": _PERMISSIONS[0], "objects": sorted(request.read_keys)},
            {"permission": _PERMISSIONS[1], "prefixes": [request.write_prefix]},
        )
        return tuple(self._mint(path, common | extra) for extra in scoped)

    def _within_scope(self, request: CredentialRequest) -> None:
        own = f"{self.prefix}/"
        if (
            type(request) is not CredentialRequest
            or request.bucket != self.bucket
            or not _contained(request.write_prefix, own)
            or not request.write_prefix.endswith("/")
            or not request.read_keys
            or not all(_contained(key, own) for key in request.read_keys)
        ):
            raise ContractError("forbidden")

    def _ttl(self, expires_at: Instant) -> int:
        try:
            remaining = (_parse(expires_at) - _parse(self.clock())).total_seconds()
        except Exception:
            raise ContractError("unavailable") from None
        ttl = min(self.total_bound_seconds + _SAFETY_MARGIN_SECONDS, int(remaining))
        if ttl <= 0:
            raise ContractError("authorization_expired")
        return ttl

    def _mint(self, path: str, body: Mapping[str, Any]) -> bytes:
        try:
            answer = self.http(path, {"tokenEnv": self.token_env, "body": body})
            if answer["success"] is not True:
                raise ContractError("unavailable")
            result = cast(Mapping[str, Any], answer["result"])
            credential = {name: result[name] for name in _FIELDS}
        except Exception:
            raise ContractError("unavailable") from None
        if not all(type(value) is str and value for value in credential.values()):
            raise ContractError("unavailable")
        return json.dumps(credential, separators=(",", ":")).encode("utf-8")


class _RedactedClientError(Exception):
    """A provider error reduced to its stable code and status; the message is dropped."""

    def __init__(self, code: str | None, status: int | None) -> None:
        super().__init__("r2 request failed")
        error: dict[str, Any] = {} if code is None else {"Code": code}
        meta: dict[str, Any] = {} if status is None else {"HTTPStatusCode": status}
        self.response: dict[str, Any] = {"Error": error, "ResponseMetadata": meta}


def _redacted(error: Exception) -> _RedactedClientError:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return _RedactedClientError(None, None)
    detail, meta = response.get("Error"), response.get("ResponseMetadata")
    code = detail.get("Code") if isinstance(detail, Mapping) else None
    status = meta.get("HTTPStatusCode") if isinstance(meta, Mapping) else None
    return _RedactedClientError(
        code if type(code) is str else None, status if type(status) is int else None
    )


@dataclass
class SplitR2Client:
    """One ``S3Client`` over a read-only and a read-write credential.

    Reads of a declared input key use the read-only client; everything under the attempt prefix
    (writes, and the head and read-back that verify them) uses the read-write one. A key in
    neither scope, a traversal, or a write to a read key is ``forbidden`` before any request.
    """

    read_only: S3Client = field(repr=False)
    read_write: S3Client = field(repr=False)
    read_keys: frozenset[str] = field(repr=False)
    write_prefix: str

    def __post_init__(self) -> None:
        if not self.write_prefix.endswith("/") or not self.write_prefix.strip("/"):
            raise ContractError("invalid_schema")

    def _route(self, key: object, write: bool) -> S3Client:
        if type(key) is not str or ".." in key.split("/"):
            raise ContractError("forbidden")
        if key in self.read_keys:
            if write:
                raise ContractError("forbidden")
            return self.read_only
        if key.startswith(self.write_prefix):
            return self.read_write
        raise ContractError("forbidden")

    def _call(self, name: str, write: bool, kwargs: dict[str, Any]) -> Mapping[str, Any]:
        client = self._route(kwargs.get("Key"), write)
        try:
            return cast(Mapping[str, Any], getattr(client, name)(**kwargs))
        except Exception as error:
            raise _redacted(error) from None

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("put_object", True, kwargs)

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("head_object", False, kwargs)

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._call("get_object", False, kwargs)


def _boto_client(
    account_id: str, access_key_id: str, secret_access_key: str, session_token: str | None
) -> S3Client:
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise ContractError("unsupported_capability") from None
    token = {} if session_token is None else {"aws_session_token": session_token}
    return cast(
        S3Client,
        boto3.client(
            "s3",
            endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com",
            region_name="auto",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            **token,
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                retries={"total_max_attempts": 1, "mode": "standard"},  # one request, no retry
            ),
        ),
    )


def r2_client(account_id: str, credentials: Mapping[str, str]) -> S3Client:
    """A boto3 client for one temporary credential: region ``auto``, one request per call.

    Both checksum options are ``when_required``: boto3 otherwise adds checksum headers R2 may
    reject. ``credentials`` carries ``accessKeyId``, ``secretAccessKey`` and ``sessionToken``.
    """
    try:
        values = {name: credentials[name] for name in _FIELDS}
    except Exception:
        raise ContractError("invalid_schema") from None
    if not all(type(value) is str and value for value in values.values()):
        raise ContractError("invalid_schema")
    return _boto_client(
        account_id, values["accessKeyId"], values["secretAccessKey"], values["sessionToken"]
    )


def r2_static_client(account_id: str, access_key_id: str, secret_access_key: str) -> S3Client:
    """A boto3 client for an operator-held access key (no session token); same options as above."""
    if not all(type(value) is str and value for value in (access_key_id, secret_access_key)):
        raise ContractError("invalid_schema")
    return _boto_client(account_id, access_key_id, secret_access_key, None)


class R2ObjectStore:
    """``ObjectStore`` over one R2 bucket, objects at ``sha256/{dd}/{digest}``.

    Used as the independent backup destination. ``ref.locations`` are untrusted and ignored; the
    key derives from the digest alone. A write is a conditional create (an existing key is never
    overwritten) and is accepted only once a read-back hashes to the expected digest, so no
    provider checksum support is assumed. A refusal is ``forbidden``; any other doubt about
    whether the write landed is ``dispatch_unknown``, which the caller must settle before
    claiming a backup. Reads have no effect, so a failed read is just ``unavailable``.

    ``authorize`` (raise to deny, as for the local store) and ``limits`` (the same per-schema
    byte ceilings the local store applies) are supplied by the runtime that builds the store.
    Provider errors are never copied: only the stable code of this module is raised.
    """

    def __init__(
        self,
        client: S3Client,
        bucket: str,
        store_id: str,
        *,
        authorize: Authorizer | None = None,
        limits: ContractLimits | None = None,
    ) -> None:
        if (
            type(bucket) is not str
            or _BUCKET.fullmatch(bucket) is None
            or type(store_id) is not str
            or not store_id
            or (authorize is not None and not callable(authorize))
            or (limits is not None and type(limits) is not ContractLimits)
            or not all(
                callable(getattr(client, name, None))
                for name in ("put_object", "head_object", "get_object")
            )
        ):
            raise ContractError("invalid_schema")
        self._client = client
        self.bucket = bucket
        self.store_id = store_id
        self._authorize = authorize
        self._limits = limits

    def __repr__(self) -> str:
        return f"R2ObjectStore(bucket={self.bucket!r}, store_id={self.store_id!r})"

    @staticmethod
    def _key(ref: Ref) -> str:
        return f"sha256/{ref.digest[:2]}/{ref.digest}"

    def _check(self, ref: Ref, context: AccessContext, effect: str) -> int:
        """Authorize the object for ``effect`` and return its byte ceiling."""
        if type(ref) is not Ref or type(context) is not AccessContext:
            raise ContractError("forbidden")
        if ref.project_id != context.project_id:
            raise ContractError("forbidden")
        if self._authorize is not None:
            try:
                # An authorizer must raise to deny; any returned value is not consent.
                result = cast(Callable[[Ref, AccessContext, str], object], self._authorize)(
                    ref, context, effect
                )
                if result is not None:
                    raise ContractError("forbidden")
            except ContractError:
                raise
            except Exception:
                raise ContractError("unavailable") from None
        limits = self._limits
        if limits is None:
            ceiling = MAX_SAFE_INTEGER
        elif ref.artifact_schema == "cf.raw-original.v1":
            ceiling = limits.max_source_bytes
        else:
            ceiling = limits.max_output_bytes
        if ref.size_bytes > ceiling:
            raise ContractError("limit_exceeded")
        return ceiling

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        ceiling = self._check(expected, context, "write")
        data = _read_exact(stream, expected, ceiling, IO_CHUNK_BYTES)  # nothing sent if it differs
        key = self._key(expected)
        media_type = expected.media_type if _MEDIA_TYPE.fullmatch(expected.media_type) else None
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=data,
                ContentLength=len(data),
                ContentType=media_type or "application/octet-stream",
                IfNoneMatch="*",
            )
        except Exception as error:
            if _classify(error) == "denied":
                raise ContractError("forbidden") from None
            # An existing key (412) and every ambiguous response are settled by reading back.
        self._prove(expected, key)
        return expected

    def _prove(self, ref: Ref, key: str) -> None:
        """The object at ``key`` hashes to ``ref``, or the write is a mismatch or unknown."""
        try:
            self._download(ref, key).close()
        except ContractError as error:
            if error.code in {"hash_mismatch", "forbidden"}:
                raise
            raise ContractError("dispatch_unknown") from None

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        """Return an independent private snapshot; caller owns closing the handle."""
        self._check(ref, context, "read")
        return self._download(ref, self._key(ref))

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
        """One bounded read of the object into a private file, verified by size and digest."""
        try:
            body = self._client.get_object(Bucket=self.bucket, Key=key)["Body"]
        except Exception as error:
            outcome = _classify(error)
            if outcome == "missing":
                raise ContractError("artifact_missing") from None
            if outcome == "denied":
                raise ContractError("forbidden") from None
            raise ContractError("unavailable") from None
        output = tempfile.TemporaryFile(mode="w+b")
        try:
            digest = hashlib.sha256()
            total = 0
            try:
                while True:
                    chunk = body.read(min(IO_CHUNK_BYTES, ref.size_bytes - total + 1))
                    if type(chunk) is not bytes:
                        raise ContractError("unavailable")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > ref.size_bytes:
                        raise ContractError("hash_mismatch")
                    digest.update(chunk)
                    output.write(chunk)
            except ContractError:
                raise
            except Exception:
                raise ContractError("unavailable") from None
            finally:
                closer = getattr(body, "close", None)
                if callable(closer):
                    closer()
            if total != ref.size_bytes or digest.hexdigest() != ref.digest:
                raise ContractError("hash_mismatch")
            output.seek(0)
            return output
        except BaseException:
            output.close()
            raise
