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
* ``r2_client`` is the only place ``boto3`` is imported, lazily, so offline use needs no SDK.

Whether R2 honors a scoped temporary credential is live preflight evidence, not asserted here.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast

from conscience_foundry.contracts.common import ContractError, Id, Instant
from conscience_foundry.contracts.execution import ExecutionPlan
from conscience_foundry.storage.staging_s3 import CredentialRequest, S3Client, credential_scopes

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
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise ContractError("unsupported_capability") from None
    return cast(
        S3Client,
        boto3.client(
            "s3",
            endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com",
            region_name="auto",
            aws_access_key_id=values["accessKeyId"],
            aws_secret_access_key=values["secretAccessKey"],
            aws_session_token=values["sessionToken"],
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                retries={"total_max_attempts": 1, "mode": "standard"},  # one request, no retry
            ),
        ),
    )
