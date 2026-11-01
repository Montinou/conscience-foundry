"""R2 split temporary credentials, split client routing and checksum mode, offline.

No network, credential or provider payload is used: the Cloudflare API and both S3 clients are
fakes, and every identifier, key and token below is synthetic. Whether R2 honors a scoped
temporary credential, a conditional create or a checksum header is live preflight evidence, not
asserted here.
"""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Mapping
from typing import Any

import pytest
from test_staging_s3 import (
    ACTOR,
    ATTEMPT_ID,
    BUCKET,
    CONTEXT,
    NOW,
    OTHER_PROJECT,
    PROJECT,
    FakeClientError,
    FakeS3,
    config,
    make_attempt,
    make_plan,
    make_store,
    ref_for,
)

from conscience_foundry.contracts.common import ArtifactRef, ContractError, ContractLimits
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import ObjectStore
from conscience_foundry.storage.r2 import (
    R2CredentialIssuer,
    R2ObjectStore,
    SplitR2Client,
    r2_client,
    r2_static_client,
)
from conscience_foundry.storage.staging_s3 import (
    CredentialRequest,
    S3StagingStore,
    StagingConfig,
    readable_refs,
)

ACCOUNT = "synthetic-account-id"
PARENT_KEY = "synthetic-parent-access-key-id"
TOKEN_ENV = "SYNTHETIC_R2_API_TOKEN"
TOKEN_VALUE = "synthetic-cloudflare-api-token-value"
PREFIX = "staging/f1"
TEMP_PATH = f"/accounts/{ACCOUNT}/r2/temp-access-credentials"
ATTEMPT_PREFIX = f"{PREFIX}/{PROJECT}/attempts/{ATTEMPT_ID}/"
TOTAL_BOUND = 120


class FakeApi:
    """Cloudflare API double: records (path, request); answers a distinct credential per call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []
        self.fail: Exception | None = None

    def __call__(self, path: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append((path, request))
        if self.fail is not None:
            raise self.fail
        permission = request["body"]["permission"]
        return {
            "success": True,
            "result": {
                "accessKeyId": f"synthetic-key-id-{permission}",
                "secretAccessKey": f"synthetic-secret-{permission}",
                "sessionToken": f"synthetic-session-{permission}",
            },
        }


class Answer:
    """An API double that always returns one fixed (possibly unusable) answer."""

    def __init__(self, answer: Mapping[str, Any]) -> None:
        self.answer = answer

    def __call__(self, path: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.answer


def make_issuer(
    api: FakeApi, *, total_bound_seconds: int = TOTAL_BOUND, now: str = NOW
) -> R2CredentialIssuer:
    return R2CredentialIssuer(
        account_id=ACCOUNT,
        bucket=BUCKET,
        prefix=PREFIX,
        parent_access_key_id=PARENT_KEY,
        token_env=TOKEN_ENV,
        total_bound_seconds=total_bound_seconds,
        clock=lambda: now,
        http=api,
    )


def request_for(**overrides: Any) -> CredentialRequest:
    values: dict[str, Any] = {
        "credential_source": "synthetic-source",
        "region": "auto",
        "bucket": BUCKET,
        "read_keys": (f"{PREFIX}/{PROJECT}/sha256/aa/{'a' * 64}",),
        "write_prefix": ATTEMPT_PREFIX,
        "expires_at": "2030-01-01T00:05:00.000Z",
    }
    return CredentialRequest(**(values | overrides))


# -- issuer ---------------------------------------------------------------------------------


def test_issuer_mints_two_scoped_credentials() -> None:
    api = FakeApi()
    issuer = make_issuer(api)
    plan = make_plan()
    store = make_store(FakeS3(), issuer=issuer)  # grant ttl 300s: expiry is now + 300s
    grants = store.grant_transport(plan, make_attempt(plan), CONTEXT)

    read_keys, write_prefix = issuer.scopes(plan, ATTEMPT_ID)
    assert write_prefix == ATTEMPT_PREFIX
    assert read_keys == frozenset(
        f"{PREFIX}/{ref.project_id}/sha256/{ref.digest[:2]}/{ref.digest}"
        for ref in readable_refs(plan)
    )

    assert [path for path, _ in api.calls] == [TEMP_PATH, TEMP_PATH]
    read_only, read_write = (request["body"] for _, request in api.calls)
    # the API token is only ever named, never carried, by the issuer
    assert all(request["tokenEnv"] == TOKEN_ENV for _, request in api.calls)
    assert read_only == {
        "bucket": BUCKET,
        "parentAccessKeyId": PARENT_KEY,
        "permission": "object-read-only",
        "ttlSeconds": TOTAL_BOUND + 60,
        "objects": sorted(read_keys),
    }
    assert read_write == {
        "bucket": BUCKET,
        "parentAccessKeyId": PARENT_KEY,
        "permission": "object-read-write",
        "ttlSeconds": TOTAL_BOUND + 60,
        "prefixes": [ATTEMPT_PREFIX],
    }
    assert "objects" not in read_write

    # both credentials travel in the grants, read-only first, and are never rendered
    assert len(grants.material) == 2
    first, second = (json.loads(piece) for piece in grants.material)
    assert first["accessKeyId"] == "synthetic-key-id-object-read-only"
    assert second["accessKeyId"] == "synthetic-key-id-object-read-write"
    rendered = repr(grants) + str(grants) + repr(issuer)
    assert "synthetic-secret" not in rendered and "synthetic-session" not in rendered
    assert TOKEN_VALUE not in rendered


def test_scopes_and_minting_come_from_the_same_issuer() -> None:
    """The scopes an attestation probes are the ones the minting path requests."""
    api = FakeApi()
    issuer = make_issuer(api)
    plan = make_plan()
    requests: list[CredentialRequest] = []

    def spy(request: CredentialRequest) -> tuple[bytes, ...]:
        requests.append(request)
        return issuer(request)

    make_store(FakeS3(), issuer=spy).grant_transport(plan, make_attempt(plan), CONTEXT)
    (request,) = requests
    assert issuer.scopes(plan, ATTEMPT_ID) == (frozenset(request.read_keys), request.write_prefix)


def test_ttl_never_outlives_grant() -> None:
    # remaining 300s is shorter than total_bound + 60: the grant wins
    api = FakeApi()
    make_issuer(api, total_bound_seconds=1000)(request_for())
    assert {request["body"]["ttlSeconds"] for _, request in api.calls} == {300}

    # a fraction of a second is never rounded up
    api = FakeApi()
    make_issuer(api)(request_for(expires_at="2030-01-01T00:00:30.900Z"))
    assert {request["body"]["ttlSeconds"] for _, request in api.calls} == {30}

    # the bound wins when the grant is farther away
    api = FakeApi()
    make_issuer(api, total_bound_seconds=10)(request_for())
    assert {request["body"]["ttlSeconds"] for _, request in api.calls} == {70}


@pytest.mark.parametrize("expires_at", ["2030-01-01T00:00:00.000Z", "2029-12-31T23:59:59.000Z"])
def test_expired_credentials_refuse_before_write(expires_at: str) -> None:
    api = FakeApi()
    with pytest.raises(ContractError) as expired:
        make_issuer(api)(request_for(expires_at=expires_at))
    assert expired.value.code == "authorization_expired"
    assert api.calls == []

    # through the store: no credential, so nothing can write
    plan = make_plan()
    client = FakeS3()
    store = make_store(client, issuer=make_issuer(api, now="2030-01-01T02:00:00.000Z"))
    with pytest.raises(ContractError):
        store.grant_transport(plan, make_attempt(plan), CONTEXT)
    assert api.calls == [] and client.calls == []


def test_issuer_refuses_a_request_outside_its_own_scope() -> None:
    api = FakeApi()
    issuer = make_issuer(api)
    wrong_bucket = request_for(bucket="other-bucket")
    wrong_prefix = request_for(write_prefix=f"other/{PROJECT}/attempts/{ATTEMPT_ID}/")
    stray_read = request_for(read_keys=(f"other/{PROJECT}/sha256/aa/{'a' * 64}",))
    traversal = request_for(write_prefix=f"{PREFIX}/../x/")
    for bad in (wrong_bucket, wrong_prefix, stray_read, traversal):
        with pytest.raises(ContractError) as refused:
            issuer(bad)
        assert refused.value.code == "forbidden"
    assert api.calls == []


def test_issuer_api_failures_are_redacted(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    caplog.set_level(logging.DEBUG)
    api = FakeApi()
    api.fail = RuntimeError(f"401 for bearer {TOKEN_VALUE}")
    with pytest.raises(ContractError) as failed:
        make_issuer(api)(request_for())
    assert TOKEN_VALUE not in str(failed.value) + repr(failed.value)
    assert failed.value.__cause__ is None and failed.value.__suppress_context__
    assert TOKEN_VALUE not in caplog.text

    # an unusable answer is an error too, and carries nothing of it
    for answer in ({"success": False, "result": None}, {"result": {"accessKeyId": 1}}, {}):
        with pytest.raises(ContractError) as unusable:
            make_issuer(Answer(answer))(request_for())  # type: ignore[arg-type]
        assert unusable.value.code == "unavailable"


# -- split client ---------------------------------------------------------------------------


READ_KEY = f"{PREFIX}/{PROJECT}/sha256/aa/{'a' * 64}"
OTHER_READ_KEY = f"{PREFIX}/{PROJECT}/sha256/bb/{'b' * 64}"
OWN_KEY = f"{ATTEMPT_PREFIX}sha256/cc/{'c' * 64}"
FOREIGN_KEY = f"{PREFIX}/{PROJECT}/attempts/other/sha256/cc/{'c' * 64}"


def split() -> tuple[SplitR2Client, FakeS3, FakeS3]:
    read_only, read_write = FakeS3(), FakeS3()
    read_only.objects[READ_KEY] = b"synthetic input"
    client = SplitR2Client(
        read_only=read_only,
        read_write=read_write,
        read_keys=frozenset({READ_KEY, OTHER_READ_KEY}),
        write_prefix=ATTEMPT_PREFIX,
    )
    return client, read_only, read_write


def test_split_client_refuses_write_to_read_key() -> None:
    client, read_only, read_write = split()
    for key in (READ_KEY, FOREIGN_KEY, "somewhere/else", f"{ATTEMPT_PREFIX}../escape"):
        with pytest.raises(ContractError) as refused:
            client.put_object(Bucket=BUCKET, Key=key, Body=b"x", IfNoneMatch="*")
        assert refused.value.code == "forbidden"
    # reads outside both scopes are refused locally too
    for operation in (client.get_object, client.head_object):
        for key in (FOREIGN_KEY, "somewhere/else", f"{ATTEMPT_PREFIX}../escape"):
            with pytest.raises(ContractError) as refused:
                operation(Bucket=BUCKET, Key=key)
            assert refused.value.code == "forbidden"
    assert read_only.calls == [] and read_write.calls == []


def test_split_client_routes_readback_under_prefix_to_rw() -> None:
    client, read_only, read_write = split()
    # a declared input is read with the read-only credential
    assert client.head_object(Bucket=BUCKET, Key=READ_KEY)["ContentLength"] == 15
    client.get_object(Bucket=BUCKET, Key=READ_KEY)
    assert read_only.calls == [("head", READ_KEY), ("get", READ_KEY)] and read_write.calls == []

    # an object this attempt wrote, and its read-back, use the read-write credential only
    client.put_object(Bucket=BUCKET, Key=OWN_KEY, Body=b"out", IfNoneMatch="*")
    client.head_object(Bucket=BUCKET, Key=OWN_KEY)
    client.get_object(Bucket=BUCKET, Key=OWN_KEY)
    assert read_write.calls == [("put", OWN_KEY), ("head", OWN_KEY), ("get", OWN_KEY)]
    assert len(read_only.calls) == 2

    # end to end through the store: write, verify by read-back, all under the prefix
    read_only, read_write = FakeS3(), FakeS3()
    routed = SplitR2Client(read_only, read_write, frozenset({READ_KEY}), ATTEMPT_PREFIX)
    store = S3StagingStore(
        config(checksum_mode="readback"),
        routed,
        authorize=None,
        storage_reserved=lambda _ref, _context: True,
        clock=lambda: NOW,
        attempt_id=ATTEMPT_ID,
        project_id=PROJECT,
    )
    data = b"synthetic worker output"
    expected = ref_for(data)
    assert store.put_verified(io.BytesIO(data), expected, CONTEXT) == expected
    assert read_only.calls == []
    operations = [op for op, _ in read_write.calls]
    assert operations[:2] == ["put", "head"] and set(operations[2:]) == {"get"}  # ranged read-back
    assert all(key.startswith(ATTEMPT_PREFIX) for _, key in read_write.calls)


def test_client_errors_are_redacted(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    caplog.set_level(logging.DEBUG)

    class Leaky(FakeClientError):
        def __init__(self, code: str, status: int) -> None:
            super().__init__(code, status)
            self.args = (f"request signed with {TOKEN_VALUE}",)
            self.response["Error"]["Message"] = f"token {TOKEN_VALUE}"

    client, read_only, read_write = split()
    read_write.fail_put_before_store = Leaky("InternalError", 500)
    read_only.head_error = Leaky("AccessDenied", 403)
    for call in (
        lambda: client.put_object(Bucket=BUCKET, Key=OWN_KEY, Body=b"x"),
        lambda: client.head_object(Bucket=BUCKET, Key=READ_KEY),
    ):
        with pytest.raises(Exception) as failure:
            call()
        response = getattr(failure.value, "response", "")
        rendered = str(failure.value) + repr(failure.value) + repr(response)
        assert TOKEN_VALUE not in rendered
        assert failure.value.__cause__ is None and failure.value.__suppress_context__
    assert TOKEN_VALUE not in caplog.text

    # the stable code and status survive, so the store still tells a 412 from a denial
    read_write.fail_put_before_store = Leaky("PreconditionFailed", 412)
    with pytest.raises(Exception) as exists:
        client.put_object(Bucket=BUCKET, Key=OWN_KEY, Body=b"x")
    assert exists.value.response["Error"] == {"Code": "PreconditionFailed"}  # type: ignore[attr-defined]
    assert exists.value.response["ResponseMetadata"] == {"HTTPStatusCode": 412}  # type: ignore[attr-defined]

    # an error with no usable shape still carries nothing
    read_write.fail_put_before_store = ValueError(TOKEN_VALUE)
    with pytest.raises(Exception) as shapeless:
        client.put_object(Bucket=BUCKET, Key=OWN_KEY, Body=b"x")
    assert TOKEN_VALUE not in str(shapeless.value) + repr(shapeless.value)


# -- checksum mode --------------------------------------------------------------------------


def test_readback_mode_sends_no_checksum_headers() -> None:
    data = b"synthetic staged bytes"
    expected = ref_for(data)
    client = FakeS3()
    client.echo_checksum = True  # a provider that would answer, if asked
    store = make_store(client, checksum_mode="readback")
    assert store.put_verified(io.BytesIO(data), expected, CONTEXT) == expected
    (put,) = client.put_kwargs
    assert "ChecksumSHA256" not in put and put["IfNoneMatch"] == "*"
    assert all("ChecksumMode" not in kwargs for kwargs in client.head_kwargs)
    assert ("get", put["Key"]) in client.calls  # verified by hash from a read-back, not by header

    # a stored object that differs is still caught
    corrupt = FakeS3()
    corrupt.corrupt_stored = True
    with pytest.raises(ContractError) as mismatch:
        make_store(corrupt, checksum_mode="readback").put_verified(
            io.BytesIO(data), expected, CONTEXT
        )
    assert mismatch.value.code == "hash_mismatch"

    # the lease is a write too
    leased = FakeS3()
    leaser = make_store(leased, checksum_mode="readback").scoped_to(make_plan(), ATTEMPT_ID)
    assert leaser.claim_lease(ATTEMPT_ID, "synthetic-nonce") == "won"
    assert all("ChecksumSHA256" not in kwargs for kwargs in leased.put_kwargs)

    # header mode is unchanged
    headed = FakeS3()
    headed.echo_checksum = True
    make_store(headed, checksum_mode="sha256_header").put_verified(
        io.BytesIO(data), expected, CONTEXT
    )
    assert "ChecksumSHA256" in headed.put_kwargs[0]
    assert all(kwargs.get("ChecksumMode") == "ENABLED" for kwargs in headed.head_kwargs)


def test_checksum_mode_is_required_and_closed() -> None:
    with pytest.raises(ContractError):
        config(checksum_mode="md5")
    with pytest.raises(TypeError):
        StagingConfig(  # type: ignore[call-arg]
            destination_id="synthetic.destination",
            store_id="synthetic-staging",
            endpoint_id="synthetic-endpoint",
            bucket=BUCKET,
            prefix=PREFIX,
            region="auto",
            credential_source="synthetic-source",
            max_object_bytes=4096,
            transfer_chunk_bytes=16,
            max_read_resumes=2,
            max_parts=4,
            grant_ttl_seconds=300,
        )
    entry = {
        "store_id": "synthetic-staging",
        "endpoint_id": "synthetic-endpoint",
        "bucket": BUCKET,
        "prefix": PREFIX,
        "region": "auto",
        "credential_source": "synthetic-source",
        "max_object_bytes": 4096,
        "transfer_chunk_bytes": 16,
        "max_read_resumes": 1,
        "max_parts": 4,
        "grant_ttl_seconds": 60,
    }
    with pytest.raises(ContractError) as missing:
        StagingConfig.resolve("synthetic.destination", {"synthetic.destination": entry})
    assert missing.value.code == "limits_missing"
    resolved = StagingConfig.resolve(
        "synthetic.destination", {"synthetic.destination": entry | {"checksum_mode": "readback"}}
    )
    assert resolved.checksum_mode == "readback"


# -- the real client factory ----------------------------------------------------------------


def test_r2_client_options() -> None:
    pytest.importorskip("boto3")
    credentials = {
        "accessKeyId": "synthetic-key-id",
        "secretAccessKey": "synthetic-secret",
        "sessionToken": "synthetic-session",
    }
    client = r2_client(ACCOUNT, credentials)
    assert client.meta.endpoint_url == f"https://{ACCOUNT}.r2.cloudflarestorage.com"  # type: ignore[attr-defined]
    assert client.meta.region_name == "auto"  # type: ignore[attr-defined]
    options = client.meta.config  # type: ignore[attr-defined]
    assert options.request_checksum_calculation == "when_required"
    assert options.response_checksum_validation == "when_required"
    assert options.retries["total_max_attempts"] == 1  # one request, never a hidden retry
    assert "synthetic-secret" not in repr(client)

    with pytest.raises(ContractError) as partial:
        r2_client(ACCOUNT, {"accessKeyId": "synthetic-key-id"})
    assert partial.value.code == "invalid_schema"


# -- the R2 backup store --------------------------------------------------------------------

BACKUP_BUCKET = "synthetic-backup"
PAYLOAD = b"synthetic backup bytes"
DENIED = FakeClientError("AccessDenied", 403)


def backup_store(client: FakeS3, **options: Any) -> R2ObjectStore:
    return R2ObjectStore(client, BACKUP_BUCKET, "backup", **options)


def backup_key(ref: ArtifactRef) -> str:
    return f"sha256/{ref.digest[:2]}/{ref.digest}"


def test_r2_object_store_round_trips_content_addressed_keys() -> None:
    client = FakeS3()
    store: ObjectStore = backup_store(client)
    ref = ref_for(PAYLOAD)
    assert store.put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT) == ref
    assert client.objects == {backup_key(ref): PAYLOAD}
    assert {call["Bucket"] for call in client.put_kwargs} == {BACKUP_BUCKET}
    assert client.put_kwargs[0]["IfNoneMatch"] == "*"  # an existing key is never overwritten
    assert store.read_verified(ref, CONTEXT, len(PAYLOAD)).data == PAYLOAD
    with store.open_verified(ref, CONTEXT) as handle:
        assert handle.read() == PAYLOAD
    empty = ref_for(b"")
    store.put_verified(io.BytesIO(b""), empty, CONTEXT)
    assert store.read_verified(empty, CONTEXT, 1).data == b""


def test_r2_object_store_second_write_is_verified_not_repeated() -> None:
    client = FakeS3()
    store = backup_store(client)
    ref = ref_for(PAYLOAD)
    store.put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    store.put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)  # 412, then proven by read-back
    assert len(client.objects) == 1
    client.objects[backup_key(ref)] = b"X" * len(PAYLOAD)  # a different object under the key
    with pytest.raises(ContractError) as clash:
        store.put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    assert clash.value.code == "hash_mismatch"


def test_r2_object_store_refuses_bad_input_before_any_request() -> None:
    client = FakeS3()
    store = backup_store(client)
    ref = ref_for(PAYLOAD)
    with pytest.raises(ContractError) as wrong:
        store.put_verified(io.BytesIO(b"x" * len(PAYLOAD)), ref, CONTEXT)
    assert wrong.value.code == "hash_mismatch"
    with pytest.raises(ContractError) as foreign:
        store.put_verified(
            io.BytesIO(PAYLOAD), ref, AccessContext(OTHER_PROJECT, ACTOR, frozenset())
        )
    assert foreign.value.code == "forbidden"
    assert client.calls == []


def test_r2_object_store_authorizer_and_ceiling_apply() -> None:
    client = FakeS3()
    ref = ref_for(PAYLOAD)
    seen: list[str] = []

    def authorize(_ref: ArtifactRef, _context: AccessContext, effect: str) -> None:
        seen.append(effect)
        if effect == "read":
            raise ContractError("forbidden")

    store = backup_store(client, authorize=authorize)
    store.put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    with pytest.raises(ContractError) as read:
        store.open_verified(ref, CONTEXT)
    assert read.value.code == "forbidden" and seen == ["write", "read"]
    with pytest.raises(ContractError) as unavailable:
        backup_store(client, authorize=lambda *_: True).open_verified(ref, CONTEXT)
    assert unavailable.value.code == "forbidden"  # a returned value is not consent
    tiny = ContractLimits.model_validate(
        {
            "schemaVersion": "cf.contract-limits.v1",
            "version": "synthetic.v1",
            "maxJsonBytes": 4,
            "maxStringScalars": 4,
            "maxArrayItems": 4,
            "maxDepth": 4,
            "maxManifestItems": 4,
            "maxSourceBytes": 4,
            "maxOutputBytes": 4,
            "maxErrorMessageScalars": 4,
        }
    )
    with pytest.raises(ContractError) as large:
        backup_store(client, limits=tiny).put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    assert large.value.code == "limit_exceeded"
    assert client.puts() == [backup_key(ref)]  # only the first write ever reached the client


def test_r2_object_store_unknown_write_outcome_fails_closed() -> None:
    ref = ref_for(PAYLOAD)
    landed = FakeS3()
    landed.lose_put_response = True  # stored, then the response is lost
    assert backup_store(landed).put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT) == ref
    assert landed.objects == {backup_key(ref): PAYLOAD}  # proven by read-back, never assumed

    absent = FakeS3()
    absent.fail_put_before_store = TimeoutError("synthetic timeout")
    with pytest.raises(ContractError) as unknown:
        backup_store(absent).put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    assert unknown.value.code == "dispatch_unknown"  # not stored now, but may still land

    blind = FakeS3()
    blind.lose_put_response = True
    blind.get_faults = [ConnectionError("synthetic reset")] * 4
    with pytest.raises(ContractError) as unreadable:
        backup_store(blind).put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    assert unreadable.value.code == "dispatch_unknown"

    unverified = FakeS3()
    unverified.corrupt_stored = True
    with pytest.raises(ContractError) as corrupt:
        backup_store(unverified).put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    assert corrupt.value.code == "hash_mismatch"


def test_r2_object_store_denied_write_is_forbidden() -> None:
    client = FakeS3()
    client.fail_put_before_store = DENIED
    with pytest.raises(ContractError) as denied:
        backup_store(client).put_verified(io.BytesIO(PAYLOAD), ref_for(PAYLOAD), CONTEXT)
    assert denied.value.code == "forbidden"


def test_r2_object_store_reads_classify_failures() -> None:
    client = FakeS3()
    store = backup_store(client)
    ref = ref_for(PAYLOAD)
    with pytest.raises(ContractError) as missing:
        store.open_verified(ref, CONTEXT)
    assert missing.value.code == "artifact_missing"
    client.objects[backup_key(ref)] = b"X" * len(PAYLOAD)
    with pytest.raises(ContractError) as corrupt:
        store.read_verified(ref, CONTEXT, len(PAYLOAD))
    assert corrupt.value.code == "hash_mismatch"
    client.objects[backup_key(ref)] = PAYLOAD
    client.get_faults = [DENIED]
    with pytest.raises(ContractError) as denied:
        store.open_verified(ref, CONTEXT)
    assert denied.value.code == "forbidden"
    client.get_faults = [TimeoutError("synthetic timeout")]
    with pytest.raises(ContractError) as other:
        store.open_verified(ref, CONTEXT)
    assert other.value.code == "unavailable"  # reads have no effect, so they simply fail
    client.get_faults = [4]  # the body is cut short, then the connection resets
    with pytest.raises(ContractError) as cut:
        store.open_verified(ref, CONTEXT)
    assert cut.value.code == "unavailable"
    with pytest.raises(ContractError) as small:
        store.read_verified(ref, CONTEXT, 3)
    assert small.value.code == "limit_exceeded"


def test_r2_object_store_never_surfaces_provider_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "synthetic-provider-secret-text"

    class Leaky(Exception):
        def __init__(self) -> None:
            super().__init__(secret)
            self.response = {
                "Error": {"Code": "InternalError", "Message": secret},
                "ResponseMetadata": {"HTTPStatusCode": 500},
            }

    client = FakeS3()
    client.fail_put_before_store = Leaky()
    store = backup_store(client)
    ref = ref_for(PAYLOAD)
    with caplog.at_level(logging.DEBUG), pytest.raises(ContractError) as write:
        store.put_verified(io.BytesIO(PAYLOAD), ref, CONTEXT)
    client.get_faults = [Leaky()]
    with pytest.raises(ContractError) as read:
        store.open_verified(ref, CONTEXT)
    for error in (write.value, read.value):
        assert secret not in str(error) and secret not in repr(error)
    assert secret not in caplog.text and secret not in repr(store)
    assert "client" not in repr(store)


def test_r2_object_store_validates_its_configuration() -> None:
    client = FakeS3()
    for bucket, store_id in (("", "backup"), ("Bad_Bucket", "backup"), (BACKUP_BUCKET, "")):
        with pytest.raises(ContractError) as bad:
            R2ObjectStore(client, bucket, store_id)
        assert bad.value.code == "invalid_schema"
    with pytest.raises(ContractError) as no_client:
        R2ObjectStore(object(), BACKUP_BUCKET, "backup")  # type: ignore[arg-type]
    assert no_client.value.code == "invalid_schema"


def test_r2_static_client_options() -> None:
    pytest.importorskip("boto3")
    client = r2_static_client(ACCOUNT, "synthetic-key-id", "synthetic-secret")
    assert client.meta.endpoint_url == f"https://{ACCOUNT}.r2.cloudflarestorage.com"  # type: ignore[attr-defined]
    assert client.meta.region_name == "auto"  # type: ignore[attr-defined]
    options = client.meta.config  # type: ignore[attr-defined]
    assert options.request_checksum_calculation == "when_required"
    assert options.response_checksum_validation == "when_required"
    assert options.retries["total_max_attempts"] == 1
    assert "synthetic-secret" not in repr(client)
    for key_id, secret in (("", "synthetic-secret"), ("synthetic-key-id", "")):
        with pytest.raises(ContractError) as empty:
            r2_static_client(ACCOUNT, key_id, secret)
        assert empty.value.code == "invalid_schema"
