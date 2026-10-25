"""Exact C03 sidecar shape without executing provenance or following audit links."""

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.artifacts import ArtifactManifest
from conscience_foundry.release.edges import edge_roles

PROJECT = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"


def ref(project: str = PROJECT) -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": project,
        "digest": "a" * 64,
        "sizeBytes": 17,
        "mediaType": "text/plain",
        "artifactSchema": "kf.raw-original.v1",
        "locations": [{"storeId": "synthetic", "objectKey": "objects/synthetic"}],
    }


def manifest(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-manifest.v1",
        "projectId": PROJECT,
        "artifact": ref(),
        "producer": {
            "codeVersion": "synthetic.code.v1",
            "imageDigest": "b" * 64,
            "processorId": "text.utf8.v1",
            "processorVersion": "synthetic.processor.v1",
        },
        "inputRefs": [ref()],
        "operationKey": "c" * 64,
        "attemptId": OTHER,
        "createdAt": "2026-10-25T00:00:00.000Z",
    } | updates


def test_artifact_manifest_exact_shape_and_audit_provenance() -> None:
    value = ArtifactManifest.model_validate(manifest())
    assert value.producer.processor_id == "text.utf8.v1"
    assert tuple(edge.role for edge in edge_roles("kf.artifact-manifest.v1", value)) == (
        "audit",
        "audit",
    )
    assert "digest" not in value.model_dump(by_alias=True)
    for update in ({"artifact": ref(OTHER)}, {"inputRefs": [ref(OTHER)]}, {"ownDigest": "a" * 64}):
        with pytest.raises(ValidationError):
            ArtifactManifest.model_validate(manifest(**update))
    with pytest.raises(ValidationError):
        value.input_refs = ()
