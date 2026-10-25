"""Compare deterministic F1 content while retaining every reported quality check."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from conscience_foundry.contracts.canonical import QualityCheck, QualityReport
from conscience_foundry.contracts.common import ContractError, ContractLimits, Digest, Id, Reason
from conscience_foundry.core.identity import (
    _DIGEST,
    _ID,
    _VERSION,
    _bounded_hash,
    _limits,
    _string,
)


@dataclass(frozen=True, slots=True)
class F1Comparison:
    project_id: Id
    asset_id: Id
    source_id: Id
    operation_key: Digest
    revision_id: Digest
    original_digest: Digest
    text_digest: Digest
    extraction_spec_digest: Digest
    structure_digest: Digest
    origin_map_digest: Digest
    quality_projection_digest: Digest


def comparison_digest(projection: F1Comparison, *, limits: ContractLimits) -> Digest:
    """Digest the exact C06 projection, excluding attempt-specific wrappers and cost."""
    _limits(limits)
    if type(projection) is not F1Comparison:
        raise ContractError("invalid_schema")
    return _bounded_hash("kf.f1-comparison.v1", {
        "projectId": _string(projection.project_id, _ID, limits),
        "assetId": _string(projection.asset_id, _ID, limits),
        "sourceId": _string(projection.source_id, _ID, limits),
        "operationKey": _string(projection.operation_key, _DIGEST, limits),
        "revisionId": _string(projection.revision_id, _DIGEST, limits),
        "originalDigest": _string(projection.original_digest, _DIGEST, limits),
        "textDigest": _string(projection.text_digest, _DIGEST, limits),
        "extractionSpecDigest": _string(projection.extraction_spec_digest, _DIGEST, limits),
        "structureDigest": _string(projection.structure_digest, _DIGEST, limits),
        "originMapDigest": _string(projection.origin_map_digest, _DIGEST, limits),
        "qualityProjectionDigest": _string(projection.quality_projection_digest, _DIGEST, limits),
    }, limits)


def quality_projection_digest(report: QualityReport, *, limits: ContractLimits) -> Digest:
    """Retain disposition and every unique check/outcome/code, never free messages.

    This checks the required F1 check set separately from deterministic comparison;
    actual quality evidence and trusted artifact provenance remain caller-owned.
    """
    _limits(limits)
    if (
        type(report) is not QualityReport
        or report.schema_version != "kf.quality-report.v1"
        or type(report.checks) is not tuple
    ):
        raise ContractError("invalid_schema")
    if len(report.checks) > limits.max_array_items:
        raise ContractError("limit_exceeded")
    checks: list[dict[str, object]] = []
    validated_checks: list[QualityCheck] = []
    for check in report.checks:
        if type(check) is not QualityCheck:
            raise ContractError("invalid_schema")
        check_id = _string(check.check_id, _VERSION, limits)
        outcome = _string(check.outcome, _VERSION, limits)
        item: dict[str, object] = {"checkId": check_id, "outcome": outcome}
        validation: dict[str, object] = dict(item)
        if check.reason is not None:
            if type(check.reason) is not Reason:
                raise ContractError("invalid_schema")
            code = _string(check.reason.code, _VERSION, limits)
            item["reasonCode"] = code
            validation["reason"] = {"code": code, "message": ""}
        try:
            validated_checks.append(QualityCheck.model_validate(validation))
        except ValidationError:
            raise ContractError("invalid_schema") from None
        checks.append(item)
    disposition = _string(report.disposition, _VERSION, limits)
    try:
        QualityReport.model_validate({
            "schema_version": "kf.quality-report.v1",
            "source_id": _string(report.source_id, _ID, limits),
            "checks": tuple(validated_checks), "disposition": disposition,
        })
    except ValidationError:
        raise ContractError("invalid_schema") from None
    # Application-defined array order; JCS only orders object keys.
    checks.sort(key=lambda item: str(item["checkId"]).encode("utf-16-be"))
    return _bounded_hash("kf.quality-projection.v1", {
        "disposition": disposition, "checks": checks,
    }, limits)
