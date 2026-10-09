from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from f_vra.cve_vf.legacy.advisories import ingest_ghsa_record, ingest_osv_record
from f_vra_server_db import models as m
from f_vra_server_db.repository import normalize_name


CONFIDENCE_SCORE = {
    "low": 0.3,
    "medium": 0.6,
    "high": 0.9,
}

REVIEWED_LABEL_ROLES = {
    "root_cause_vf": "root_cause",
    "vulnerable_usage_site": "usage_site",
}

ANNOTATION_EVIDENCE_SOURCE = "vf_annotations_jsonl"


@dataclass
class AnnotationImportResult:
    rows_read: int = 0
    eligible_rows: int = 0
    imported_advisories: int = 0
    imported_entities: int = 0
    updated_entities: int = 0
    skipped_rows: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped_rows += 1
        self.skipped_reasons[reason] = self.skipped_reasons.get(reason, 0) + 1


def _fetch_osv_by_cve(cve_id: str) -> dict[str, Any] | None:
    response = requests.get(f"https://api.osv.dev/v1/vulns/{cve_id}", timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def _fetch_ghsa(ghsa_id: str) -> dict[str, Any] | None:
    try:
        response = requests.get(
            f"https://api.github.com/advisories/{ghsa_id}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "f_vra-annotation-import"},
            timeout=30,
        )
    except requests.RequestException:
        return None
    if response.status_code in {403, 404, 429}:
        return None
    try:
        response.raise_for_status()
    except requests.RequestException:
        return None
    return response.json()


def _ensure_package_metadata(session: Session, advisory: m.Advisory, payload: dict[str, Any], package: str) -> m.AdvisoryAffectedPackage | None:
    affected = _affected_package_for(session, advisory, package)
    if affected is not None:
        return affected
    for alias in payload.get("aliases") or []:
        if not str(alias).upper().startswith("GHSA-"):
            continue
        ghsa = _fetch_ghsa(str(alias))
        if ghsa is None:
            continue
        ingest_ghsa_record(session, ghsa)
        refreshed = _advisory_for_cve(session, str(ghsa.get("cve_id") or payload.get("id") or advisory.canonical_id))
        if refreshed is not None:
            affected = _affected_package_for(session, refreshed, package)
            if affected is not None:
                return affected
    return None


def _annotation_entities(session: Session, advisory: m.Advisory) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    entities = session.scalars(select(m.VulnerableEntity).where(m.VulnerableEntity.advisory_id == advisory.id))
    for entity in entities:
        if any(item.get("source") == ANNOTATION_EVIDENCE_SOURCE for item in entity.evidence if isinstance(item, dict)):
            rows.append(
                {
                    "package_name": entity.package_name,
                    "name": entity.name,
                    "entity_type": entity.entity_type,
                    "role": entity.role,
                    "confidence": entity.confidence,
                    "evidence": list(entity.evidence or []),
                }
            )
    return rows


def _restore_annotation_entities(session: Session, advisory: m.Advisory, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        package_name = str(row["package_name"])
        name = str(row["name"])
        if _entity_for(session, advisory, package_name, name) is not None:
            continue
        affected = _affected_package_for(session, advisory, package_name)
        session.add(
            m.VulnerableEntity(
                advisory_id=advisory.id,
                affected_package_id=affected.id if affected else None,
                package_name=package_name,
                name=name,
                entity_type=str(row.get("entity_type") or "function"),
                role=str(row.get("role") or "sink"),
                confidence=float(row.get("confidence") or 0.0),
                evidence=list(row.get("evidence") or []),
            )
        )
    session.commit()


def _ingest_osv_preserving_annotations(session: Session, cve_id: str, payload: dict[str, Any]) -> None:
    advisory = _advisory_for_cve(session, cve_id)
    preserved = _annotation_entities(session, advisory) if advisory is not None else []
    ingest_osv_record(session, payload)
    refreshed = _advisory_for_cve(session, cve_id)
    if refreshed is not None and preserved:
        _restore_annotation_entities(session, refreshed, preserved)


def _advisory_for_cve(session: Session, cve_id: str) -> m.Advisory | None:
    wanted = cve_id.upper()
    advisory = session.scalars(select(m.Advisory).where(func.upper(m.Advisory.canonical_id) == wanted)).first()
    if advisory is not None:
        return advisory
    alias = session.scalars(select(m.AdvisoryAlias).where(func.upper(m.AdvisoryAlias.alias) == wanted)).first()
    return session.get(m.Advisory, alias.advisory_id) if alias else None


def _affected_package_for(session: Session, advisory: m.Advisory, package: str) -> m.AdvisoryAffectedPackage | None:
    normalized = normalize_name(package)
    return session.scalars(
        select(m.AdvisoryAffectedPackage).where(
            m.AdvisoryAffectedPackage.advisory_id == advisory.id,
            m.AdvisoryAffectedPackage.normalized_name == normalized,
        )
    ).first()


def _entity_for(session: Session, advisory: m.Advisory, package: str, name: str) -> m.VulnerableEntity | None:
    return session.scalars(
        select(m.VulnerableEntity).where(
            m.VulnerableEntity.advisory_id == advisory.id,
            m.VulnerableEntity.package_name == package,
            m.VulnerableEntity.name == name,
        )
    ).first()


def _reviewed_candidates(row: dict[str, Any]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for candidate in row.get("per_candidate") or []:
        if not isinstance(candidate, dict):
            continue
        label = str(candidate.get("label") or "")
        role = REVIEWED_LABEL_ROLES.get(label)
        qualified_name = str(candidate.get("qualified_name") or "").strip()
        if role is None or not qualified_name:
            continue
        candidates.append(
            {
                "qualified_name": qualified_name,
                "label": label,
                "role": role,
                "reasoning": str(candidate.get("reasoning") or ""),
            }
        )
    return candidates


def _evidence_for(row: dict[str, Any], candidate: dict[str, str], line_number: int, group_id: str, confidence: str, evidence_level: str) -> dict[str, Any]:
    return {
        "source": ANNOTATION_EVIDENCE_SOURCE,
        "line": line_number,
        "group_id": group_id,
        "mapping_type": row.get("mapping_type"),
        "candidate_label": candidate["label"],
        "reasoning": candidate["reasoning"],
        "confidence": confidence,
        "evidence_level": evidence_level,
        "summary": row.get("summary") or "",
        "annotation_note": row.get("annotation_note") or "",
        "model": row.get("model") or "",
        "annotation_ts": row.get("annotation_ts"),
        "prompt_chars": row.get("prompt_chars"),
    }


def _role_priority(role: str) -> int:
    return {"root_cause": 3, "usage_site": 2, "sink": 1}.get(role, 0)


def _merge_evidence(existing: list[Any], new_item: dict[str, Any]) -> tuple[list[Any], bool]:
    merged = list(existing or [])
    encoded = {json.dumps(item, sort_keys=True, default=str) for item in merged}
    new_encoded = json.dumps(new_item, sort_keys=True, default=str)
    if new_encoded in encoded:
        return merged, False
    merged.append(new_item)
    return merged, True


def _upsert_entity(
    session: Session,
    *,
    advisory: m.Advisory,
    affected: m.AdvisoryAffectedPackage,
    name: str,
    role: str,
    confidence: float,
    evidence: dict[str, Any],
) -> str:
    entity = _entity_for(session, advisory, affected.package_name, name)
    if entity is None:
        session.add(
            m.VulnerableEntity(
                advisory_id=advisory.id,
                affected_package_id=affected.id,
                package_name=affected.package_name,
                name=name,
                entity_type="function",
                role=role,
                confidence=confidence,
                evidence=[evidence],
            )
        )
        session.commit()
        return "inserted"

    changed = False
    if entity.affected_package_id != affected.id:
        entity.affected_package_id = affected.id
        changed = True
    if entity.entity_type != "function":
        entity.entity_type = "function"
        changed = True
    if confidence > entity.confidence:
        entity.confidence = confidence
        changed = True
    if _role_priority(role) > _role_priority(entity.role):
        entity.role = role
        changed = True
    merged_evidence, evidence_changed = _merge_evidence(entity.evidence, evidence)
    if evidence_changed:
        entity.evidence = merged_evidence
        changed = True
    if changed:
        session.commit()
        return "updated"
    return "unchanged"


def _ensure_advisory_and_package(session: Session, cve_id: str, package: str) -> tuple[m.Advisory | None, m.AdvisoryAffectedPackage | None, bool]:
    advisory = _advisory_for_cve(session, cve_id)
    if advisory is not None:
        affected = _affected_package_for(session, advisory, package)
        if affected is not None:
            return advisory, affected, False

    payload = _fetch_osv_by_cve(cve_id)
    if payload is None:
        return advisory, None, False

    _ingest_osv_preserving_annotations(session, cve_id, payload)
    advisory = _advisory_for_cve(session, cve_id)
    if advisory is None:
        return None, None, True
    affected = _ensure_package_metadata(session, advisory, payload, package)
    return advisory, affected, True


def import_vf_annotations(
    session: Session,
    path: Path,
    *,
    min_confidence: str = "high",
    evidence_level: str = "patch_verified",
    source: str = "osv",
    packages: set[str] | None = None,
    cve_ids: set[str] | None = None,
) -> AnnotationImportResult:
    """Import reviewed VF annotations and attach them to real advisory/package rows."""
    if source.lower() != "osv":
        raise ValueError(f"Unsupported annotation advisory source: {source}")
    minimum = CONFIDENCE_SCORE.get(min_confidence.lower())
    if minimum is None:
        raise ValueError(f"Unsupported min confidence: {min_confidence}")
    package_filter = {normalize_name(item) for item in packages or set()}
    cve_filter = {item.upper() for item in cve_ids or set()}

    result = AnnotationImportResult()
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            result.rows_read += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                result.skip("invalid_json")
                continue
            group_id = str(row.get("group_id") or "")
            if "::" not in group_id:
                result.skip("missing_group_id")
                continue
            cve_id, package = group_id.split("::", 1)
            if package_filter and normalize_name(package) not in package_filter:
                result.skip("package_filter")
                continue
            if cve_filter and cve_id.upper() not in cve_filter:
                result.skip("cve_filter")
                continue
            confidence = str(row.get("confidence") or "").lower()
            score = CONFIDENCE_SCORE.get(confidence, 0.0)
            if score < minimum:
                result.skip("low_confidence")
                continue
            if str(row.get("evidence_level") or "") != evidence_level:
                result.skip("evidence_filter")
                continue
            candidates = _reviewed_candidates(row)
            if not candidates:
                result.skip("missing_vf")
                continue
            result.eligible_rows += 1

            advisory, affected, imported_advisory = _ensure_advisory_and_package(session, cve_id, package)
            if imported_advisory:
                result.imported_advisories += 1
            if advisory is None:
                result.skip("advisory_not_persisted")
                continue
            if affected is None:
                result.skip("osv_not_found" if _advisory_for_cve(session, cve_id) is None else "package_not_affected")
                continue

            for candidate in candidates:
                action = _upsert_entity(
                    session,
                    advisory=advisory,
                    affected=affected,
                    name=candidate["qualified_name"],
                    role=candidate["role"],
                    confidence=score,
                    evidence=_evidence_for(row, candidate, line_number, group_id, confidence, evidence_level),
                )
                if action == "inserted":
                    result.imported_entities += 1
                elif action == "updated":
                    result.updated_entities += 1
    return result
