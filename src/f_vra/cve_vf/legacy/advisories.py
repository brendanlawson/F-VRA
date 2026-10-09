from __future__ import annotations

import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable

import requests
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from f_vra_server_db import models as m
from f_vra_server_db.repository import normalize_name


def _sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _alias_type(alias: str) -> str:
    prefix = alias.split("-", 1)[0].upper()
    return prefix if prefix in {"CVE", "GHSA", "OSV", "PYSEC", "SNYK"} else ""


def _severity_label(score: float | None, raw: str = "") -> str:
    lowered = raw.lower()
    if lowered in {"critical", "high", "medium", "low"}:
        return lowered.title()
    if score is None:
        return ""
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def _score_from_vector(vector: str) -> float | None:
    return None


def _upsert_raw(session: Session, *, source: str, record_id: str, payload: dict[str, Any]) -> None:
    digest = _sha256(payload)
    existing = session.scalars(
        select(m.RawAdvisorySource).where(
            m.RawAdvisorySource.source == source,
            m.RawAdvisorySource.source_record_id == record_id,
            m.RawAdvisorySource.sha256 == digest,
        )
    ).first()
    if existing is None:
        session.add(
            m.RawAdvisorySource(
                source=source,
                source_record_id=record_id,
                raw_payload=payload,
                sha256=digest,
            )
        )


def _upsert_advisory(session: Session, *, canonical_id: str, title: str, description: str, published: str | None, modified: str | None, withdrawn: str | None) -> m.Advisory:
    advisory = session.scalars(select(m.Advisory).where(m.Advisory.canonical_id == canonical_id)).first()
    if advisory is None:
        advisory = m.Advisory(canonical_id=canonical_id)
        session.add(advisory)
        session.flush()
    advisory.title = title[:512]
    advisory.description = description or title
    advisory.published_at = _parse_dt(published)
    advisory.modified_at = _parse_dt(modified)
    advisory.withdrawn_at = _parse_dt(withdrawn)
    advisory.status = "withdrawn" if advisory.withdrawn_at else "active"
    return advisory


def _replace_aliases(session: Session, advisory: m.Advisory, aliases: Iterable[str]) -> None:
    session.execute(delete(m.AdvisoryAlias).where(m.AdvisoryAlias.advisory_id == advisory.id))
    for alias in sorted({item for item in aliases if item}):
        session.add(m.AdvisoryAlias(advisory_id=advisory.id, alias=alias, alias_type=_alias_type(alias)))


def _replace_references(session: Session, advisory: m.Advisory, references: list[dict[str, Any]]) -> None:
    session.execute(delete(m.AdvisoryReference).where(m.AdvisoryReference.advisory_id == advisory.id))
    for ref in references:
        url = str(ref.get("url") or ref.get("html_url") or "")
        if not url:
            continue
        session.add(
            m.AdvisoryReference(
                advisory_id=advisory.id,
                url=url,
                source=str(ref.get("source") or ""),
                reference_type=str(ref.get("type") or ""),
                tags=ref.get("tags") or [],
            )
        )


def _replace_severity(session: Session, advisory: m.Advisory, severities: list[dict[str, Any]]) -> None:
    session.execute(delete(m.SeverityRecord).where(m.SeverityRecord.advisory_id == advisory.id))
    for item in severities:
        vector = str(item.get("score") or item.get("cvss_v3") or item.get("cvss_v4") or "")
        score = item.get("numeric_score")
        if score is not None:
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = None
        session.add(
            m.SeverityRecord(
                advisory_id=advisory.id,
                source=str(item.get("source") or "advisory"),
                severity_type=str(item.get("type") or item.get("severity_type") or ""),
                vector=vector,
                score=score,
                severity=_severity_label(score, str(item.get("severity") or "")),
            )
        )


def _replace_weaknesses(session: Session, advisory: m.Advisory, weaknesses: Iterable[str]) -> None:
    session.execute(delete(m.WeaknessRecord).where(m.WeaknessRecord.advisory_id == advisory.id))
    for cwe in sorted({item for item in weaknesses if item}):
        session.add(m.WeaknessRecord(advisory_id=advisory.id, cwe_id=cwe, source="advisory"))


def _range_versions(events: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    affected: list[str] = []
    fixed: list[str] = []
    for event in events:
        if "introduced" in event and event["introduced"] not in {"0", ""}:
            affected.append(f">={event['introduced']}")
        if "fixed" in event:
            fixed.append(str(event["fixed"]))
        if "last_affected" in event:
            affected.append(f"<={event['last_affected']}")
    return affected, fixed


def ingest_osv_record(session: Session, payload: dict[str, Any]) -> str:
    canonical_id = str(payload.get("id") or "")
    if not canonical_id:
        raise ValueError("OSV advisory has no id")
    _upsert_raw(session, source="osv", record_id=canonical_id, payload=payload)
    aliases = [canonical_id, *payload.get("aliases", [])]
    advisory = _upsert_advisory(
        session,
        canonical_id=canonical_id,
        title=payload.get("summary") or canonical_id,
        description=payload.get("details") or payload.get("summary") or canonical_id,
        published=payload.get("published"),
        modified=payload.get("modified"),
        withdrawn=payload.get("withdrawn"),
    )
    _replace_aliases(session, advisory, aliases)
    _replace_references(session, advisory, payload.get("references") or [])
    _replace_severity(session, advisory, payload.get("severity") or [])
    _replace_weaknesses(session, advisory, payload.get("database_specific", {}).get("cwe_ids") or [])

    session.execute(delete(m.VulnerableEntity).where(m.VulnerableEntity.advisory_id == advisory.id))
    session.execute(delete(m.AdvisoryAffectedPackage).where(m.AdvisoryAffectedPackage.advisory_id == advisory.id))
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for affected in payload.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "PyPI").lower()
        package_name = str(package.get("name") or "")
        if ecosystem not in {"pypi", "pip"} or not package_name:
            continue
        normalized = normalize_name(package_name)
        group = grouped.setdefault(
            ("pypi", normalized),
            {
                "package_name": package_name,
                "affected_versions": set(),
                "fixed_versions": set(),
                "ranges": [],
                "functions": set(),
            },
        )
        affected_versions = [str(item) for item in affected.get("versions") or []]
        fixed_versions: list[str] = []
        for range_item in affected.get("ranges") or []:
            events = range_item.get("events") or []
            range_affected, range_fixed = _range_versions(events)
            affected_versions.extend(range_affected)
            fixed_versions.extend(range_fixed)
            group["ranges"].append(range_item)
        group["affected_versions"].update(item for item in affected_versions if item)
        group["fixed_versions"].update(item for item in fixed_versions if item)
        group["functions"].update(str(symbol) for symbol in affected.get("database_specific", {}).get("functions") or [] if str(symbol))

    for (_ecosystem, normalized), group in grouped.items():
        package_name = str(group["package_name"])
        row = m.AdvisoryAffectedPackage(
            advisory_id=advisory.id,
            ecosystem="pypi",
            package_name=package_name,
            normalized_name=normalized,
            affected_versions=sorted(group["affected_versions"]),
            fixed_versions=sorted(group["fixed_versions"]),
        )
        session.add(row)
        session.flush()
        for range_item in group["ranges"]:
            session.add(
                m.AffectedRange(
                    affected_package_id=row.id,
                    range_type=str(range_item.get("type") or "ECOSYSTEM"),
                    repo_url=str(range_item.get("repo") or ""),
                    events=range_item.get("events") or [],
                )
            )
        for symbol in sorted(group["functions"]):
            session.add(
                m.VulnerableEntity(
                    advisory_id=advisory.id,
                    affected_package_id=row.id,
                    package_name=package_name,
                    name=str(symbol),
                    confidence=0.7,
                    evidence=[{"source": "osv.database_specific.functions"}],
                )
            )
    session.commit()
    return canonical_id


def ingest_ghsa_record(session: Session, payload: dict[str, Any]) -> str:
    ghsa_id = str(payload.get("ghsa_id") or payload.get("id") or "")
    cve_id = str(payload.get("cve_id") or "")
    canonical_id = cve_id or ghsa_id
    if not canonical_id:
        raise ValueError("GHSA advisory has no id")
    _upsert_raw(session, source="ghsa", record_id=ghsa_id or canonical_id, payload=payload)
    advisory = _upsert_advisory(
        session,
        canonical_id=canonical_id,
        title=payload.get("summary") or canonical_id,
        description=payload.get("description") or payload.get("summary") or canonical_id,
        published=payload.get("published_at"),
        modified=payload.get("updated_at"),
        withdrawn=payload.get("withdrawn_at"),
    )
    _replace_aliases(session, advisory, [item for item in (canonical_id, cve_id, ghsa_id) if item])
    _replace_references(session, advisory, [{"url": payload.get("html_url"), "type": "ADVISORY"}])
    cvss = payload.get("cvss") or {}
    _replace_severity(
        session,
        advisory,
        [{"source": "ghsa", "type": "CVSS", "score": cvss.get("vector_string"), "numeric_score": cvss.get("score")}],
    )
    cwes = [item.get("cwe_id") for item in payload.get("cwes") or [] if isinstance(item, dict)]
    _replace_weaknesses(session, advisory, cwes)

    session.execute(delete(m.AdvisoryAffectedPackage).where(m.AdvisoryAffectedPackage.advisory_id == advisory.id))
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for vuln in payload.get("vulnerabilities") or []:
        package_name = str(vuln.get("package", {}).get("name") or "")
        ecosystem = str(vuln.get("package", {}).get("ecosystem") or "").lower()
        if ecosystem != "pip" or not package_name:
            continue
        vulnerable_range = str(vuln.get("vulnerable_version_range") or "")
        patched_raw = vuln.get("first_patched_version")
        if isinstance(patched_raw, dict):
            patched = str(patched_raw.get("identifier") or "")
        else:
            patched = str(patched_raw or "")
        normalized = normalize_name(package_name)
        group = grouped.setdefault(
            ("pypi", normalized),
            {
                "package_name": package_name,
                "affected_versions": set(),
                "fixed_versions": set(),
            },
        )
        if vulnerable_range:
            group["affected_versions"].add(vulnerable_range)
        if patched:
            group["fixed_versions"].add(patched)

    for (_ecosystem, normalized), group in grouped.items():
        session.add(
            m.AdvisoryAffectedPackage(
                advisory_id=advisory.id,
                ecosystem="pypi",
                package_name=str(group["package_name"]),
                normalized_name=normalized,
                affected_versions=sorted(group["affected_versions"]),
                fixed_versions=sorted(group["fixed_versions"]),
            )
        )
    session.commit()
    return canonical_id


def fetch_osv(ecosystem: str = "PyPI", limit: int = 500) -> list[dict[str, Any]]:
    ecosystem_path = ecosystem if ecosystem == "[EMPTY]" else ecosystem[:1].upper() + ecosystem[1:]
    index_url = f"https://storage.googleapis.com/osv-vulnerabilities/{ecosystem_path}/modified_id.csv"
    response = requests.get(index_url, timeout=30)
    response.raise_for_status()
    rows = [
        row
        for row in csv.reader(response.text.splitlines())
        if len(row) >= 2 and row[1].strip()
    ]
    rows.sort(key=lambda row: row[0], reverse=True)
    records: list[dict[str, Any]] = []
    for _modified_at, osv_id in rows[:limit]:
        osv_id = osv_id.strip().removesuffix(".json")
        if not osv_id:
            continue
        detail = requests.get(f"https://api.osv.dev/v1/vulns/{osv_id}", timeout=30)
        detail.raise_for_status()
        records.append(detail.json())
    return records


def fetch_ghsa(ecosystem: str = "pip", limit: int = 500) -> list[dict[str, Any]]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(
        "https://api.github.com/advisories",
        params={"ecosystem": ecosystem, "per_page": min(limit, 100)},
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    return list(response.json())[:limit]


def sync_advisories(session: Session, *, source: str, ecosystem: str = "pypi", limit: int = 500) -> int:
    source = source.lower()
    if source == "osv":
        records = fetch_osv("PyPI" if ecosystem.lower() == "pypi" else ecosystem, limit=limit)
        for record in records:
            ingest_osv_record(session, record)
        return len(records)
    if source == "ghsa":
        records = fetch_ghsa("pip" if ecosystem.lower() == "pypi" else ecosystem, limit=limit)
        for record in records:
            ingest_ghsa_record(session, record)
        return len(records)
    raise ValueError(f"Unsupported advisory source: {source}")
