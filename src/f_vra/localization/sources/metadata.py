from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import requests

from f_vra.localization.models import MetadataSource


@dataclass
class ResolvedMetadata:
    cve_id: str | None
    description: str = ""
    cwe_id: str | None = None
    references: list[str] = field(default_factory=list)
    patch_urls: list[str] = field(default_factory=list)
    source: MetadataSource = "unknown"
    raw: dict[str, Any] = field(default_factory=dict)


def _looks_like_patch(url: str) -> bool:
    lowered = url.lower()
    return (
        lowered.endswith((".patch", ".diff"))
        or "/commit/" in lowered
        or "/pull/" in lowered
        or "patch" in lowered
    )


def _get_json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
    except (requests.RequestException, ValueError):
        return None
    return None


def resolve_osv(cve_id: str) -> ResolvedMetadata | None:
    data = _get_json(f"https://api.osv.dev/v1/vulns/{cve_id}")
    if not data:
        return None
    references = [item.get("url", "") for item in data.get("references", []) if item.get("url")]
    aliases = data.get("aliases", [])
    resolved_cve = next((alias for alias in aliases if alias.startswith("CVE-")), cve_id)
    return ResolvedMetadata(
        cve_id=resolved_cve,
        description=data.get("details") or data.get("summary") or "",
        references=references,
        patch_urls=[url for url in references if _looks_like_patch(url)],
        source="OSV",
        raw=data,
    )


def resolve_nvd(cve_id: str) -> ResolvedMetadata | None:
    headers = {}
    if key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = key
    data = _get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers=headers,
    )
    vulnerabilities = (data or {}).get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
        "",
    )
    references = [item.get("url", "") for item in cve.get("references", []) if item.get("url")]
    weaknesses = cve.get("weaknesses", [])
    cwe_id = None
    for weakness in weaknesses:
        for item in weakness.get("description", []):
            value = item.get("value", "")
            if value.startswith("CWE-"):
                cwe_id = value
                break
    return ResolvedMetadata(
        cve_id=cve_id,
        description=description,
        cwe_id=cwe_id,
        references=references,
        patch_urls=[url for url in references if _looks_like_patch(url)],
        source="NVD",
        raw=cve,
    )


def resolve_metadata(cve_id: str) -> ResolvedMetadata:
    return resolve_osv(cve_id) or resolve_nvd(cve_id) or ResolvedMetadata(cve_id=cve_id)


def download_patch(url: str) -> tuple[str, str] | None:
    headers = {"Accept": "application/vnd.github.patch"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    urls = [url]
    lowered = url.lower().rstrip("/")
    if "github.com/" in lowered and ("/commit/" in lowered or "/pull/" in lowered):
        if not lowered.endswith((".patch", ".diff")):
            urls.insert(0, url.rstrip("/") + ".patch")

    for candidate_url in urls:
        try:
            response = requests.get(candidate_url, headers=headers, timeout=20)
            if response.status_code == 200 and "@@" in response.text:
                return response.text, candidate_url
        except requests.RequestException:
            continue
    return None
