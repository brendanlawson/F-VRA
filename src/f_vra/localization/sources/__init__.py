from f_vra.localization.sources.metadata import (
    ResolvedMetadata,
    download_patch,
    resolve_metadata,
    resolve_nvd,
    resolve_osv,
)
from f_vra.localization.sources.patch import (
    PatchAnalysis,
    PatchFileChange,
    load_patch,
    parse_patch_text,
)
from f_vra.localization.sources.repositories import (
    clone_or_update,
    github_commit_from_reference,
    github_commit_from_references,
    github_repo_url_from_reference,
    github_repo_urls_from_references,
)

__all__ = [
    "PatchAnalysis",
    "PatchFileChange",
    "ResolvedMetadata",
    "clone_or_update",
    "download_patch",
    "github_commit_from_reference",
    "github_commit_from_references",
    "github_repo_url_from_reference",
    "github_repo_urls_from_references",
    "load_patch",
    "parse_patch_text",
    "resolve_metadata",
    "resolve_nvd",
    "resolve_osv",
]
