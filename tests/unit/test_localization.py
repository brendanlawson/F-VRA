from pathlib import Path

from typer.testing import CliRunner

from f_vra.cli.main import app
from f_vra.localization.retrieval.candidates import select_patch_absent
from f_vra.localization.retrieval.embedding import OpenAICompatibleEmbeddingBackend
from f_vra.localization.code.function_parser import parse_repo
from f_vra.localization.code.function_parser import parse_repository
from f_vra.localization.sources.metadata import ResolvedMetadata, download_patch
from f_vra.localization.models import LocalizationRequest
from f_vra.localization.sources.repositories import github_repo_url_from_reference
from f_vra.localization.service import localize, localize_vulnerable_functions

runner = CliRunner()


def test_parse_repo_extracts_python_functions():
    funcs = parse_repo("tests/fixtures/sample_app")

    qualnames = {func["qualname"] for func in funcs}

    assert {"main", "public_api", "unused_api", "Client.fetch"} <= qualnames


def test_localize_ranks_candidate_functions_with_fallback_retrieval():
    result = localize(
        "CVE-X",
        description="request fetch url using requests get",
        repo_path="tests/fixtures/sample_app",
        top_k=3,
    )

    assert result.mode == "PATCH_ABSENT"
    assert result.vf == "Client.fetch"
    assert "Client.fetch" in result.candidates


def test_hybrid_retrieval_uses_embedding_signal(monkeypatch):
    functions = parse_repository("tests/fixtures/sample_app")
    fetch_id = next(item.identity for item in functions if item.qualname == "Client.fetch")

    monkeypatch.setattr(
        "f_vra.localization.retrieval.candidates.lexical_scores",
        lambda description, items: {item.identity: 0.0 for item in items},
    )
    monkeypatch.setattr(
        "f_vra.localization.retrieval.candidates.embedding_scores",
        lambda description, items: (
            {
                item.identity: 0.95 if item.identity == fetch_id else 0.05
                for item in items
            },
            "test-light-model",
        ),
    )

    selection = select_patch_absent(
        "credentials escape across a redirected secure connection",
        functions,
        pool_size=4,
        use_embeddings=True,
    )

    assert selection.candidates[0].qualname == "Client.fetch"
    assert selection.embedding_model == "test-light-model"
    assert selection.embedding_status == "used"
    assert selection.relevance_scores[fetch_id] == 1.0
    assert selection.relevance_scores[fetch_id] > selection.relevance_scores[
        next(item.identity for item in functions if item.qualname == "main")
    ]


def test_embedding_failure_falls_back_to_bm25(monkeypatch):
    functions = parse_repository("tests/fixtures/sample_app")

    def fail_embedding(description, items):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(
        "f_vra.localization.retrieval.candidates.embedding_scores",
        fail_embedding,
    )

    selection = select_patch_absent(
        "request fetch url using requests get",
        functions,
        use_embeddings=True,
    )

    assert selection.candidates[0].qualname == "Client.fetch"
    assert selection.embedding_scores == {}
    assert selection.embedding_status == "fallback: model unavailable"


def test_local_embedding_backend_batches_and_orders_vectors(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0]},
                    {"index": 0, "embedding": [1.0, 0.0]},
                ]
            }

    monkeypatch.setattr(
        "f_vra.localization.retrieval.embedding.settings.local_embedding_api_key",
        "test-key",
    )
    monkeypatch.setattr(
        "f_vra.localization.retrieval.embedding.settings.local_embedding_base_url",
        "https://quatmo-api.iahn.hanoi.vn/v1",
    )

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("f_vra.localization.retrieval.embedding.requests.post", fake_post)

    backend = OpenAICompatibleEmbeddingBackend(
        model_name="qwen3-embedding",
        api_key="test-key",
        base_url="https://quatmo-api.iahn.hanoi.vn/v1",
        provider_name="local",
    )
    vectors = backend.embed(["query", "function"])

    assert vectors == [[1.0, 0.0], [0.0, 1.0]]
    assert captured["url"] == "https://quatmo-api.iahn.hanoi.vn/v1/embeddings"
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["json"]["input"] == ["query", "function"]
    assert captured["json"]["model"] == "qwen3-embedding"


def test_patch_absent_report_has_product_schema():
    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            cve_description="HTTP request can hang without a timeout",
            cwe_id="CWE-400",
            repository_path=Path("tests/fixtures/sample_app"),
            top_k=3,
        )
    )

    data = report.to_dict()
    assert data["mode"] == "PATCH_ABSENT"
    assert data["metadata_source"] == "manual"
    assert data["patch_source"] is None
    assert len(data["candidates"]) == 3
    assert {
        "rank",
        "score",
        "confidence",
        "function_name",
        "qualname",
        "file_path",
        "start_line",
        "end_line",
        "source_excerpt",
        "why_this_may_be_vulnerable",
        "evidence_used",
    } <= data["candidates"][0].keys()


def test_patch_present_tracks_modified_function_and_callers():
    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            cve_description="HTTP request can hang without a timeout",
            repository_path=Path("tests/fixtures/sample_app"),
            patch_path=Path("tests/fixtures/sample_app/fix.patch"),
            top_k=5,
        )
    )

    by_name = {candidate.qualname: candidate for candidate in report.candidates}
    assert report.mode == "PATCH_PRESENT"
    assert report.patch_source is not None
    assert "Client.fetch" in by_name
    assert any("changed patch lines" in item for item in by_name["Client.fetch"].evidence_used)
    assert "public_api" in by_name
    assert any("patch-related function" in item for item in by_name["public_api"].evidence_used)


def test_auto_resolve_falls_back_to_patch_absent(monkeypatch):
    monkeypatch.setattr(
        "f_vra.localization.service.resolve_metadata",
        lambda cve_id: ResolvedMetadata(
            cve_id=cve_id,
            description="unsafe HTTP request handling",
            source="OSV",
        ),
    )

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            repository_path=Path("tests/fixtures/sample_app"),
            auto_resolve_patch=True,
            top_k=2,
        )
    )

    assert report.mode == "PATCH_ABSENT"
    assert report.metadata_source == "OSV"


def test_auto_clone_inferred_github_repository_when_repository_missing(monkeypatch):
    cloned = {}

    monkeypatch.setattr(
        "f_vra.localization.service.resolve_metadata",
        lambda cve_id: ResolvedMetadata(
            cve_id=cve_id,
            description="unsafe HTTP request handling",
            references=["https://github.com/example/sample_app/commit/abc123"],
            patch_urls=[],
            source="OSV",
        ),
    )

    def fake_clone(repo_url, commit=None):
        cloned["repo_url"] = repo_url
        cloned["commit"] = commit
        return Path("tests/fixtures/sample_app")

    monkeypatch.setattr("f_vra.localization.service.clone_or_update", fake_clone)

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            repository_path=Path("tests/fixtures/not_cloned_yet"),
            top_k=2,
            use_embeddings=False,
        )
    )

    assert cloned["repo_url"] == "https://github.com/example/sample_app.git"
    assert report.mode == "PATCH_ABSENT"
    assert report.metadata["repository_source"] == "https://github.com/example/sample_app.git"
    assert report.repository_path.endswith("tests\\fixtures\\sample_app") or report.repository_path.endswith(
        "tests/fixtures/sample_app"
    )


def test_pairwise_ranking_uses_configured_provider(monkeypatch):
    captured = {}

    monkeypatch.setattr("f_vra.localization.ranking.methods.pairwise.settings.local_llm_api_key", "test-key")
    monkeypatch.setattr("f_vra.localization.ranking.methods.pairwise.settings.local_llm_base_url", "https://llm.test/v1")
    monkeypatch.setattr("f_vra.localization.ranking.methods.pairwise.settings.local_llm_model", "qwen3-coder")

    def fake_chat(messages, model=None, temperature=0.0):
        captured["messages"] = messages
        captured["model"] = model
        captured["temperature"] = temperature
        return "A"

    monkeypatch.setattr("f_vra.localization.providers.llm_client.chat", fake_chat)

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            cve_description="request fetch url using requests get",
            repository_path=Path("tests/fixtures/sample_app"),
            top_k=2,
            use_embeddings=False,
            pairwise=True,
            swiss_rounds=1,
            finalists=2,
        )
    )

    assert captured["messages"][0]["role"] == "system"
    assert captured["model"] == "qwen3-coder"
    assert report.metadata["pairwise_ranking"]["used"] is True
    assert report.metadata["pairwise_ranking"]["source"] == "pairwise_ranking"
    assert "llm_used" not in report.metadata


def test_github_repo_url_from_reference_normalizes_commit_url():
    assert (
        github_repo_url_from_reference("https://github.com/psf/requests/commit/abc123")
        == "https://github.com/psf/requests.git"
    )


def test_download_patch_uses_github_patch_endpoint(monkeypatch):
    requested_urls = []

    class Response:
        status_code = 200
        text = "@@ -1 +1 @@\n-old\n+new\n"

    def fake_get(url, **kwargs):
        requested_urls.append(url)
        return Response()

    monkeypatch.setattr("f_vra.localization.sources.metadata.requests.get", fake_get)

    downloaded = download_patch("https://github.com/example/project/commit/abc123")

    assert downloaded is not None
    assert downloaded[1].endswith("/commit/abc123.patch")
    assert requested_urls == ["https://github.com/example/project/commit/abc123.patch"]


def test_localization_parse_diagnostic_runs():
    result = runner.invoke(
        app,
        [
            "localization",
            "parse",
            "--repository",
            "tests/fixtures/sample_app",
            "--limit",
            "2",
        ],
    )

    assert result.exit_code == 0
    assert '"functions_found": 4' in result.stdout
    assert '"qualname": "main"' in result.stdout


def test_localization_patch_and_tracker_diagnostics_run():
    patch_result = runner.invoke(
        app,
        [
            "localization",
            "patch",
            "--patch",
            "tests/fixtures/sample_app/fix.patch",
        ],
    )
    tracker_result = runner.invoke(
        app,
        [
            "localization",
            "track",
            "--repository",
            "tests/fixtures/sample_app",
            "--patch",
            "tests/fixtures/sample_app/fix.patch",
        ],
    )

    assert patch_result.exit_code == 0
    assert '"status": "ok"' in patch_result.stdout
    assert '"file_path": "pkg/lib.py"' in patch_result.stdout
    assert tracker_result.exit_code == 0
    assert '"qualname": "Client.fetch"' in tracker_result.stdout
    assert '"qualname": "public_api"' in tracker_result.stdout
