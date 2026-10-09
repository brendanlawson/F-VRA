from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "experiments"))

from f_vra.analysis.dependencies.resolver import resolve_dependency_graph_from_runtime
from f_vra.runtime.conda import RuntimeEnvironment, RuntimePackage, select_python_version
from f_vra.runtime.closure import build_dependency_closure
from run_conda_cve_vf_rebuild import _map_target_import_root


def test_python_selection_honors_project_metadata(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.13,<3.14"\n', encoding="utf-8")
    assert select_python_version(tmp_path, ["3.14", "3.13", "3.12"]) == "3.13"


def test_python_selection_intersects_pyproject_and_lock_constraints(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.11"\n', encoding="utf-8")
    (tmp_path / "uv.lock").write_text('version = 1\nrequires-python = ">=3.11, <3.14"\n', encoding="utf-8")
    assert select_python_version(tmp_path, ["3.14", "3.13", "3.12"]) == "3.13"


def test_uv_closure_applies_markers_and_transitive_edges(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        """
version = 1
requires-python = ">=3.11, <3.14"

[[package]]
name = "root"
version = "1.0.0"
dependencies = [
    { name = "base" },
    { name = "future-only", marker = "python_full_version >= '3.13'" },
]

[[package]]
name = "base"
version = "2.0.0"
dependencies = [{ name = "leaf" }]

[[package]]
name = "leaf"
version = "3.0.0"

[[package]]
name = "future-only"
version = "4.0.0"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    closure = build_dependency_closure("demo", tmp_path, ["root"], python_version="3.12.9")
    assert [item.normalized_name for item in closure.packages] == ["base", "leaf", "root"]
    assert "future-only" not in closure.package_names
    assert closure.install_requirements == ("base==2.0.0", "leaf==3.0.0", "root==1.0.0")


def test_runtime_graph_has_one_record_per_captured_distribution(tmp_path: Path) -> None:
    package = RuntimePackage(
        name="Requests",
        normalized_name="requests",
        version="2.32.5",
        source_path=str(tmp_path / "requests"),
        import_roots=("requests",),
        python_source=True,
        source_fingerprint="source-a",
        requires_dist=("urllib3<3,>=1.21.1",),
    )
    runtime = RuntimeEnvironment(
        project_id="project-a",
        project_path=str(tmp_path),
        prefix=str(tmp_path / "env"),
        python_executable=str(tmp_path / "env" / "python.exe"),
        python_version="3.12.1",
        fingerprint="environment-a",
        packages=(package,),
    )
    graph = resolve_dependency_graph_from_runtime(tmp_path, runtime)
    assert [(item.normalized_name, item.version) for item in graph.dependencies] == [("requests", "2.32.5")]
    assert graph.fingerprint.config_hash == "environment-a"
    assert graph.dependencies[0].dependencies == ["urllib3"]


def test_runtime_serialization_preserves_environment_identity(tmp_path: Path) -> None:
    runtime = RuntimeEnvironment(
        project_id="project-a",
        project_path=str(tmp_path),
        prefix=str(tmp_path / "env"),
        python_executable=str(tmp_path / "env" / "python.exe"),
        python_version="3.12.1",
        fingerprint="environment-a",
        packages=(RuntimePackage("requests", "requests", "2.32.5"),),
        conda_packages=({"name": "python", "version": "3.12.1"},),
        pip_inspect={"installed": []},
    )
    restored = RuntimeEnvironment.from_json(runtime.to_json())
    assert restored == runtime


def test_runtime_import_root_mapping_handles_known_distribution_aliases(tmp_path: Path) -> None:
    runtime = RuntimeEnvironment(
        project_id="project-a",
        project_path=str(tmp_path),
        prefix=str(tmp_path / "env"),
        python_executable=str(tmp_path / "env" / "python.exe"),
        python_version="3.13.1",
        fingerprint="environment-a",
        packages=(
            RuntimePackage("PyJWT", "pyjwt", "2.10.1", import_roots=("jwt",)),
            RuntimePackage("python-multipart", "python-multipart", "0.0.20", import_roots=("multipart",)),
            RuntimePackage("protobuf", "protobuf", "6.33.1", import_roots=("google",)),
            RuntimePackage("langchain-core", "langchain-core", "1.0.0", import_roots=("langchain_core",)),
            RuntimePackage("PyMuPDF", "pymupdf", "1.24.11", import_roots=("fitz",)),
        ),
    )
    cases = {
        ("pyjwt", "pyjwt.api_jws.PyJWS._load"): "jwt.api_jws.PyJWS._load",
        ("python-multipart", "python_multipart.multipart.File.__init__"): "multipart.multipart.File.__init__",
        ("protobuf", "python.google.protobuf.json_format._Parser._ConvertAnyMessage"): "google.protobuf.json_format._Parser._ConvertAnyMessage",
        ("langchain-core", "libs.core.langchain_core.prompts.string.check_valid_template"): "langchain_core.prompts.string.check_valid_template",
        ("pymupdf", "src.__main__.embedded_get"): "fitz.__main__.embedded_get",
    }
    for (package, target), expected in cases.items():
        assert _map_target_import_root(target, package, runtime)[0] == expected
