from f_vra.core.models import ExternalNode, LibrarySummary
from f_vra.reachability.engine import ReachabilityQueryEngine


def test_reachability_matches_direct_vulnerable_usage():
    ui = [
        ExternalNode(
            file_path="<external:requests>",
            function_name="requests.get",
            qualified_name="requests.get",
            target_module="requests",
            target_name="get",
        )
    ]

    report = ReachabilityQueryEngine(ui, {}, {"requests.get"}).check_reachability()

    assert report.is_vulnerable is True
    assert report.paths[0].tpl_chain == ["requests.get"]


def test_reachability_expands_library_summary_outer_reach():
    ui = [
        ExternalNode(
            file_path="<external:sample>",
            function_name="sample.public_api",
            qualified_name="sample.public_api",
            target_module="sample",
            target_name="public_api",
        )
    ]
    summary = LibrarySummary(
        inner_summary={"sample.public_api": {"sample.Client.fetch"}},
        outer_summary={"sample.public_api": {"requests.get"}},
    )

    report = ReachabilityQueryEngine(ui, {"sample": summary}, {"requests.get"}).check_reachability()

    assert report.is_vulnerable is True
    assert report.paths[0].tpl_chain == ["sample.public_api", "requests.get"]


def test_reachability_follows_transitive_outer_summaries():
    ui = [
        ExternalNode(
            file_path="<external:mocklib_a>",
            function_name="mocklib_a.safe_entry",
            qualified_name="mocklib_a.safe_entry",
            target_module="mocklib_a",
            target_name="safe_entry",
        )
    ]
    summaries = {
        "mocklib_a": LibrarySummary(
            outer_summary={"mocklib_a.safe_entry": {"mocklib_b.bridge"}},
        ),
        "mocklib_b": LibrarySummary(
            outer_summary={"mocklib_b.bridge": {"mockvuln.dangerous_sink"}},
        ),
    }

    report = ReachabilityQueryEngine(
        ui,
        summaries,
        {"mockvuln.dangerous_sink"},
    ).check_reachability()

    assert report.is_vulnerable is True
    assert report.paths[0].tpl_chain == [
        "mocklib_a.safe_entry",
        "mocklib_b.bridge",
        "mockvuln.dangerous_sink",
    ]
