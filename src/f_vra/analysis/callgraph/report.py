from __future__ import annotations

from typing import Any

from f_vra.core.models import CallGraph


def node_name(node: Any) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def edge_dict(edge: Any) -> dict[str, Any]:
    return {
        "caller": node_name(edge.caller),
        "callee": node_name(edge.callee),
        "callee_type": "external" if edge.callee.is_external else "internal",
        "edge_type": getattr(edge, "edge_type", "confirmed_static"),
        "confidence": getattr(edge, "confidence", 1.0),
        "resolver": getattr(edge, "resolver", "static"),
        "reason": getattr(edge, "reason", ""),
        "call_expr": getattr(edge, "call_expr", ""),
        "line_number": getattr(edge, "line_number", 0),
    }


def graph_report_edges(graph: CallGraph) -> list[dict[str, Any]]:
    return [edge_dict(edge) for edge in graph.edges]
