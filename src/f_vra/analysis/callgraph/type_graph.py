from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class IdentifierKind(str, Enum):
    MODULE = "module"
    EXTERNAL_MODULE = "external_module"
    EXTERNAL = "external"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    ATTRIBUTE = "attribute"
    LITERAL = "literal"
    UNKNOWN = "unknown"


class TypeGraphRelationKind(str, Enum):
    ASSIGNS_TO = "assigns_to"
    POINTS_TO = "points_to"
    PARAMETER_FLOW = "parameter_flow"
    RETURN_FLOW = "return_flow"
    ATTRIBUTE_FLOW = "attribute_flow"
    IMPORT_ALIAS = "import_alias"
    INHERITS = "inherits"
    CALL_FLOW = "call_flow"
    CALL_RESULT = "call_result"
    DYNAMIC_FLOW = "dynamic_flow"


@dataclass(frozen=True)
class TypeGraphNode:
    kind: IdentifierKind
    name: str
    namespace: str = ""

    @property
    def identity(self) -> str:
        return "::".join(part for part in (self.kind.value, self.namespace, self.name) if part)

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "name": self.name,
            "namespace": self.namespace,
            "identity": self.identity,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TypeGraphNode":
        return cls(
            kind=IdentifierKind(str(data["kind"])),
            name=str(data["name"]),
            namespace=str(data.get("namespace", "")),
        )


@dataclass(frozen=True)
class TypeGraphRelation:
    source: TypeGraphNode
    target: TypeGraphNode
    kind: TypeGraphRelationKind
    location: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "kind": self.kind.value,
            "location": self.location,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TypeGraphRelation":
        return cls(
            source=TypeGraphNode.from_dict(data["source"]),
            target=TypeGraphNode.from_dict(data["target"]),
            kind=TypeGraphRelationKind(str(data["kind"])),
            location=str(data.get("location", "")),
            reason=str(data.get("reason", "")),
        )


@dataclass
class TypeGraphState:
    """Function-local type facts used by the callgraph engine.

    Missing variables mean top/unknown, so callers should keep candidates rather
    than pruning when a lookup returns ``None``.
    """

    bindings: dict[str, set[str]] = field(default_factory=dict)
    relations: list[TypeGraphRelation] = field(default_factory=list)

    def get(self, name: str) -> set[str] | None:
        values = self.bindings.get(name)
        return set(values) if values is not None else None

    def strong_update(self, name: str, types: Iterable[str], *, reason: str = "", location: str = "") -> None:
        values = {item for item in types if item}
        if not values:
            self.bindings.pop(name, None)
            return
        self.bindings[name] = values
        source = TypeGraphNode(IdentifierKind.VARIABLE, name)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=TypeGraphNode(IdentifierKind.CLASS, value),
                    kind=TypeGraphRelationKind.POINTS_TO,
                    location=location,
                    reason=reason,
                )
            )

    def weak_update(self, name: str, types: Iterable[str], *, reason: str = "", location: str = "") -> None:
        current = self.bindings.get(name)
        values = {item for item in types if item}
        if current is None or not values:
            self.bindings.pop(name, None)
            return
        self.strong_update(name, current | values, reason=reason, location=location)

    def set_top(self, name: str) -> None:
        self.bindings.pop(name, None)

    def copy(self) -> "TypeGraphState":
        return TypeGraphState({name: set(values) for name, values in self.bindings.items()}, list(self.relations))

    def to_dict(self) -> dict[str, object]:
        return {
            "bindings": {name: sorted(values) for name, values in sorted(self.bindings.items())},
            "relations": [relation.to_dict() for relation in self.relations],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TypeGraphState":
        return cls(
            bindings={str(name): set(values) for name, values in data.get("bindings", {}).items()},
            relations=[
                TypeGraphRelation.from_dict(item)
                for item in data.get("relations", [])
            ],
        )

    @staticmethod
    def join(left: "TypeGraphState", right: "TypeGraphState") -> "TypeGraphState":
        joined = TypeGraphState()
        for name in left.bindings.keys() & right.bindings.keys():
            joined.bindings[name] = set(left.bindings[name]) | set(right.bindings[name])
        joined.relations = list(left.relations) + list(right.relations)
        return joined


@dataclass
class FunctionTypeGraph:
    function: str
    context: str = "default"
    entry_types: dict[str, set[str]] = field(default_factory=dict)
    return_types: set[str] = field(default_factory=set)
    relations: list[TypeGraphRelation] = field(default_factory=list)

    def record_parameter_flow(self, parameter: str, types: Iterable[str], *, caller: str = "") -> None:
        values = {item for item in types if item}
        if not values:
            return
        self.entry_types.setdefault(parameter, set()).update(values)
        source = TypeGraphNode(IdentifierKind.VARIABLE, parameter, namespace=self.function)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=TypeGraphNode(IdentifierKind.CLASS, value),
                    kind=TypeGraphRelationKind.PARAMETER_FLOW,
                    reason=f"argument propagated from {caller}" if caller else "argument propagated from callsite",
                )
            )

    def record_return_flow(self, types: Iterable[str], *, reason: str = "") -> None:
        values = {item for item in types if item}
        if not values:
            return
        self.return_types.update(values)
        source = TypeGraphNode(IdentifierKind.FUNCTION, self.function)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=TypeGraphNode(IdentifierKind.CLASS, value),
                    kind=TypeGraphRelationKind.RETURN_FLOW,
                    reason=reason,
                )
            )

    def record_assignment_flow(
        self,
        target: str,
        types: Iterable[str],
        *,
        value_expr: str = "",
        location: str = "",
        reason: str = "",
    ) -> None:
        values = {item for item in types if item}
        if not target or not values:
            return
        source = TypeGraphNode(_node_kind_for_name(target), target, namespace=self.function)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=_type_node(value),
                    kind=TypeGraphRelationKind.ASSIGNS_TO,
                    location=location,
                    reason=reason or (f"assigned from {value_expr}" if value_expr else "assignment"),
                )
            )

    def record_attribute_flow(
        self,
        attribute: str,
        types: Iterable[str],
        *,
        location: str = "",
        reason: str = "",
    ) -> None:
        values = {item for item in types if item}
        if not attribute or not values:
            return
        source = TypeGraphNode(IdentifierKind.ATTRIBUTE, attribute, namespace=self.function)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=_type_node(value),
                    kind=TypeGraphRelationKind.ATTRIBUTE_FLOW,
                    location=location,
                    reason=reason or "attribute/field flow",
                )
            )

    def record_import_alias(
        self,
        alias: str,
        target: str,
        *,
        location: str = "",
        reason: str = "",
    ) -> None:
        if not alias or not target:
            return
        self.relations.append(
            TypeGraphRelation(
                source=TypeGraphNode(IdentifierKind.VARIABLE, alias, namespace=self.function),
                target=TypeGraphNode(IdentifierKind.MODULE, target),
                kind=TypeGraphRelationKind.IMPORT_ALIAS,
                location=location,
                reason=reason or "import alias",
            )
        )

    def record_call_result(
        self,
        call_expr: str,
        types: Iterable[str],
        *,
        location: str = "",
        reason: str = "",
    ) -> None:
        values = {item for item in types if item}
        if not call_expr or not values:
            return
        source = TypeGraphNode(IdentifierKind.FUNCTION, call_expr, namespace=self.function)
        for value in sorted(values):
            self.relations.append(
                TypeGraphRelation(
                    source=source,
                    target=_type_node(value),
                    kind=TypeGraphRelationKind.CALL_RESULT,
                    location=location,
                    reason=reason or "call result flow",
                )
            )

    def record_dynamic_flow(
        self,
        expression: str,
        *,
        location: str = "",
        reason: str = "",
    ) -> None:
        if not expression:
            return
        self.relations.append(
            TypeGraphRelation(
                source=TypeGraphNode(IdentifierKind.UNKNOWN, expression, namespace=self.function),
                target=TypeGraphNode(IdentifierKind.UNKNOWN, "?"),
                kind=TypeGraphRelationKind.DYNAMIC_FLOW,
                location=location,
                reason=reason or "dynamic flow could not be resolved statically",
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "function": self.function,
            "context": self.context,
            "entry_types": {
                name: sorted(values)
                for name, values in sorted(self.entry_types.items())
            },
            "return_types": sorted(self.return_types),
            "relations": [relation.to_dict() for relation in self.relations],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FunctionTypeGraph":
        graph = cls(
            function=str(data["function"]),
            context=str(data.get("context", "default")),
            entry_types={
                str(name): set(values)
                for name, values in data.get("entry_types", {}).items()
            },
            return_types=set(data.get("return_types", [])),
        )
        graph.relations = [
            TypeGraphRelation.from_dict(item)
            for item in data.get("relations", [])
        ]
        return graph


def _node_kind_for_name(name: str) -> IdentifierKind:
    return IdentifierKind.ATTRIBUTE if "." in name or "[" in name else IdentifierKind.VARIABLE


def _type_node(value: str) -> TypeGraphNode:
    if value.startswith("external:"):
        return TypeGraphNode(IdentifierKind.EXTERNAL, value.split(":", 1)[1])
    if value.startswith("factory:"):
        return TypeGraphNode(IdentifierKind.UNKNOWN, value)
    if value.startswith("function:"):
        return TypeGraphNode(IdentifierKind.FUNCTION, value.split(":", 1)[1])
    if value in {"STRING", "INTEGER", "UNKNOWN"}:
        return TypeGraphNode(IdentifierKind.LITERAL, value)
    return TypeGraphNode(IdentifierKind.CLASS, value)
