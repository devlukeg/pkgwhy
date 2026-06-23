from __future__ import annotations

from collections import deque

from packaging.requirements import InvalidRequirement, Requirement

from pkgwhy.metadata.installed import list_installed_packages, normalize_package_name


def installed_dependency_graph() -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for package in list_installed_packages():
        name = package.identity.normalized_name
        graph[name] = _dependency_names(package.requires)
    return graph


def transitive_dependencies_for(direct_dependencies: set[str], graph: dict[str, set[str]] | None = None) -> set[str]:
    dependency_graph = graph if graph is not None else installed_dependency_graph()
    normalized_direct = {normalize_package_name(name) for name in direct_dependencies}
    transitive: set[str] = set()
    queue: deque[str] = deque()

    for direct in normalized_direct:
        queue.extend(dependency_graph.get(direct, set()))

    while queue:
        dependency = queue.popleft()
        if dependency in normalized_direct or dependency in transitive:
            continue
        transitive.add(dependency)
        queue.extend(dependency_graph.get(dependency, set()))

    return transitive


def _dependency_names(requirements: list[str]) -> set[str]:
    names: set[str] = set()
    for value in requirements:
        try:
            names.add(normalize_package_name(Requirement(value).name))
        except InvalidRequirement:
            continue
    return names

