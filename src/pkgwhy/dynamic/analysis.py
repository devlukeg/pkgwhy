from __future__ import annotations

from pkgwhy.core.models import AgentDecision, DynamicAnalysisResult, DynamicAnalysisStatus, DynamicNetworkMode

EXPERIMENTAL_DYNAMIC_WARNING = "Experimental dynamic analysis is not a production sandbox."
STATIC_DEFAULT_WARNING = "Static package inspection remains the default pkgwhy review path."
HOST_EXECUTION_REFUSAL = "Refusing to run dynamic analysis for unknown package code on the host."


def build_unavailable_dynamic_result(
    target: str,
    *,
    container: bool,
    network: str,
) -> DynamicAnalysisResult:
    """Build a safe-fail dynamic result without executing the target."""
    warnings = [
        EXPERIMENTAL_DYNAMIC_WARNING,
        STATIC_DEFAULT_WARNING,
        HOST_EXECUTION_REFUSAL,
    ]
    limitations = [
        "No dynamic sandbox backend is implemented in this build.",
        "No process, filesystem, or network events were collected.",
        "Empty event lists are not proof that no behavior would occur in a real run.",
    ]
    sandbox_backend = "container" if container else "none"
    status = DynamicAnalysisStatus.BACKEND_UNAVAILABLE if container else DynamicAnalysisStatus.BLOCKED

    if network != DynamicNetworkMode.OFF.value:
        warnings.append("Only network mode 'off' is accepted in this pre-alpha skeleton.")
        limitations.append("Network-enabled dynamic analysis is not supported.")
        status = DynamicAnalysisStatus.BLOCKED
    elif container:
        warnings.append("Container sandbox backend is not implemented or available in this build.")
    else:
        warnings.append("No sandbox backend selected. Host execution is not allowed.")

    return DynamicAnalysisResult(
        target=target,
        sandbox_backend=sandbox_backend,
        network_mode=DynamicNetworkMode.OFF,
        status=status,
        warnings=warnings,
        process_events=[],
        filesystem_events=[],
        network_events=[],
        decision=AgentDecision.BLOCK,
        limitations=limitations,
    )

