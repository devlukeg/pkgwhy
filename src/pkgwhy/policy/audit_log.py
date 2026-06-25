from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from pkgwhy.core.models import AgentPackagePrecheckResult
from pkgwhy.registry.local import config_dir

AGENT_DECISION_LOG_SCHEMA_VERSION = "pkgwhy.agent_decision_log.v1"


def write_agent_package_decision_log(
    result: AgentPackagePrecheckResult,
    *,
    log_root: Path | None = None,
) -> Path:
    """Write a compact local audit record for an agent package decision."""

    created_at = datetime.now(tz=UTC)
    root = log_root or config_dir() / "agent-decisions"
    package_dir = root / _safe_path_segment(result.package)
    package_dir.mkdir(parents=True, exist_ok=True)
    log_path = package_dir / f"{created_at.strftime('%Y%m%dT%H%M%S%fZ')}.json"
    payload = {
        "schema_version": AGENT_DECISION_LOG_SCHEMA_VERSION,
        "created_at": created_at.isoformat(),
        "precheck_schema_version": result.schema_version,
        "policy_schema_version": result.policy_schema_version,
        "target_type": result.target_type,
        "package": result.package,
        "version": result.version,
        "non_interactive": result.non_interactive,
        "decision": result.decision.value,
        "risk_level": result.risk_level.value,
        "confidence": result.confidence.value,
        "policy_decision_source": result.policy_decision_source,
        "reason_count": len(result.reasons),
        "warning_count": len(result.warnings),
        "reasons": list(result.reasons),
        "warnings": list(result.warnings),
    }
    log_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return log_path


def _safe_path_segment(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-_")
    return normalized or "unknown-package"
