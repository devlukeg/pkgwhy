from __future__ import annotations

from pkgwhy.core.models import Confidence, PackageExplanation


LOCAL_EXPLANATIONS: dict[str, PackageExplanation] = {
    "packaging": PackageExplanation(
        package="packaging",
        summary="Core utilities for parsing and comparing Python package versions, specifiers, markers, and requirements.",
        common_use_cases=["Validate dependency specifiers", "Compare package versions", "Parse requirement strings"],
        common_imports=["packaging.version", "packaging.requirements", "packaging.specifiers"],
        minimal_usage_example="from packaging.version import Version\nVersion('2.0') > Version('1.9')",
        common_alternatives=[],
        why_it_might_be_installed=["Used by packaging tools and dependency-aware applications."],
        confidence=Confidence.HIGH,
        sources_used=["built-in pkgwhy explanation database"],
    ),
    "pydantic": PackageExplanation(
        package="pydantic",
        summary="Data validation and structured model library for Python type hints.",
        common_use_cases=["Validate structured data", "Define JSON-friendly models", "Parse API payloads and configuration"],
        common_imports=["pydantic.BaseModel", "pydantic.Field"],
        minimal_usage_example="from pydantic import BaseModel\nclass Item(BaseModel):\n    name: str",
        common_alternatives=["attrs", "dataclasses", "marshmallow"],
        why_it_might_be_installed=["Used by applications that need typed validation or stable JSON output."],
        confidence=Confidence.HIGH,
        sources_used=["built-in pkgwhy explanation database"],
    ),
    "rich": PackageExplanation(
        package="rich",
        summary="Terminal formatting library for tables, colors, tracebacks, progress bars, and structured console output.",
        common_use_cases=["Render CLI tables", "Improve terminal output", "Display progress and formatted logs"],
        common_imports=["rich.console", "rich.table"],
        minimal_usage_example="from rich.console import Console\nConsole().print('[bold]Hello[/bold]')",
        common_alternatives=["click styling", "blessed"],
        why_it_might_be_installed=["Used by command-line tools for readable terminal output."],
        confidence=Confidence.HIGH,
        sources_used=["built-in pkgwhy explanation database"],
    ),
    "typer": PackageExplanation(
        package="typer",
        summary="CLI framework built on Click that uses Python type hints to define command-line interfaces.",
        common_use_cases=["Build Python CLIs", "Create typed command arguments", "Generate command help"],
        common_imports=["typer"],
        minimal_usage_example="import typer\napp = typer.Typer()\n@app.command()\ndef main(name: str):\n    typer.echo(name)",
        common_alternatives=["click", "argparse"],
        why_it_might_be_installed=["Used by Python projects that expose command-line commands."],
        confidence=Confidence.HIGH,
        sources_used=["built-in pkgwhy explanation database"],
    ),
}

