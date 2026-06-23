from __future__ import annotations

# Curated subset of commonly typosquatted PyPI targets, not an exhaustive index.
POPULAR_PACKAGE_REFERENCES: dict[str, tuple[str, ...]] = {
    "requests": ("requests",),
    "numpy": ("numpy",),
    "pandas": ("pandas",),
    "django": ("django",),
    "flask": ("flask",),
    "fastapi": ("fastapi",),
    "scikit-learn": ("scikit-learn", "sklearn"),
    "scipy": ("scipy",),
    "matplotlib": ("matplotlib",),
    "pytest": ("pytest",),
    "setuptools": ("setuptools",),
    "pip": ("pip",),
    "wheel": ("wheel",),
    "typer": ("typer",),
    "click": ("click",),
    "rich": ("rich",),
    "pydantic": ("pydantic",),
    "httpx": ("httpx",),
    "cryptography": ("cryptography",),
    "sqlalchemy": ("sqlalchemy",),
    "beautifulsoup4": ("beautifulsoup4", "bs4"),
    "pillow": ("pillow", "pil"),
}

KNOWN_LEGITIMATE_FAMILIES: set[str] = {
    "django-debug-toolbar",
    "pytest-cov",
    "pandas-stubs",
    "types-requests",
}
