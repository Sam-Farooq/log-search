from __future__ import annotations

import json
from pathlib import Path

import pytest

from logsearch.templates import TemplateSet, default_indices_dir

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def indices_dir() -> Path:
    return default_indices_dir()


@pytest.fixture(scope="session")
def templates(indices_dir: Path) -> TemplateSet:
    return TemplateSet(indices_dir)


@pytest.fixture(scope="session")
def app(templates: TemplateSet):
    return templates.compose("logs-app")


@pytest.fixture(scope="session")
def audit(templates: TemplateSet):
    return templates.compose("logs-audit")


@pytest.fixture
def write_indices(tmp_path: Path):
    """Build a throwaway `indices/` directory out of literal dicts.

    The checks have to be provable against a mapping that is wrong, and the
    shipped templates are not wrong, so the failure cases get their own files.
    """

    def _write(files: dict[str, dict]) -> Path:
        directory = tmp_path / "indices"
        directory.mkdir(exist_ok=True)
        for name, body in files.items():
            (directory / name).write_text(json.dumps(body), encoding="utf-8")
        return directory

    return _write
