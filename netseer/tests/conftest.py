"""Shared pytest fixtures: an app on a temporary database and data directory."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# main.py builds a module-level `app` on import; point it at a throwaway database so tests never run
# migrations or mark_interrupted() on the real src/database/netseer.db.
_IMPORT_DIR = tempfile.mkdtemp(prefix="netseer-test-")
os.environ["NETSEER_DB"] = os.path.join(_IMPORT_DIR, "import.db")
os.environ["NETSEER_DATA"] = os.path.join(_IMPORT_DIR, "data")

from netseer.src.api.main import create_app  # noqa: E402


@pytest.fixture()
def app(tmp_path):
    """A fresh NetSeer app with its own database and data directory."""
    return create_app(db_path=tmp_path / "test.db", data_dir=tmp_path / "data")


@pytest.fixture()
def client(app):
    """HTTP client that does not follow redirects, so tests can assert them."""
    with TestClient(app, follow_redirects=False) as c:
        yield c
