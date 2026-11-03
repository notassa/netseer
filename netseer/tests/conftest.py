"""Shared pytest fixtures: an app on a temporary database and data directory."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netseer.src.api.main import create_app


@pytest.fixture()
def app(tmp_path):
    """A fresh NetSeer app with its own database and data directory."""
    return create_app(db_path=tmp_path / "test.db", data_dir=tmp_path / "data")


@pytest.fixture()
def client(app):
    """HTTP client that does not follow redirects, so tests can assert them."""
    with TestClient(app, follow_redirects=False) as c:
        yield c
