"""Shared pytest fixtures and path setup."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dnsguard.config import load_config  # noqa: E402


@pytest.fixture(scope="session")
def config() -> dict:
    return load_config()
