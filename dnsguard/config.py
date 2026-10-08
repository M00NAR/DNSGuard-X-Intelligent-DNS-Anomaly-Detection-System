"""Configuration loading for DNSGuard-X."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load the YAML configuration file.

    Relative paths inside the config (whitelist, database) are resolved against
    the directory that contains the config file, and stored back as absolute paths.

    Args:
        path: Path to a YAML config file. Defaults to ``config.yaml`` in the project root.

    Returns:
        The parsed configuration dictionary.
    """
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not cfg_path.is_file():
        raise ConfigError(f"Config file not found: {cfg_path}")
    try:
        with cfg_path.open("r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {cfg_path}: {exc}") from exc

    for section in ("detectors", "host_window", "matching", "alerts", "storage", "whitelist"):
        if section not in cfg:
            raise ConfigError(f"Config section '{section}' is missing in {cfg_path}")

    base = cfg_path.resolve().parent
    wl = cfg["whitelist"]
    if wl.get("path"):
        wl["path"] = str(_resolve(base, wl["path"]))
    st = cfg["storage"]
    if st.get("db_path"):
        st["db_path"] = str(_resolve(base, st["db_path"]))
    return cfg


def _resolve(base: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else base / p
