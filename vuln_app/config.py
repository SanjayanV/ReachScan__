"""
config.py — Application configuration loader.

VULNERABILITY: Uses yaml.load() without a Loader argument.
CVE-2020-14343 (PyYAML): Arbitrary code execution via crafted YAML payload.

This module is called from app.main(), making yaml.load a REACHABLE sink.
Call chain: main() → load_config() → yaml.load()
"""

import yaml


def load_config(config_path: str) -> dict:
    """
    Load application config from a YAML file.

    ⚠️  VULNERABLE: yaml.load() without Loader=yaml.SafeLoader
    allows deserialization of arbitrary Python objects.
    A malicious config file can achieve remote code execution.

    Fix: yaml.safe_load(f) or yaml.load(f, Loader=yaml.SafeLoader)
    """
    with open(config_path, "r") as f:
        # SINK: yaml.load — CVE-2020-14343
        config = yaml.load(f)   # noqa: S506
    return config


def validate_config(config: dict) -> bool:
    """Validate required config keys are present."""
    required = {"db_host", "db_port", "secret_key"}
    missing = required - set(config.keys())
    if missing:
        raise ValueError(f"Missing config keys: {missing}")
    return True
