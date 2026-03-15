"""
simulator/generators — Pluggable platform-specific event generators.

Registry pattern: each platform module registers a PlatformGenerator subclass.
The main simulator loads all generators on startup via register_all().
"""
from __future__ import annotations

import datetime
import random
import uuid
from typing import Optional


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _random_pid() -> int:
    return random.randint(1000, 65535)


def _random_uid() -> int:
    return random.randint(1000, 9999)


def _random_port() -> int:
    return random.randint(49152, 65535)


class PlatformGenerator:
    """Base class for platform-specific event generators."""

    platform: str = ""
    event_types: list[str] = []

    def generate_attack(self, technique_id: str, **kwargs) -> list[dict]:
        """Generate attack events for a given technique. Returns ECS dicts."""
        raise NotImplementedError

    def generate_benign(self, event_type: str, count: int = 5) -> list[dict]:
        """Generate benign/baseline events. Returns ECS dicts."""
        raise NotImplementedError


# --- Registry ---
_generators: dict[str, "PlatformGenerator"] = {}


def register_generator(gen: "PlatformGenerator") -> None:
    _generators[gen.platform] = gen


def get_generator(platform: str) -> "PlatformGenerator":
    if platform not in _generators:
        raise KeyError(f"No generator registered for platform: {platform}")
    return _generators[platform]


def list_platforms() -> list[str]:
    return list(_generators.keys())


def register_all() -> None:
    """Import and register all platform generators."""
    from simulator.generators.linux import LinuxGenerator
    from simulator.generators.cloud import CloudGenerator
    from simulator.generators.network import NetworkGenerator
    from simulator.generators.macos import MacOSGenerator

    for gen_cls in [LinuxGenerator, CloudGenerator, NetworkGenerator, MacOSGenerator]:
        register_generator(gen_cls())
