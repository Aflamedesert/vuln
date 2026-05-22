from __future__ import annotations

import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from scanner.core.models import ServiceInfo


@dataclass
class PluginFinding:
    plugin_name: str
    title: str
    description: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    evidence: str | None = None


class BasePlugin(ABC):
    name: str
    description: str

    @abstractmethod
    def applies_to(self, service: ServiceInfo) -> bool: ...

    @abstractmethod
    def run(self, service: ServiceInfo, host: str) -> list[PluginFinding]: ...


def discover_plugins() -> list[BasePlugin]:
    plugins_dir = Path(__file__).parent
    found: list[BasePlugin] = []
    for _, mod_name, _ in pkgutil.iter_modules([str(plugins_dir)]):
        if mod_name == "base":
            continue
        module = importlib.import_module(f"scanner.plugins.{mod_name}")
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(cls, BasePlugin)
                and cls is not BasePlugin
                and cls.__module__ == module.__name__
            ):
                found.append(cls())
    return found
