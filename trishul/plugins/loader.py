"""
TRISHUL Scanner — Dynamic Plugin Loader
"""
from __future__ import annotations

import importlib.util
import inspect
import os
from typing import List, Type

from trishul.plugins.base import BasePlugin

# Files to skip
_SKIP_FILES = {"__init__.py", "base.py", "loader.py"}


class PluginLoader:
    """
    Discovers and loads plugins from one or more directories.
    """

    def __init__(self, plugin_dirs: List[str]) -> None:
        self.plugin_dirs = plugin_dirs

    def load(self) -> List[BasePlugin]:
        plugins: List[BasePlugin] = []
        seen: set = set()

        for plugin_dir in self.plugin_dirs:
            if not os.path.isdir(plugin_dir):
                continue

            for filename in sorted(os.listdir(plugin_dir)):
                if not filename.endswith(".py"):
                    continue
                if filename in _SKIP_FILES:
                    continue
                if filename in seen:
                    continue
                seen.add(filename)

                filepath = os.path.join(plugin_dir, filename)
                plugin_classes = self._load_from_file(filepath)
                for cls in plugin_classes:
                    try:
                        instance = cls()
                        plugins.append(instance)
                    except Exception as exc:
                        print(f"[PluginLoader] Could not instantiate {cls}: {exc}")

        return plugins

    def _load_from_file(self, filepath: str) -> List[Type[BasePlugin]]:
        """Import a Python file and return all BasePlugin subclasses found."""
        module_name = f"trishul_plugin_{os.path.basename(filepath)[:-3]}"
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec is None or spec.loader is None:
            return []

        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            print(f"[PluginLoader] Failed to load {filepath}: {exc}")
            return []

        classes = []
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BasePlugin)
                and obj is not BasePlugin
                and not inspect.isabstract(obj)
            ):
                classes.append(obj)
        return classes
