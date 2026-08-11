# SPDX-License-Identifier: Apache-2.0
"""Cross-platform accessibility-first desktop execution adapters."""

from sova.desktop.appium import (
    AppiumDesktopExecutor,
    AppiumDesktopTarget,
    AppiumTransport,
    DesktopPlatform,
    LoopbackAppiumTransport,
)
from sova.desktop.atspi import AtSpiBackend, AtSpiDesktopExecutor, PyAtSpiBackend
from sova.desktop.conformance import DesktopConformancePlan, run_desktop_conformance

__all__ = [
    "AppiumDesktopExecutor",
    "AppiumDesktopTarget",
    "AppiumTransport",
    "AtSpiBackend",
    "AtSpiDesktopExecutor",
    "DesktopConformancePlan",
    "DesktopPlatform",
    "LoopbackAppiumTransport",
    "PyAtSpiBackend",
    "run_desktop_conformance",
]
