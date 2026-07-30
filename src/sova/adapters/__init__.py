# SPDX-License-Identifier: Apache-2.0
"""Optional capture adapters that never become SOVA's trust root."""

from sova.adapters.codex_exec import CodexExecAdapter, CodexRunResult

__all__ = ["CodexExecAdapter", "CodexRunResult"]
