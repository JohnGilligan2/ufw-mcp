"""Revoke was removed on purpose (John, 2026-08-18).

A concern raised in the design review was a first-level user deleting a SIP
trunk or Inteliquent address. The wrapper already refused to touch rules it had
not created, but the decision was that the capability should not exist at all
for now.

This test exists so re-adding it is a deliberate act with a failing test in
front of it, rather than something that reappears in a refactor. If you are
genuinely re-enabling revoke: restore the constant in ufw.py, restore the tool
in server.py, re-add the sudoers entry on BOTH switches, re-install the wrapper,
and then delete this file in the same commit.
"""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "ufw_mcp"


def test_no_revoke_tool_is_exposed():
    tree = ast.parse((PKG / "server.py").read_text(encoding="utf-8"))
    tools = [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
        and any(getattr(d, "attr", "") == "tool" for d in n.decorator_list)
    ]
    assert tools, "no tools found at all - the scan is broken, not the code"
    assert not [t for t in tools if "revoke" in t or "remove" in t or "delete" in t], tools


def test_the_revoke_wrapper_cannot_be_executed():
    """Even if a tool came back, the executor must not accept the revoke path."""
    src = (PKG / "ufw.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    assigned = {
        t.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        for t in n.targets
        if isinstance(t, ast.Name)
    }
    assert "REVOKE" not in assigned, "ufw.py defines a REVOKE command constant again"

    # Look in the AST, not the raw text: the file carries a comment explaining
    # why revoke is gone, and a comment is not a code path. ast drops comments,
    # so a hit here is a real string literal in executable code.
    literals = {
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }
    offenders = [s for s in literals if "ufw-mcp-revoke" in s]
    assert not offenders, f"revoke wrapper path present in code: {offenders}"
