"""Background dead-rule watch.

A dead rule is an ALLOW that sits below a DENY for the same address. It looks
correct in `ufw status` and passes no traffic, so somebody believes a customer
is authorized when they are not. Five of these were already in production when
this tool was built, one of them a customer somebody had tried to unblock in
July and never realised had failed.

That is precisely the kind of fault that should find you rather than wait to be
asked about, so it is a scheduled scan rather than a tool nobody remembers to
click.

Two design choices worth knowing:

* It emails on CHANGE, not on schedule. A daily message saying the same three
  rules are still dead trains people to ignore it. Only newly-appeared dead
  rules trigger a send; the state lives on the audit volume so a redeploy does
  not resend everything.
* The recipient is fixed. Outbound goes to John, who forwards. This is a house
  rule rather than a config decision, so it is not read from the environment
  where it could quietly be pointed elsewhere.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from . import ufw
from .config import Config

log = logging.getLogger("ufw_mcp.audit_scan")

# House rule, deliberately not configurable: outbound mail goes to John and he
# forwards. See ~/.claude/CLAUDE.md.
ALERT_TO = "approver@example.com"
ALERT_FROM = "approver@example.com"

_DEAD = re.compile(r"^DEAD:\s+(\S+)\s+deny\[(\d+)\]\s+<\s+allow\[(\d+)\]")


def _state_path(cfg: Config) -> Path:
    base = Path(cfg.audit_file).parent if cfg.audit_file else Path("/audit")
    return base / "dead-rules-state.json"


def _load_seen(cfg: Config) -> set[str]:
    try:
        return set(json.loads(_state_path(cfg).read_text(encoding="utf-8"))["seen"])
    except Exception:  # noqa: BLE001 - absent or unreadable state is "nothing seen"
        return set()


def _save_seen(cfg: Config, seen: set[str]) -> None:
    try:
        p = _state_path(cfg)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "seen": sorted(seen),
            "updated": datetime.now(timezone.utc).isoformat(),
        }), encoding="utf-8")
    except OSError as exc:
        log.error("could not persist dead-rule state (%s): %s", _state_path(cfg), exc)


async def scan(cfg: Config) -> dict:
    """Run the conflicts check on every switch. Returns findings by switch."""
    results = await ufw.fleet(cfg).list_mode("conflicts")
    findings: dict[str, list[dict]] = {}
    unreachable: list[str] = []
    for r in results:
        if not r.ok:
            unreachable.append(r.target)
            continue
        rows = []
        for line in (r.output or "").splitlines():
            m = _DEAD.match(line.strip())
            if m:
                rows.append({"ip": m.group(1), "deny": int(m.group(2)),
                             "allow": int(m.group(3)), "raw": line.strip()})
        findings[r.target] = rows
    return {"findings": findings, "unreachable": unreachable}


def _send_email(subject: str, body_md: str) -> str:
    """Send via Resend. Returns the message id, or '' if mail is not configured."""
    import os
    import urllib.error
    import urllib.request

    key = os.environ.get("UFWMCP_RESEND_API_KEY", "").strip()
    if not key:
        log.warning("dead rules found but UFWMCP_RESEND_API_KEY is unset; not mailing")
        return ""
    html = "<pre style='font-family:ui-monospace,Menlo,monospace;font-size:13px'>" \
           + body_md.replace("&", "&amp;").replace("<", "&lt;") + "</pre>"
    payload = json.dumps({
        "from": ALERT_FROM, "to": [ALERT_TO], "subject": subject, "html": html,
    }).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails", data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            # Resend sits behind Cloudflare, which blocks the default
            # "Python-urllib/3.x" agent with 403 "error code: 1010". That reads
            # like a rejected API key and is not one - the request never reaches
            # Resend at all.
            "User-Agent": "ufw-mcp/1.0 (+https://ufw-mcp.example.com)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode()).get("id", "")
    except urllib.error.HTTPError as exc:
        log.error("resend rejected the alert: %s %s", exc.code,
                  exc.read().decode("utf-8", "replace")[:300])
    except Exception as exc:  # noqa: BLE001
        log.error("could not send the dead-rule alert: %s", exc)
    return ""


async def run_once(cfg: Config, force_email: bool = False) -> dict:
    """One scan. Emails only about dead rules that are NEW since last time."""
    out = await scan(cfg)
    current = {f"{sw}:{row['ip']}" for sw, rows in out["findings"].items() for row in rows}
    seen = _load_seen(cfg)
    new = current - seen

    total = sum(len(v) for v in out["findings"].values())
    log.info("dead-rule scan: %d found, %d new, unreachable=%s",
             total, len(new), out["unreachable"] or "none")

    out.update({"total": total, "new": sorted(new), "emailed": False})

    if new or (force_email and current):
        lines = [
            "Dead firewall rules on the voice switches",
            "",
            "A dead rule is an ALLOW sitting below a DENY for the same address.",
            "It looks correct in `ufw status` and passes no traffic, so somebody",
            "believes a customer is authorized when they are not.",
            "",
        ]
        for sw, rows in sorted(out["findings"].items()):
            lines.append(f"{sw}: {len(rows)} dead rule(s)")
            for row in rows:
                flag = "  NEW" if f"{sw}:{row['ip']}" in new else "     "
                lines.append(f"{flag} {row['ip']:<18} deny[{row['deny']}] beats allow[{row['allow']}]")
            lines.append("")
        if out["unreachable"]:
            lines += [f"NOT CHECKED (switch unreachable): {', '.join(out['unreachable'])}", ""]
        lines += [
            "Adding another allow will NOT fix these. The deny above has to be",
            "cleared by someone who knows why it is there - it may be an APIBAN",
            "feed entry or a manual fraud block.",
            "",
            f"Scanned {datetime.now(timezone.utc).isoformat(timespec='seconds')} by ufw-mcp.",
        ]
        subject = f"ufw-mcp: {len(new)} new dead firewall rule(s)" if new \
            else f"ufw-mcp: {total} dead firewall rule(s)"
        mid = _send_email(subject, "\n".join(lines))
        out["emailed"] = bool(mid)
        out["message_id"] = mid

    _save_seen(cfg, current)
    return out


async def watcher(cfg: Config, interval_hours: float) -> None:
    """Background loop. Never lets an exception kill the task."""
    # Let the server finish starting before the first scan.
    await asyncio.sleep(120)
    while True:
        try:
            await run_once(cfg)
        except Exception as exc:  # noqa: BLE001 - a scan failure must not stop the watch
            log.error("dead-rule scan failed (will retry): %s", exc)
        await asyncio.sleep(max(0.25, interval_hours) * 3600)
