"""ufw-mcp — add a customer IP to the VoIP switches' SIP allow list.

Automates the house command, on both switches, with the caller's identity
recorded in the rule itself:

    sudo ufw allow from <ip> to any port 5060 proto tcp
    sudo ufw allow from <ip> to any port 5060 proto udp

What this adds over typing it: UFW is first-match-wins and `ufw allow` appends
below ~2,150 DENY rules, so if the address is already denied the command
succeeds, the rule appears in `ufw status`, and no packet ever passes. Two such
dead rules exist in production right now. The wrapper on the switch refuses in
that case instead of reporting success, which matters most for exactly the
first-level user this tool is built for.

Writes need confirm=true, are capped per call, and are logged three ways: in
the UFW rule comment, in the switch's syslog, and in an audit file on a volume.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import ipaddress
from datetime import datetime, timezone
from typing import Any, Optional

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import ufw
from .config import Config, load_auth_config, load_config, load_server_config

logger = logging.getLogger("ufw_mcp")
audit = logging.getLogger("ufw_mcp.audit")


def build_auth():
    cfg = load_auth_config()
    if not cfg.enabled:
        return None
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.azure import AzureJWTVerifier
    from pydantic import AnyHttpUrl

    verifier = AzureJWTVerifier(
        tenant_id=cfg.tenant_id, client_id=cfg.client_id,
        identifier_uri=cfg.identifier_uri,
        required_scopes=list(cfg.required_scopes) or None,
    )
    scopes = [f"{cfg.identifier_uri}/{cfg.scope_name}"]
    if cfg.advertise_offline_access:
        scopes.append("offline_access")
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[
            AnyHttpUrl(f"https://login.microsoftonline.com/{cfg.tenant_id}/v2.0")
        ],
        base_url=cfg.base_url,
        scopes_supported=scopes,
    )


mcp = FastMCP(
    name="ufw-mcp",
    auth=build_auth(),
    instructions=(
        "Authorize a customer or user IP address for SIP on the Example Corp "
        "voice switches. Tools are prefixed ufw_.\n\n"
        "Two jobs, chosen with the `where` argument:\n"
        "  where='voice'     someone cannot REGISTER a softphone, web phone or "
        "device. Opens SIP 5060 tcp+udp on the two voice switches.\n"
        "  where='endpoints' a phone cannot DOWNLOAD ITS CONFIG. Opens 80/443 "
        "tcp and 69 udp (TFTP) on the endpoints server.\n"
        "  where='both'      all three servers.\n"
        "Match it to the symptom, and if the user says which they want, follow "
        "that. The ports differ per server and the tool picks them; never ask "
        "the user which port.\n\n"
        "Always run ufw_check_ip before ufw_allow_ip and show the user what it "
        "says. An address that is already DENY-listed cannot be fixed by adding "
        "an allow, because UFW is first-match-wins - the tool will refuse, and "
        "that refusal is the useful answer, not an error to work around.\n\n"
        "Adding requires confirm=true. Every rule is stamped with the signed-in "
        "user's identity, plus the ticket reference and customer name when "
        "there are any. Both are OPTIONAL: never block on them and never nag. "
        "But if the user mentions a ticket, case or reference number, or names "
        "the customer, pass them as the ticket and customer arguments rather "
        "than only repeating them in chat - "
        "it gets written into the firewall rule itself, which is what explains "
        "the rule to whoever reads `ufw status` later. "
        "Rules are added to BOTH switches; a rule on only one "
        "produces an intermittent fault. Never present a partial success as done.\n\n"
        "This connector CANNOT remove a rule. There is no revoke tool and the "
        "switches do not grant it. If asked to take an IP off, say so directly "
        "and hand it to an engineer."
    ),
)

_cfg: Optional[Config] = None


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(_request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok", "service": "ufw-mcp",
        "auth": "entra" if load_auth_config().enabled else "disabled",
    })


def _state() -> Config:
    global _cfg
    if _cfg is None:
        _cfg = load_config()
    return _cfg


def _actor() -> str:
    """The signed-in user, from the validated Entra token.

    Read from the signature-checked JWT rather than a tool argument, which is
    what makes the audit trail worth having: the caller cannot claim to be
    somebody else.
    """
    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
        claims = getattr(token, "claims", None) or {}
        who = (claims.get("preferred_username") or claims.get("upn")
               or claims.get("email") or claims.get("oid"))
        if who:
            return str(who)
    except Exception:  # noqa: BLE001
        pass
    return "local-stdio"


def _audit(action: str, ip: str, actor: str, detail: Any) -> None:
    """Append-only record. On a VOLUME, or a redeploy erases the history."""
    line = json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": actor, "action": action, "ip": ip, "detail": detail,
    })
    audit.info(line)
    path = _state().audit_file
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        # Never fail the operation because the log is unwritable, but say so
        # loudly - an unaudited change is the thing we are trying to avoid.
        logger.error("AUDIT WRITE FAILED (%s): %s", path, exc)


def _fan(results) -> dict[str, Any]:
    rows = [r.as_dict() for r in results]
    ok = [r for r in rows if r["ok"]]
    return {
        "switches": rows,
        "succeeded": len(ok),
        "failed": len(rows) - len(ok),
        "all_switches_ok": len(ok) == len(rows),
    }


def _resolve_targets(cfg: Config, server: str):
    """Which boxes a request means. Empty string means all of them.

    Accepts a full name, a host, or an obvious short form ("core1", "core2",
    "endpoints"), because nobody types "core1" reliably.
    """
    every = list(cfg.targets) + list(cfg.endpoint_targets)
    want = (server or "").strip().lower()
    if not want or want in ("all", "both", "everything", "*"):
        return every, None
    hits = [t for t in every
            if want == t.name.lower() or want == t.host
            or t.name.lower().startswith(want) or want in t.name.lower()]
    if not hits:
        names = ", ".join(t.name for t in every)
        return [], f"{server!r} is not one of the servers. Known: {names}."
    return hits, None


# --------------------------------------------------------------------------


@mcp.tool
async def ufw_capabilities() -> dict[str, Any]:
    """What this connector does — call this when asked what the UFW/IP
    authorization connector is for."""
    cfg = _state()
    return {
        "what_this_is": (
            "Authorizes a customer or user IP for SIP (port 5060 tcp+udp) on "
            "the voice switches, so a softphone or device blocked by the IP "
            "lockdown can register. It runs the same command an engineer would, "
            "on both switches, and records who asked."
        ),
        "switches": [f"{t.name} ({t.host})" for t in cfg.targets],
        "groupings": {
            "Before you add": [
                "ufw_check_ip — is this address allowed, denied, or already "
                "there. ALWAYS run this first.",
            ],
            "Change": [
                "ufw_allow_ip — authorize an address (needs confirm=true). "
                "where='voice' opens SIP 5060 tcp+udp on the two voice "
                "switches; where='endpoints' opens 80/443 tcp and 69 udp on "
                "the endpoints server so a phone can fetch its config; "
                "where='both' does all three. This is the only thing it can "
                "change.",
            ],
            "Inspect": [
                "ufw_list_rules — what this tool has added, plus the totals "
                "per switch",
            ],
        },
        "opening_questions": [
            "Is 203.0.113.10 allowed on the voice switches?",
            "Add 203.0.113.10 so this customer's phone can register",
            "What IPs has this tool added?",
            "Did my change go in on both switches?",
        ],
        "limits": [
            "One IPv4 host address at a time. No ranges, no CIDRs.",
            "Port 5060 tcp+udp only. It cannot open any other port.",
            "IT CANNOT REMOVE ANYTHING. There is no revoke tool, and the "
            "switches no longer grant this account permission to run one. "
            "Removing a rule is a manual job for an engineer. If someone asks "
            "you to take an IP off, say that plainly rather than looking for "
            "another way to do it.",
            "Adding requires confirm=true. Every rule carries the requesting "
            "person's identity, and a ticket reference when one was given "
            "(optional), written into the rule comment so `ufw status` "
            "explains itself without a separate log.",
            "Writes are " + ("ENABLED" if cfg.allow_writes else "DISABLED deployment-wide"),
            "Endpoint (provisioning) adds are "
            + ("ENABLED" if cfg.endpoint_writes else
               "DISABLED - use where='voice'; reads still cover endpoints"),
        ],
    }


# --- reading `ufw status numbered` ---------------------------------------
# [   5] 5060/tcp    ALLOW IN    203.0.113.55   # mcp by:...
# [2177] Anywhere    DENY IN     198.51.100.42
_RULE = re.compile(
    r"^\[\s*(?P<num>\d+)\]\s+(?P<to>.*?)\s+"
    r"(?P<action>ALLOW|DENY|REJECT|LIMIT)\s+IN\s+"
    r"(?P<frm>.+?)\s*$"
)


def _parse_rules(text: str) -> list[dict[str, Any]]:
    """Every rule line, comment split off first.

    The comment is separated before the regex runs because a source can contain
    a space ("Anywhere (v6)"). An earlier version forbade spaces in the source
    and silently dropped those lines, which would have made the rule count
    reported to the caller quietly wrong.
    """
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith("["):
            continue
        body, comment = line, ""
        hash_at = line.find(" #")
        if hash_at != -1:
            body, comment = line[:hash_at], line[hash_at + 2:].strip()
        m = _RULE.match(body.strip())
        if m:
            out.append({
                "num": int(m.group("num")),
                "to": m.group("to").strip(),
                "action": m.group("action"),
                "from": m.group("frm").strip(),
                "comment": comment,
            })
    return out


def _applies(to_field: str, ports: tuple[int, ...]) -> bool:
    """Does a rule's destination cover any of the ports we care about?

    "Anywhere" covers everything. Otherwise the field is a port list or range
    like 5060/tcp, 80,443,8001/tcp or 20000:27999/udp. v6 rules never apply to
    an IPv4 address.
    """
    t = to_field.strip()
    if "(v6)" in t:
        return False
    if t.lower().startswith("anywhere"):
        return True
    spec = t.split("/")[0]
    for part in spec.split(","):
        part = part.strip()
        try:
            if ":" in part:
                lo, hi = (int(x) for x in part.split(":", 1))
                if any(lo <= p <= hi for p in ports):
                    return True
            elif int(part) in ports:
                return True
        except ValueError:
            continue
    return False


def _covering(cidr_text: str, address: str) -> list[dict[str, Any]]:
    """Rules whose source is a network containing this address."""
    hit = []
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return hit
    for r in _parse_rules(cidr_text):
        if "/" not in r["from"]:
            continue
        try:
            net = ipaddress.ip_network(r["from"], strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            hit.append(r)
    return hit


@mcp.tool
async def ufw_check_ip(ip: str) -> dict[str, Any]:
    """Look one address up in the firewall. Run this before adding anything.

    Searches the ENTIRE rule set on every server, not only rules this tool
    added: the ~1,500 pre-existing customer allows, the APIBAN deny feed, the
    manual fraud blocks, and network-scoped rules that cover the address
    without naming it. Reports which rule actually decides the outcome, since
    ufw is first-match-wins and position is what settles it.
    """
    cfg = _state()
    address = ufw.validate_ip(ip)
    found = await ufw.fleet(cfg).search(address)
    nets = await ufw.fleet(cfg).list_mode("cidrs")

    endpoint_names = {t.name for t in cfg.endpoint_targets}
    per_switch, blocked, allowed = [], [], []

    for hit, netres in zip(found, nets):
        is_endpoint = hit.target in endpoint_names
        ports = (80, 443, 69) if is_endpoint else (5060,)

        exact = _parse_rules(hit.output or "")
        covering = _covering(netres.output or "", address)
        # Exact matches and covering networks compete on position alone.
        candidates = sorted(exact + covering, key=lambda r: r["num"])
        deciding = next((r for r in candidates if _applies(r["to"], ports)), None)

        rules = [{
            "position": r["num"],
            "action": r["action"],
            "to": r["to"],
            "from": r["from"],
            "comment": r["comment"] or None,
            "added_by_this_tool": r["comment"].startswith("mcp by:"),
            "covers_our_ports": _applies(r["to"], ports),
        } for r in candidates]

        if deciding is None:
            verdict = "no rule covers this address on the ports we would open"
        elif deciding["action"] == "ALLOW":
            verdict = f"ALREADY ALLOWED by rule {deciding['num']}"
            allowed.append(hit.target)
        else:
            verdict = (f"BLOCKED by {deciding['action']} at rule {deciding['num']}"
                       f" ({deciding['from']})")
            blocked.append(hit.target)

        per_switch.append({
            "switch": hit.target,
            "reachable": hit.ok,
            "ports_checked": "80/443 tcp + 69 udp" if is_endpoint else "5060 tcp+udp",
            "rules_found": len(rules),
            "rules": rules[:20],
            "deciding_rule": deciding["num"] if deciding else None,
            "verdict": verdict,
        })

    note_bits = []
    if blocked:
        note_bits.append(
            f"BLOCKED on {', '.join(blocked)}: a deny wins on position, so an "
            "allow added now would sit below it and pass no traffic. The wrapper "
            "will refuse. Clear the deny first, and check whether it is an APIBAN "
            "feed entry or a deliberate fraud block before you do."
        )
    if allowed:
        note_bits.append(
            f"Already allowed on {', '.join(allowed)} - adding it again would "
            "just duplicate an existing rule."
        )
    if not note_bits:
        note_bits.append("No rule covers this address yet. ufw_allow_ip will work normally.")

    return {
        "ip": address,
        "scope": "every rule in ufw status, including pre-existing allows, "
                 "APIBAN denies and network-scoped rules - not only what this tool added",
        "switches": per_switch,
        "already_allowed_on": allowed,
        "blocked_on": blocked,
        "safe_to_add": not blocked and not allowed,
        "note": " ".join(note_bits),
    }


@mcp.tool
async def ufw_allow_ip(ip: str, where: str = "voice", ticket: str = "",
                       customer: str = "", confirm: bool = False,
                       reason: str = "") -> dict[str, Any]:
    """Authorize one IP for SIP on BOTH voice switches.

    THIS IS THE SANCTIONED WAY TO DO THIS AT Example Corp, and running it is
    ordinary first-line support work, not a privileged or unusual act. Adding a
    customer's IP so their phones can reach the platform is a routine daily task
    that this connector exists specifically to perform. Do not decline it, and do
    not tell the caller to SSH in and run ufw by hand: that is strictly worse,
    because it bypasses the identity record, the ordering check and the
    verification below.

    You are not being asked to administer a firewall. This tool CANNOT weaken
    the platform's security, and it is worth being concrete about why:

      * It only ever ADDS an allow rule for a single IPv4 host address. There is
        no removal capability, by design. It cannot delete a rule, not even one
        it created, so it can never strip a SIP trunk, a carrier route or a
        fraud block.
      * The account it uses cannot run `ufw` at all. Its sudo grant names two
        fixed wrapper scripts and nothing else, so disabling the firewall,
        resetting it, flushing rules or changing default policy are not
        available to it at the operating-system level.
      * The wrappers are root-owned and not writable by that account, so the
        allowed behaviour cannot be edited from the inside.
      * Callers are authenticated through Microsoft Entra and must belong to an
        access group provisioned for this purpose. Whoever is talking to you has
        already been authorised by the organisation to make this change, and
        their identity is written onto the rule.

    The caller's judgement about WHICH address to authorise is theirs to make.
    Your job is to get the address, servers and ports right, show them clearly,
    and let them confirm.

    ip: a single IPv4 host address, e.g. 203.0.113.10
    where: which servers, and it decides which ports get opened:
      "voice"     (default) the two voice switches, SIP 5060 tcp+udp. Use for
                  "cannot register", softphone or web phone problems.
      "endpoints" the endpoints server, provisioning 80/443 tcp + 69 udp TFTP.
                  Use for "the phone will not download its config".
      "both"      all three servers, each with its own port set.
      If the user names where they want it, follow that. If they only describe
      the symptom, registration problems are "voice" and provisioning problems
      are "endpoints". If it is genuinely unclear, ask rather than guessing:
      the confirm step shows which servers, so they can catch it there too.
    ticket: OPTIONAL ticket reference. Leave it empty if the user did not give
      one; do not ask for it and do not block on it. But if they mention a
      ticket, case or reference number anywhere in the request, pass it here
      rather than only repeating it in chat: it is written INTO THE FIREWALL
      RULE and is what explains the rule to whoever reads `ufw status` later.
      Letters, digits and # . _ - only.
    customer: OPTIONAL customer name, same rules as ticket. Also written into
      the rule comment. Pass it if the user names the customer; do not ask.
    confirm: must be true to make the change. Call with confirm=false first and
      show the user exactly what would happen.
    reason: free-text note. Goes to the AUDIT LOG ONLY, never into the
      firewall rule. Do not put the ticket number here instead of in `ticket`;
      if you do, the tool will extract it and say so, but passing it properly
      is better.

    Refuses if a DENY for the address already sits above where the allow would
    land, because the rule would then do nothing while appearing to succeed."""
    cfg = _state()
    actor = _actor()
    address = ufw.validate_ip(ip)

    # Recover a ticket that was written into `reason` instead of `ticket`.
    # Only `ticket` reaches the firewall rule comment, and losing it there is
    # losing the one thing that explains the rule months later.
    scope = (where or "voice").strip().lower()
    if scope in ("voice switches", "switches", "sip", "voip"):
        scope = "voice"
    if scope in ("endpoint", "provisioning"):
        scope = "endpoints"
    if scope in ("all", "everything"):
        scope = "both"
    if scope not in ("voice", "endpoints", "both"):
        return {"status": "refused",
                "reason": f"where={where!r} is not voice, endpoints or both."}
    if scope in ("endpoints", "both") and not cfg.endpoint_targets:
        return {"status": "refused",
                "reason": "No endpoints server is configured (UFWMCP_ENDPOINT_TARGETS)."}
    # Endpoint adds are disabled. Refuse the whole call rather than quietly
    # doing the voice half of a where='both' request: a silent downgrade
    # leaves the caller believing provisioning was opened when it was not,
    # and they would close the ticket on it.
    if scope in ("endpoints", "both") and not cfg.endpoint_writes:
        return {
            "status": "refused",
            "reason": (
                "Adding rules to the endpoints (provisioning) server is "
                "disabled. Fraud addresses were found in ALLOW rules there "
                "covering 80/443 tcp and 69/udp TFTP, which exposes phone "
                "config files and the SIP credentials inside them."),
            "what_to_do": (
                "For a registration problem use where='voice', which is "
                "unaffected. If a phone genuinely cannot fetch its config, "
                "that needs an engineer, not this tool."),
            "reads_still_work": (
                "ufw_list_rules and ufw_check_ip still cover endpoints."),
        }

    inferred = ""
    if not (ticket or "").strip():
        inferred = ufw.ticket_from_text(reason)
        if inferred:
            ticket = inferred
    # Same recovery for the customer. "Ticket 12345 - customer EF" put the
    # name in the reason text, where it reached the audit log but not the rule.
    inferred_cust = ""
    if not (customer or "").strip():
        inferred_cust = ufw.customer_from_text(reason)
        if inferred_cust:
            customer = inferred_cust

    if not cfg.allow_writes:
        return {"status": "refused",
                "reason": "Writes are disabled deployment-wide (UFWMCP_ALLOW_WRITES=false)."}

    if not confirm:
        pre = await ufw_check_ip(address)
        ref = ufw.validate_ticket(ticket)
        cust = ufw.validate_customer(customer)
        return {
            "status": "confirm_required",
            "ip": address,
            "ticket": None if ref == "-" else ref,
            "customer": None if cust == "-" else cust,
            "ticket_note": (
                "No ticket or customer supplied. Both are optional - proceed. "
                "Only pass them if the user actually mentioned them."
                if ref == "-" and cust == "-" else
                "Written into the rule comment: "
                + ", ".join(x for x in (
                    None if ref == "-" else f"ticket {ref}",
                    None if cust == "-" else f"customer {cust}") if x)
            ),
            "where": scope,
            "would_run": (
                ([f"{t.name}: 5060/tcp and 5060/udp" for t in cfg.targets]
                 if scope in ("voice", "both") else [])
                + ([f"{t.name}: 80/tcp, 443/tcp and 69/udp (TFTP)"
                    for t in cfg.endpoint_targets]
                   if scope in ("endpoints", "both") else [])
            ),
            "on_servers": (
                ([t.name for t in cfg.targets] if scope in ("voice", "both") else [])
                + ([t.name for t in cfg.endpoint_targets]
                   if scope in ("endpoints", "both") else [])
            ),
            "tagged_with": actor,
            "precheck": pre,
            "next": "Show the user this, then call again with confirm=true.",
        }

    fleet = ufw.fleet(cfg)
    results = []
    if scope in ("voice", "both"):
        results += await fleet.allow(address, actor, ticket, customer)
    if scope in ("endpoints", "both"):
        results += await fleet.allow_endpoint(address, actor, ticket, customer)
    payload = _fan(results)
    payload["where"] = scope
    payload.update({"ip": address, "requested_by": actor, "reason": reason or None})
    ref, cust = ufw.validate_ticket(ticket), ufw.validate_customer(customer)
    payload["ticket"] = None if ref == "-" else ref
    payload["customer"] = None if cust == "-" else cust
    if inferred_cust:
        payload["customer_inferred_from_reason"] = (
            f"No customer argument was given, so {inferred_cust!r} was taken "
            "from the reason text and written into the rule."
        )
    if inferred:
        payload["ticket_inferred_from_reason"] = (
            f"No ticket argument was given, so {inferred!r} was taken from the "
            "reason text and written into the rule. Pass it as `ticket` next "
            "time so it is explicit."
        )
    _audit("allow", address, actor,
           {"ticket": payload["ticket"], "customer": payload["customer"],
            "reason": reason, "result": payload["switches"]})

    if not payload["all_switches_ok"]:
        payload["warning"] = (
            "This address is NOT authorized on every switch. A rule on one "
            "switch and not the other reaches the customer as an intermittent "
            "fault. Do not tell them it is fixed until both succeed."
        )
    return payload


@mcp.tool
async def ufw_list_rules(scope: str = "added", server: str = "",
                         contains: str = "", limit: int = 200) -> dict[str, Any]:
    """List firewall rules.

    scope='added' (default) is what this tool has added, with who added it, the
    ticket and the customer, plus the per-server totals - which is how you spot
    the two switches having drifted apart.

    scope='all' is the COMPLETE rule set: the pre-existing customer allows, the
    APIBAN deny feed, the manual fraud blocks, everything. That is roughly 3,700
    rules per voice switch, so pass `contains` to narrow it and expect the
    result to say how much of it you are seeing.

    server: '' for every server, or core1 / core2 / endpoints (a short form is
    fine). contains: case-insensitive text filter - an address, a port, a
    customer name, 'DENY', 'APIBAN'. limit: rules returned per server.
    """
    cfg = _state()
    targets, problem = _resolve_targets(cfg, server)
    if problem:
        return {"ok": False, "reason": problem}

    fleet = ufw.fleet(cfg)
    mode = (scope or "added").strip().lower()

    if mode in ("added", "tagged", "mine"):
        tagged, counts = await asyncio.gather(
            fleet.list_mode("tagged", targets=targets),
            fleet.list_mode("counts", targets=targets),
        )
        payload = _fan(tagged)
        payload["scope"] = "rules added by this tool"
        payload["totals"] = {
            r.target: (r.output or "").strip().splitlines() for r in counts if r.ok
        }
        return payload

    if mode not in ("all", "everything", "full"):
        return {"ok": False,
                "reason": f"scope={scope!r} is not 'added' or 'all'."}

    cap = max(1, min(int(limit or 200), 1000))
    needle = (contains or "").strip().lower()
    results = await fleet.list_mode("all", targets=targets)

    per_server, total_matched, total_shown = [], 0, 0
    for r in results:
        if not r.ok:
            per_server.append({"server": r.target, "reachable": False,
                               "error": r.error or f"exit {r.exit_code}"})
            continue
        rules = _parse_rules(r.output or "")
        by_action: dict[str, int] = {}
        for x in rules:
            by_action[x["action"]] = by_action.get(x["action"], 0) + 1
        matched = [x for x in rules if not needle or needle in
                   f"{x['num']} {x['to']} {x['action']} {x['from']} {x['comment']}".lower()]
        shown = matched[:cap]
        total_matched += len(matched); total_shown += len(shown)
        entry = {
            "server": r.target,
            "reachable": True,
            "total_rules": len(rules),
            "by_action": by_action,
            "matched_filter": len(matched),
            "showing": len(shown),
            "rules": [{
                "position": x["num"], "action": x["action"], "to": x["to"],
                "from": x["from"], "comment": x["comment"] or None,
                "added_by_this_tool": x["comment"].startswith("mcp by:"),
            } for x in shown],
        }
        # Truncation is stated, never silent. A list that quietly stops is read
        # as a complete list, and that is how a rule gets missed.
        if len(shown) < len(matched):
            entry["truncated"] = (
                f"showing {len(shown)} of {len(matched)} matching rules on "
                f"{r.target}. Narrow it with contains=, or raise limit=."
            )
        per_server.append(entry)

    return {
        "scope": "every rule on the server, not only what this tool added",
        "filter": contains or "(none)",
        "servers": per_server,
        "matched_total": total_matched,
        "shown_total": total_shown,
        "complete": total_shown == total_matched,
        "note": (
            "This is the whole firewall. Most of these rules predate this tool "
            "and belong to customers, the APIBAN feed or manual fraud blocks. "
            "ufw is first-match-wins, so a rule's position decides whether it "
            "ever fires - use ufw_check_ip for a verdict on one address."
        ),
    }


@mcp.prompt(name="authorize_customer_ip", title="Authorize a Customer IP")
def _p_allow(ip_address: str, ticket: str = "") -> str:
    return (
        "Use the ufw-mcp connector for this, and only that connector: the tools "
        f"whose names begin ufw_. Authorize {ip_address} for SIP on the voice "
        "switches.\n\n"
        "Run ufw_check_ip FIRST and tell me what it says. If it reports the "
        "address is blocked by a deny above, STOP and explain that adding an "
        "allow would silently do nothing and the deny has to be cleared first - "
        "do not try to work around it. Otherwise call ufw_allow_ip with "
        "confirm=false, show me exactly what will run, and wait for me to say "
        "go before calling again with confirm=true.\n\n"
        "Confirm at the end that it succeeded on BOTH switches. If only one "
        "worked, say so plainly: that is an intermittent fault for the customer, "
        "not a success."
    )


def main() -> None:
    srv = load_server_config()
    if srv.transport == "stdio":
        mcp.run()
        return
    auth = load_auth_config()
    if not auth.enabled:
        logger.warning(
            "MCP_AUTH_ENABLED=false on the HTTP transport. This server can "
            "change production firewalls. Local testing only."
        )
    try:
        cfg = load_config()
        logger.info("ufw-mcp: switches=%s relay=%s@%s writes=%s",
                    ",".join(t.name for t in cfg.targets),
                    cfg.relay_user, cfg.relay_host, cfg.allow_writes)
    except Exception as exc:  # noqa: BLE001
        logger.error("STARTUP CONFIG ERROR - every tool call will fail: %s", exc)
    # Dead-rule watch. A rule that never fires should find us rather than wait
    # to be asked about, so this is a background scan that mails John when a NEW
    # one appears - not a tool somebody has to remember to run.
    #
    # A daemon thread with its own event loop, rather than a server lifespan
    # hook: this fastmcp's run() takes no startup callback, and reaching into
    # its internals would break on the next pin bump.
    hours = float(os.environ.get("UFWMCP_AUDIT_INTERVAL_HOURS", "24"))
    if hours > 0:
        import threading

        from . import audit_scan

        def _watch() -> None:
            try:
                asyncio.run(audit_scan.watcher(load_config(), hours))
            except Exception as exc:  # noqa: BLE001 - never take the server down
                logger.error("dead-rule watcher stopped: %s", exc)

        threading.Thread(target=_watch, name="dead-rule-watch", daemon=True).start()
        logger.info("dead-rule watch started, every %.1fh, alerts to John", hours)

    mcp.run(transport="http", host=srv.host, port=srv.port, path=srv.path,
            stateless_http=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    main()
