"""Executing the three privileged wrappers on both switches, through the relay.

THE ONLY COMMANDS THIS SERVER CAN RUN are the three constants below. They are
not built from caller input and are not configurable, because a configurable
command list is a guardrail that can be edited away. The caller supplies one
thing: an IPv4 address, validated here AND again inside the wrapper on the
switch, which is the copy that actually matters.

Every call fans out to BOTH switches. `198.51.100.42` is currently allowed on
core1 and denied on core2, which reaches a customer as an intermittent
fault; a tool that can write to one and not the other manufactures that bug on
purpose.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shlex
import threading
from dataclasses import dataclass, field
from typing import Optional

from .config import Config, Target

log = logging.getLogger("ufw_mcp.ufw")

ALLOW = "/usr/local/sbin/ufw-mcp-allow"                    # 5060 tcp+udp, switches only
ALLOW_ENDPOINT = "/usr/local/sbin/ufw-mcp-allow-endpoint"  # 80,443 tcp + 69 udp, endpoints only
LIST = "/usr/local/sbin/ufw-mcp-list"

# Each wrapper is installed ONLY on the boxes it belongs to: the switches do
# not carry ALLOW_ENDPOINT and the endpoints server does not carry ALLOW.
# So a request aimed at the wrong group fails at sudo rather than opening the
# wrong ports - a stronger guarantee than one shared script taking a profile
# argument, where a caller mistake would be enough.

# REVOKE IS DELIBERATELY ABSENT (John, 2026-08-18), and its absence here is the
# real control rather than the missing tool in server.py. A design-review concern in
# the 2026-08-18 design meeting was a first-level user removing a SIP trunk or
# Inteliquent address. The wrapper already refused to touch anything it had not
# created, but "for now" means the capability should not exist at all, so:
#   * this constant is gone, and _exec() only accepts ALLOW or LIST
#   * the sudoers grant on both switches was narrowed to those two paths
#   * /usr/local/sbin/ufw-mcp-revoke was deleted from both switches
# Re-enabling is: restore the constant, restore the tool, re-add the sudoers
# entry, re-install the wrapper. tests/test_no_revoke.py fails if the first two
# happen without a deliberate decision.

# The identity string is interpolated into a remote command, so it is
# constrained to what an Entra UPN can contain and nothing else.
_SAFE_ACTOR = re.compile(r"^[A-Za-z0-9._@+-]{1,64}$")
# The ticket reference is written into a `ufw ... comment "..."` argument on the
# switch, so it is constrained here AND again in the wrapper. Quotes, spaces,
# semicolons and backticks are all absent from this set on purpose.
_SAFE_TICKET = re.compile(r"^[A-Za-z0-9#._-]{1,32}$")
# Customer names legitimately contain spaces and ampersands, so those are in.
# Quotes, backticks, semicolons and $ are not, and every argument is
# shell-quoted before it is sent, so a space cannot split into two arguments.
_SAFE_CUSTOMER = re.compile(r"^[A-Za-z0-9 ._&-]{1,48}$")


class UfwError(RuntimeError):
    pass


@dataclass
class HostResult:
    target: str
    host: str
    path: str = ""          # "direct" or "relay" - which route actually worked
    ok: bool = False
    exit_code: int = -1
    output: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        d = {"switch": self.target, "ok": self.ok, "path": self.path,
             "output": self.output}
        if not self.ok:
            d["error"] = self.error or f"exit {self.exit_code}"
        return d


def validate_ip(value: str) -> str:
    """One IPv4 host address. Rejects CIDR, ranges, hostnames, metacharacters."""
    v = (value or "").strip()
    try:
        addr = ipaddress.IPv4Address(v)
    except ipaddress.AddressValueError as exc:
        raise UfwError(
            f"{value!r} is not a single IPv4 address. This tool adds one host at "
            "a time; ranges and CIDRs are refused on purpose."
        ) from exc
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        raise UfwError(f"{addr} is a loopback/multicast/reserved address.")
    return str(addr)


def validate_ticket(ticket: str) -> str:
    """Normalise a ticket reference, or '-' when none was supplied.

    '-' rather than an empty string because it is a positional argument to the
    wrapper, and an empty positional silently shifts every argument after it.
    """
    t = (ticket or "").strip()
    if not t:
        return "-"
    if not _SAFE_TICKET.match(t):
        raise UfwError(
            f"{ticket!r} is not a usable ticket reference. Letters, digits and "
            "# . _ - only, up to 32 characters."
        )
    return t


# "Ticket 12345", "ticket #12345", "INF-48213", "case 12345"...
_TICKET_IN_TEXT = re.compile(
    r"(?i)\b(?:ticket|case|ref|reference|inc|incident)\b\s*(?:no\.?|number|#)?\s*([A-Za-z0-9][A-Za-z0-9#._-]{2,31})"
)


def ticket_from_text(text: str) -> str:
    """Pull a ticket reference out of free text.

    Real calls put the ticket in `reason` instead of `ticket` - it happened
    twice within an hour of shipping, because "reason" is where a person
    naturally writes context. `reason` only reaches the audit log, so the rule
    comment silently lost the one field that explains it later. Rather than
    treat that as user error, recover it: a ticket mentioned anywhere is a
    ticket the caller meant to record.
    """
    m = _TICKET_IN_TEXT.search(text or "")
    if not m:
        return ""
    candidate = m.group(1).rstrip(".,;:")
    # A reference always carries a digit; ordinary prose does not. Without this,
    # "no reference here" yielded "here", and a rule stamped ticket:here reads
    # like a real reference to whoever finds it later.
    if not any(ch.isdigit() for ch in candidate):
        return ""
    try:
        return validate_ticket(candidate)
    except UfwError:
        return ""


_CUSTOMER_IN_TEXT = re.compile(
    r"(?i)\b(?:customer|cust|client|account|acct)\b\s*(?:name)?\s*[:=-]?\s*"
    r"([A-Za-z0-9][A-Za-z0-9 ._&-]{1,47})"
)

# First word of a candidate that means it is prose, not a name.
_NOT_A_NAME = {
    "called", "calls", "calling", "cannot", "cant", "could", "did", "does",
    "has", "have", "is", "isnt", "needs", "not", "reported", "reports", "said",
    "says", "unable", "wants", "was", "will", "with", "phone", "phones", "site",
    "ip", "requested", "asked", "reporting", "having", "the", "their", "a", "an",
}


def customer_from_text(text: str) -> str:
    """Pull a customer name out of free text, or "" if nothing safe is found.

    Three gates, because a wrong name in a firewall rule reads as fact:
      1. an explicit keyword (customer / cust / client / account)
      2. the value starts with an uppercase character - "EF" and
         "Example Movers" do, "called in" does not
      3. the first word is not a known prose word
    Missing a lowercase customer name is fine; inventing one is not.
    """
    m = _CUSTOMER_IN_TEXT.search(text or "")
    if not m:
        return ""
    # Cut at anything that starts a new clause.
    candidate = re.split(r"[,;()\[\]]|\s-\s|\bticket\b", m.group(1), 1,
                         flags=re.IGNORECASE)[0]
    candidate = " ".join(candidate.split()).rstrip(".,;:-")
    if not candidate or not candidate[0].isupper():
        return ""
    if candidate.split()[0].lower().strip(".,") in _NOT_A_NAME:
        return ""
    try:
        return validate_customer(candidate)
    except UfwError:
        return ""


def validate_customer(customer: str) -> str:
    """Normalise a customer name, or '-' when none was supplied."""
    c = " ".join((customer or "").split())
    if not c:
        return "-"
    if not _SAFE_CUSTOMER.match(c):
        raise UfwError(
            f"{customer!r} is not a usable customer name. Letters, digits, "
            "spaces and . _ & - only, up to 48 characters."
        )
    return c


def validate_actor(actor: str) -> str:
    a = (actor or "").strip()
    if not _SAFE_ACTOR.match(a):
        raise UfwError("Refusing to run with an unusable caller identity.")
    return a


class Fleet:
    """One relay connection, a channel per switch, reused across calls."""

    def __init__(self, cfg: Config):
        self._cfg = cfg
        self._relay = None
        self._lock = threading.Lock()

    # -- relay ---------------------------------------------------------------
    def _relay_client(self):
        import paramiko

        with self._lock:
            if self._relay is not None:
                tr = self._relay.get_transport()
                if tr is not None and tr.is_active():
                    return self._relay
                try:
                    self._relay.close()
                except Exception:  # noqa: BLE001
                    pass
                self._relay = None
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = dict(
                hostname=self._cfg.relay_host, port=self._cfg.relay_port,
                username=self._cfg.relay_user, timeout=self._cfg.ssh_timeout,
                banner_timeout=self._cfg.ssh_timeout, auth_timeout=self._cfg.ssh_timeout,
                allow_agent=False, look_for_keys=False,
            )
            if self._cfg.relay_key_file:
                kwargs["key_filename"] = self._cfg.relay_key_file
            if self._cfg.relay_password:
                kwargs["password"] = self._cfg.relay_password
            try:
                c.connect(**kwargs)
            except Exception as exc:  # noqa: BLE001
                raise UfwError(
                    f"Could not reach the SSH relay {self._cfg.relay_user}@"
                    f"{self._cfg.relay_host} ({type(exc).__name__}). Nothing was "
                    "attempted against either switch - every path goes through it."
                ) from exc
            tr = c.get_transport()
            if tr:
                tr.set_keepalive(30)
            self._relay = c
            return c

    def _exec(self, target: Target, argv: list[str]) -> HostResult:
        """Run one wrapper on one switch. argv[0] must be a wrapper constant."""
        import paramiko

        if argv[0] not in (ALLOW, ALLOW_ENDPOINT, LIST):
            raise UfwError(
                "refusing to run a command that is not the allow or list "
                "wrapper. Revoke was removed deliberately; see the note above."
            )
        res = HostResult(target=target.name, host=target.host)
        client = None
        try:
            client, res.path = self._open(target)
            # shlex.quote every argument. A customer name contains spaces, and
            # an unquoted one would split into two positional arguments and
            # shift everything after it.
            cmd = "sudo -n " + " ".join(shlex.quote(a) for a in argv)
            _in, out, err = client.exec_command(cmd, timeout=120)
            stdout = out.read().decode("utf-8", "replace")
            stderr = err.read().decode("utf-8", "replace")
            res.exit_code = out.channel.recv_exit_status()
            res.output = (stdout + stderr).strip()
            res.ok = res.exit_code == 0
            if not res.ok:
                res.error = res.output or f"exit {res.exit_code}"
        except UfwError as exc:
            res.error = str(exc)
        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass
        return res

    def _open(self, target: Target):
        """Direct first, relay second. Returns (client, path_used).

        Direct is one hop and needs no shared relay password. The relay is only
        tried if direct fails AND one is configured, so a switch that stops
        accepting our egress address degrades to the slower path instead of
        taking the tool offline.
        """
        import paramiko

        common = dict(
            username=self._cfg.ssh_user, key_filename=self._cfg.ssh_key_file,
            timeout=self._cfg.ssh_timeout, allow_agent=False, look_for_keys=False,
        )
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(target.host, **common)
            return c, "direct"
        except Exception as direct_exc:  # noqa: BLE001
            if not self._cfg.relay_host:
                raise UfwError(
                    f"Direct SSH to {target.name} ({target.host}) failed "
                    f"({type(direct_exc).__name__}) and no relay is configured. "
                    "Check that our egress address is still allowed on that switch."
                ) from direct_exc
            log.warning("direct SSH to %s failed (%s); falling back to the relay",
                        target.name, type(direct_exc).__name__)
            relay = self._relay_client()
            chan = relay.get_transport().open_channel(
                "direct-tcpip", (target.host, 22), ("127.0.0.1", 0),
                timeout=self._cfg.ssh_timeout,
            )
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(target.host, sock=chan, **common)
            return c, "relay"

    # -- public --------------------------------------------------------------
    async def run_all(self, argv: list[str], targets=None) -> list[HostResult]:
        """Same command on every target in the group, concurrently."""
        group = self._cfg.targets if targets is None else targets
        return list(await asyncio.gather(
            *(asyncio.to_thread(self._exec, t, argv) for t in group)
        ))

    def _args(self, wrapper, ip, actor, ticket, customer, override_deny):
        argv = [wrapper, validate_ip(ip), validate_actor(actor),
                validate_ticket(ticket), validate_customer(customer)]
        if override_deny:
            argv.append("override-deny")
        return argv

    async def allow(self, ip: str, actor: str, ticket: str = "",
                    customer: str = "", override_deny: bool = False) -> list[HostResult]:
        """SIP on the voice switches: 5060 tcp+udp."""
        return await self.run_all(
            self._args(ALLOW, ip, actor, ticket, customer, override_deny))

    async def allow_endpoint(self, ip: str, actor: str, ticket: str = "",
                             customer: str = "", override_deny: bool = False) -> list[HostResult]:
        """Provisioning on the endpoints server: 80/443 tcp + 69 udp (TFTP)."""
        return await self.run_all(
            self._args(ALLOW_ENDPOINT, ip, actor, ticket, customer, override_deny),
            targets=self._cfg.endpoint_targets)

    async def list_mode(self, mode: str = "tagged", include_endpoints: bool = True,
                        targets=None) -> list[HostResult]:
        if mode not in ("tagged", "counts", "conflicts", "cidrs", "all"):
            raise UfwError("mode must be tagged, counts, conflicts, cidrs or all")
        if targets is None:
            targets = list(self._cfg.targets)
            if include_endpoints:
                targets += list(self._cfg.endpoint_targets)
        return await self.run_all([LIST, mode], targets=targets)

    async def search(self, ip: str, include_endpoints: bool = True) -> list[HostResult]:
        """Every rule mentioning this address, anywhere in the chain.

        The address is validated here as well as inside the wrapper. It is the
        only caller-supplied value that reaches a wrapper argument, and the
        wrapper interpolates it into a regex, so both ends check it.
        """
        address = validate_ip(ip)
        group = list(self._cfg.targets)
        if include_endpoints:
            group += list(self._cfg.endpoint_targets)
        return await self.run_all([LIST, "search", address], targets=group)

    def close(self) -> None:
        with self._lock:
            if self._relay is not None:
                try:
                    self._relay.close()
                finally:
                    self._relay = None


_FLEET: Optional[Fleet] = None
_FLEET_LOCK = threading.Lock()


def fleet(cfg: Config) -> Fleet:
    global _FLEET
    with _FLEET_LOCK:
        if _FLEET is None:
            _FLEET = Fleet(cfg)
        return _FLEET
