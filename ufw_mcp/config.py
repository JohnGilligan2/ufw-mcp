"""Configuration for ufw-mcp.

Reaches the two VoIP switches by SSH as nocufw, then sudo to one of two
wrapper scripts. Two paths, tried in order:

  1. DIRECT   container -> nocufw@switch          (preferred)
  2. RELAY    container -> relay -> nocufw@switch (fallback, if configured)

Direct began working 2026-08-18 once our egress was allowed on the switches;
before that only the relay could reach them. The relay is retained on purpose
rather than deleted: direct access depends on a UFW allow rule on the switches
themselves, and if that rule is ever removed this tool would lose the ability
to reach the firewalls it exists to manage. The relay gets there through the
broader 203.0.113.20/26 grant instead.

Two things are deliberately NOT configurable, because making them configurable
is how a guardrail becomes a suggestion:

* the remote commands. Only the three wrapper paths are ever executed, and
  they are constants in ufw.py, not env values.
* the target port. The wrapper hardcodes 5060 tcp+udp, which is the house
  standard command documented in the runbook.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in ("1", "true", "yes", "on")


def _read_secret(var: str) -> str:
    """VAR_B64 wins over VAR. Base64 because Portainer substitutes stack
    variables into compose and Compose then expands the result, so a `$` in a
    plaintext secret is silently deleted."""
    b64 = os.environ.get(f"{var}_B64", "").strip()
    if b64:
        try:
            return base64.b64decode(b64, validate=True).decode("utf-8").rstrip("\r\n")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise RuntimeError(f"{var}_B64 is not valid base64 UTF-8: {exc}") from exc
    return os.environ.get(var, "")


@dataclass(frozen=True)
class Target:
    """One VoIP switch."""

    name: str
    host: str


@dataclass(frozen=True)
class Config:
    # Every rule goes on BOTH switches. 198.51.100.42 is allowed on core1
    # and denied on core2 right now, which presents to a customer as an
    # intermittent fault and is very hard to diagnose. A tool that can write to
    # one and not the other manufactures that bug, so fan-out is not optional.
    targets: tuple = field(default_factory=tuple)
    # The endpoints server. Different box, different job, different ports:
    # phones fetch config from it over HTTP/HTTPS and TFTP, and nothing
    # listens on 5060 there. Kept as a separate group so a SIP request can
    # never land on it and vice versa.
    endpoint_targets: tuple = field(default_factory=tuple)

    ssh_user: str = "nocufw"
    ssh_key_file: str = ""
    ssh_timeout: float = 20.0

    # relay
    relay_host: str = ""
    relay_port: int = 22
    relay_user: str = ""
    relay_password: str = ""
    relay_key_file: str = ""

    # Writes require confirm=true from the caller. This is the deployment-wide
    # master; with it false, the server is read-only regardless of arguments.
    allow_writes: bool = True
    # Adds to the endpoints (provisioning) server are OFF by default as of
    # 2026-08-20. Three fraud addresses were found sitting in ALLOW rules on
    # endpoints1 covering 80/tcp, 443/tcp and 69/udp. That is provisioning
    # access: it lets a caller pull phone config files, which carry SIP
    # credentials. 60+ extensions across 23 customer domains were compromised
    # and used for 25+ hours of toll fraud. Until it is understood how those
    # rules were added, first-level support does not get to add more of them.
    # Reads (ufw_list_rules, ufw_check_ip) are unaffected and still cover
    # endpoints, because seeing what is there is how this got caught.
    # Re-enable deliberately with UFWMCP_ENDPOINT_WRITES=true.
    endpoint_writes: bool = False
    # Refuse to add more than this many addresses in one call.
    max_ips_per_call: int = 25
    audit_file: str = "/audit/ufw-mcp.log"


@dataclass(frozen=True)
class AuthConfig:
    enabled: bool
    tenant_id: str = ""
    client_id: str = ""
    identifier_uri: str = ""
    scope_name: str = "access_as_user"
    required_scopes: tuple[str, ...] = ()
    base_url: str = ""
    advertise_offline_access: bool = True


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    path: str = "/mcp"
    transport: str = "stdio"


def load_auth_config() -> AuthConfig:
    if not _env_bool("MCP_AUTH_ENABLED", False):
        return AuthConfig(enabled=False)
    vals = {k: os.environ.get(k, "") for k in
            ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_IDENTIFIER_URI", "MCP_BASE_URL")}
    missing = [k for k, v in vals.items() if not v]
    if missing:
        raise RuntimeError(
            "MCP_AUTH_ENABLED=true but these are unset: " + ", ".join(missing)
            + ". Refusing to start half-configured."
        )
    raw = os.environ.get("ENTRA_REQUIRED_SCOPES", "").strip()
    return AuthConfig(
        enabled=True,
        tenant_id=vals["ENTRA_TENANT_ID"],
        client_id=vals["ENTRA_CLIENT_ID"],
        identifier_uri=vals["ENTRA_IDENTIFIER_URI"],
        scope_name=os.environ.get("ENTRA_SCOPE_NAME", "access_as_user"),
        required_scopes=tuple(s for s in raw.replace(",", " ").split() if s),
        base_url=vals["MCP_BASE_URL"],
        advertise_offline_access=_env_bool("ENTRA_ADVERTISE_OFFLINE_ACCESS", True),
    )


def load_server_config() -> ServerConfig:
    return ServerConfig(
        host=os.environ.get("MCP_BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("MCP_PORT", "8000")),
        path=os.environ.get("MCP_PATH", "/mcp"),
        transport=os.environ.get("MCP_TRANSPORT", "stdio").strip().lower(),
    )



def _materialise_key() -> str:
    """Return a path to the nocufw private key.

    Portainer has no secret store we use, and baking a key into the image puts
    it in every layer and every registry copy. So the key travels as a base64
    stack variable and is written to disk at startup with 0600, inside the
    container only. UFWMCP_SSH_KEY_FILE still wins if a real file is mounted.
    """
    explicit = os.environ.get("UFWMCP_SSH_KEY_FILE", "").strip()
    if explicit:
        if not os.path.exists(explicit):
            raise RuntimeError(f"UFWMCP_SSH_KEY_FILE={explicit} does not exist.")
        return explicit

    blob = os.environ.get("UFWMCP_SSH_KEY_B64", "").strip()
    if not blob:
        raise RuntimeError(
            "Neither UFWMCP_SSH_KEY_FILE nor UFWMCP_SSH_KEY_B64 is set. "
            "nocufw is key-auth only, so there is no password fallback."
        )
    try:
        pem = base64.b64decode(blob, validate=True)
    except binascii.Error as exc:
        raise RuntimeError(f"UFWMCP_SSH_KEY_B64 is not valid base64: {exc}") from exc
    if b"PRIVATE KEY" not in pem:
        raise RuntimeError("UFWMCP_SSH_KEY_B64 does not decode to a private key.")
    # OpenSSH refuses a key without a trailing newline.
    if not pem.endswith(b"\n"):
        pem += b"\n"
    path = os.environ.get("UFWMCP_SSH_KEY_PATH", "/keys/nocufw_ed25519")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as fh:
        fh.write(pem)
    os.chmod(path, 0o600)
    return path


def _parse_targets(raw: str, var: str) -> list:
    """Parse 'name=host,name=host'. Empty is allowed; malformed is not."""
    out = []
    for item in (raw or "").replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise RuntimeError(f"{var} entry {item!r} is not name=host.")
        name, host = item.split("=", 1)
        out.append(Target(name=name.strip(), host=host.strip()))
    return out


def load_config() -> Config:
    raw = os.environ.get("UFWMCP_TARGETS", "").strip()
    if not raw:
        raise RuntimeError(
            "UFWMCP_TARGETS is unset. Expected 'name=host,name=host', e.g. "
            "'core1=203.0.113.20,core2=198.51.100.6'."
        )
    targets = _parse_targets(raw, "UFWMCP_TARGETS")
    if not targets:
        raise RuntimeError("UFWMCP_TARGETS parsed to nothing.")

    # The relay is now a FALLBACK, not the only path. Direct SSH to the
    # switches started working on 2026-08-18 once our egress was allowed on
    # them. Direct is preferred (one hop, no shared relay password), but the
    # relay is kept because direct access depends on a UFW allow rule ON the
    # switches: if that rule is ever removed, the tool would otherwise lose the
    # ability to reach the very firewalls it manages. The relay reaches them
    # via the broader 203.0.113.20/26 grant, which is more durable.
    endpoint_targets = _parse_targets(
        os.environ.get("UFWMCP_ENDPOINT_TARGETS", ""), "UFWMCP_ENDPOINT_TARGETS")

    relay_host = os.environ.get("UFWMCP_RELAY_HOST", "").strip()
    key_file = _materialise_key()

    return Config(
        targets=tuple(targets),
        endpoint_targets=tuple(endpoint_targets),
        ssh_user=os.environ.get("UFWMCP_SSH_USER", "nocufw").strip(),
        ssh_key_file=key_file,
        ssh_timeout=float(os.environ.get("UFWMCP_SSH_TIMEOUT", "20")),
        relay_host=relay_host,
        relay_port=int(os.environ.get("UFWMCP_RELAY_PORT", "22")),
        relay_user=os.environ.get("UFWMCP_RELAY_USER", "").strip(),
        relay_password=_read_secret("UFWMCP_RELAY_PASSWORD"),
        relay_key_file=os.environ.get("UFWMCP_RELAY_KEY_FILE", "").strip(),
        allow_writes=_env_bool("UFWMCP_ALLOW_WRITES", True),
        endpoint_writes=_env_bool("UFWMCP_ENDPOINT_WRITES", False),
        max_ips_per_call=int(os.environ.get("UFWMCP_MAX_IPS_PER_CALL", "25")),
        audit_file=os.environ.get("UFWMCP_AUDIT_FILE", "/audit/ufw-mcp.log").strip(),
    )
