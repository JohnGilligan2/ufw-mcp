# ufw-mcp: least-privilege UFW allow for the VoIP servers

Proposal. Nothing here has been applied to any server.

Planned host: **ufw-mcp.example.com** (matches `itglue-mcp`, `proxmox-mcp`,
`network-mcp`). Separate server from network-mcp, because network-mcp's
read-only guarantee is AST-enforced and adding a write path deletes the property
that makes it safe to hand to five engineers. Same split as tactical-rmm-mcp /
tactical-rmm-audit-mcp.

## The house command it automates

Per Dan, and confirmed in shell history, two rules per address:

```
sudo ufw allow from <ip> to any port 5060 proto tcp
sudo ufw allow from <ip> to any port 5060 proto udp
```

Done in bulk across a carrier's ranges, then verified with
`ufw status | grep 5060 | grep -c tcp` / `-c udp`. The tool matches that shape:
the wrapper handles ONE address (so the privileged code stays small), the MCP
tool loops for bulk, and it returns the before/after counts the same way.

## What the tool adds over typing the command

**It refuses when the allow would silently do nothing.**

UFW is first-match-wins and `ufw allow` APPENDS. On these servers there are
~3,600 rules with ~2,150 DENY entries occupying the top. So if the address is
already denied, the allow lands below it, the command succeeds, the rule appears
in `ufw status`, and no packet ever passes.

This is not hypothetical. Found live on 2026-08-17, read-only:

```
core1   [2145] DENY IN 198.51.100.36   # FraudWatch 2026-07-15 example-isp-NY /32
            [3371] 5060/tcp ALLOW IN 198.51.100.36     <- dead
            [3372] 5060/udp ALLOW IN 198.51.100.36     <- dead

core2   [2145] DENY IN 198.51.100.36   # FraudWatch 2026-07-15 example-isp-NY /32
            [2150] DENY IN 198.51.100.42
            [2914] 5060/tcp ALLOW IN 198.51.100.42     <- dead
            [2915] 5060/udp ALLOW IN 198.51.100.42     <- dead
            [3440] 5060/tcp ALLOW IN 198.51.100.36     <- dead
```

`198.51.100.42` is also **inconsistent across the two cores**: working on
core1, dead on core2. That customer would present as intermittent.

The wrapper detects this and exits 4 with the offending line, rather than
reporting success. An `override-deny` argument exists to insert ABOVE the deny,
but it is deliberately not the default: superseding a fraud block should be a
decision, not a side effect.

## Audit: who added or revoked what

Three layers, all keyed to the **Entra identity from the validated JWT**, never
to an argument the caller supplies. That is the property that makes the trail
trustworthy: it is signature-checked, not self-declared. network-mcp already
does this in `server.py::_actor()` and the same code carries over.

1. **In the rule itself.** `comment "mcp by:approver@example.com <ts>"`.
   The audit lives in the artifact, so `ufw status` names who added every rule
   forever, with no log to correlate, visible to anyone on the box who has never
   heard of the MCP server.
2. **On the VoIP server.** `logger -t ufw-mcp` writes to that machine's syslog,
   so the record exists where the change happened.
3. **On the MCP server.** An append-only audit file with caller, action, target,
   host and result. **It must live on a named volume** or a Portainer redeploy
   erases it, which is a live trap here given push-to-deploy rebuilds the
   container.

Entra sign-in logs are a fourth, independent record of who authenticated.

Revoke is logged identically, and `ufw-mcp-revoke` only removes rules carrying
the `mcp by:` tag, so it physically cannot delete an APIBAN or FraudWatch entry.

## Least privilege on the box

The account is NOT a superuser. It is an ordinary user permitted to invoke one
privileged action:

```bash
sudo useradd --create-home --shell /bin/bash --comment 'ufw allow automation' nocufw
```

No `-G sudo`, no supplementary groups. Then `visudo -f /etc/sudoers.d/ufw-mcp`:

```
Cmnd_Alias UFW_MCP = /usr/local/sbin/ufw-mcp-allow, \
                     /usr/local/sbin/ufw-mcp-revoke, \
                     /usr/local/sbin/ufw-mcp-list
nocufw ALL=(root) NOPASSWD: UFW_MCP
Defaults!UFW_MCP !requiretty
```

Never `NOPASSWD: /usr/sbin/ufw *`. `ufw` also has `reset`, `disable` and
`delete`, and sudoers argument wildcards are routinely escapable. The security
boundary is the SCRIPT; sudoers only decides which binary.

**The trap that turns this into a root account:** the wrapper must be root-owned
and not writable by `nocufw`, nor sitting in a directory it can write. Install
with `install -o root -g root -m 0755`. Verify the whole grant with
`sudo -l -U nocufw` on both servers.

It does need a real shell, unlike the relay account, because the MCP tool runs
`sudo ufw-mcp-allow ...` over SSH and OpenSSH executes remote commands through
the user's shell. The shell is not the privilege; the sudoers line is.

## apiban2ufw.sh: read 2026-08-17, and it changes one thing

Runs **every 4 minutes** from `/etc/cron.d/ns_apiban`, as root.

**The good news: it does not flush or rewrite anything.** It diffs the feed
against `ufw status | grep APIBAN | grep DENY`, so it only ever considers rules
carrying its own comment. It adds the delta and removes feed entries that have
dropped off. Our ALLOW rules are invisible to it and cannot be clobbered. The
exclusion-list concern was unfounded, and the account/sudoers design stands
unchanged.

**The thing that matters:** it adds with

```
/usr/sbin/ufw insert 1 deny from $line to any comment "From APIBAN $dateVar"
```

**`insert 1`, not append.** So APIBAN puts new denies at the TOP, every four
minutes. That means "insert our allow at position 1" is not a durable position:
it is above everything that exists at the moment we write it, and below anything
APIBAN adds afterwards.

Consequence, and the wrapper now says this out loud:

* Deny came from **APIBAN** -> inserting an allow above it works until
  apiban.org lists the address again, then breaks silently. The durable fix is
  upstream at the feed, not in UFW.
* Deny is **manual / FraudWatch** -> inserting above is durable, because nothing
  re-adds it.

Both example-isp-NY denies are FraudWatch, not APIBAN, so those are the durable
case.

One latent bug worth knowing, not ours to fix today: `remove_ips_ufw` deletes by
rule spec (`ufw delete deny from $line/32`), not by comment. If an address ever
appears in both the APIBAN feed and a manual deny, a feed removal could delete
the manual rule instead.

## Still open before building

1. **Decide whether removing a fraud block is in scope.** Adding a scoped allow
   and deleting an FraudWatch DENY are different privileges. Recommend the tool
   ships with allow + revoke-own-rules only, and unblocking a fraud-blocked
   address stays manual or gets its own tighter group.
3. **Fix the five dead rules above** by hand, independently of this project.

## Revoke removed, 2026-08-18

John's call, matching Alice's concern in the design meeting that a first-level
user could remove a SIP trunk or Inteliquent address. Removed at BOTH layers,
because removing only the tool would leave the privilege in place:

* no `ufw_revoke_ip` tool, and `ufw.py` has no REVOKE constant, so the executor
  physically cannot run that path
* the sudoers grant on both switches is narrowed to `ufw-mcp-allow` and
  `ufw-mcp-list`
* `/usr/local/sbin/ufw-mcp-revoke` deleted from both switches

Verified after the change: `sudo -l -U nocufw` lists two paths, invoking the
revoke wrapper as `nocufw` is refused, and allow/list still work.

`tests/test_no_revoke.py` fails if the tool or the constant comes back, so
re-enabling is a deliberate act. Doing it properly means restoring all four:
constant, tool, sudoers entry, wrapper file.
