# Exact commands for approval

NOTHING HERE HAS BEEN RUN. Two parts, approve independently.

Targets: **core1 203.0.113.20** and **core2 198.51.100.6**, identical on
both. Reached via the relay as today.

---

# PART A — stand up the least-privilege account

Run as your admin user on each server. Idempotent; safe to re-run.

## A1. Create the account (unprivileged, no groups)

```bash
sudo useradd --create-home --shell /bin/bash --comment 'ufw allow automation (ufw-mcp)' nocufw
```

No `-G sudo`. No supplementary groups. No password is set, so password login is
impossible; it authenticates by key only.

## A2. Install its key

```bash
sudo install -d -m 700 -o nocufw -g nocufw /home/nocufw/.ssh
sudo tee /home/nocufw/.ssh/authorized_keys >/dev/null <<'KEY'
<paste the contents of your own .pub file here>
KEY
sudo chown nocufw:nocufw /home/nocufw/.ssh/authorized_keys
sudo chmod 600 /home/nocufw/.ssh/authorized_keys
```

## A3. Install the three wrappers

Bodies are in this directory: `ufw-mcp-allow`, `ufw-mcp-revoke`,
`ufw-mcp-list`. Root-owned, 0755, and critically NOT writable by `nocufw` --
a wrapper it can edit is a one-line root escalation.

```bash
sudo install -o root -g root -m 0755 ufw-mcp-allow  /usr/local/sbin/ufw-mcp-allow
sudo install -o root -g root -m 0755 ufw-mcp-revoke /usr/local/sbin/ufw-mcp-revoke
sudo install -o root -g root -m 0755 ufw-mcp-list   /usr/local/sbin/ufw-mcp-list
```

## A4. Grant exactly those three, and nothing else

```bash
sudo visudo -c -f /dev/stdin <<'SUDO' && sudo tee /etc/sudoers.d/ufw-mcp >/dev/null <<'SUDO2'
Cmnd_Alias UFW_MCP = /usr/local/sbin/ufw-mcp-allow, /usr/local/sbin/ufw-mcp-list
nocufw ALL=(root) NOPASSWD: UFW_MCP
Defaults!UFW_MCP !requiretty
SUDO
Cmnd_Alias UFW_MCP = /usr/local/sbin/ufw-mcp-allow, /usr/local/sbin/ufw-mcp-list
nocufw ALL=(root) NOPASSWD: UFW_MCP
Defaults!UFW_MCP !requiretty
SUDO2
sudo chmod 0440 /etc/sudoers.d/ufw-mcp
sudo visudo -c
```

`visudo -c` at the end validates the whole sudoers set. If it reports a
problem, fix it in that shell before logging out, or you can lock yourself out
of sudo.

---

# PART B — verify the grant is actually narrow

```bash
sudo -l -U nocufw
```

Must list ONLY the three `/usr/local/sbin/ufw-mcp-*` paths. Anything more means
A4 is wrong.

```bash
ls -l /usr/local/sbin/ufw-mcp-*      # expect  -rwxr-xr-x root root
ls -ld /usr/local/sbin               # expect  drwxr-xr-x root root
sudo -u nocufw sudo -n /usr/local/sbin/ufw-mcp-list counts
sudo -u nocufw sudo -n /usr/local/sbin/ufw-mcp-list conflicts
```

The last one should reprint the dead rules from Part C, which is a live proof
the tooling sees what we saw.

Negative test, both must be refused:

```bash
sudo -u nocufw sudo -n /usr/sbin/ufw status         # expect: not allowed
sudo -u nocufw sudo -n /bin/bash                    # expect: not allowed
```

---

# PART C — the five dead rules (needs a decision, not just approval)

These already exist and do nothing. Rule numbers shift as APIBAN runs, so every
command below looks the rule up by pattern rather than hardcoding a number.

Current state:

```
core1   DENY 198.51.100.36  # FraudWatch 2026-07-15 example-isp-NY /32
            ALLOW 5060 tcp+udp 198.51.100.36        dead
core2   DENY 198.51.100.36  # FraudWatch 2026-07-15 example-isp-NY /32
            DENY 198.51.100.42  (no comment)
            ALLOW 5060 tcp+udp 198.51.100.36        dead
            ALLOW 5060 tcp+udp 198.51.100.42        dead
```

`198.51.100.42` is allowed and WORKING on core1 and denied on core2.
That asymmetry is almost certainly unintended.

**Option 1 - keep the blocks, delete the dead allows.** Correct if the FraudWatch
block on example-isp-NY is still wanted. Removes the false impression that the
customer is allowed.

**Option 2 - remove the DENY so the existing allows take effect.** Correct if
example-isp-NY was cleared and someone tried to unblock it in July and did not
realise it failed. This deletes a fraud block, so it is your call, not mine.

Inspect first, on each server:

```bash
sudo ufw status numbered | grep -E '198\.51\.100\.36|198\.51\.100\.6'
sudo grep -i 'example-isp\|198\.51\.100\.36' /var/log/ufw.log* 2>/dev/null | tail -5
```

Then, for whichever rule you decide to remove, delete by looked-up number:

```bash
N=$(sudo ufw status numbered | grep 'DENY' | grep '198.51.100.36' | sed -n 's/^\[[ ]*\([0-9]\+\)\].*/\1/p' | head -1)
echo "would delete rule [$N]:"; sudo ufw status numbered | sed -n "/^\[[ ]*$N\]/p"
# then, only if that line is the one you mean:
sudo ufw --force delete "$N"
```

Do them one at a time and re-read the numbering between each, because deleting
renumbers everything below.

---

# apiban2ufw.sh: read, Part A and B unaffected

It diffs only rules commented `From APIBAN` and never touches ALLOW rules, so
nothing here can be clobbered by it. It runs every 4 minutes and adds with
`ufw insert 1`, i.e. at the TOP -- so an allow inserted above a deny stays above
today's denies but not tomorrow's. Both example-isp-NY denies are FraudWatch rather
than APIBAN, so removing or superseding them is durable.
