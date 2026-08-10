# Project Aegis Phase 5-7: Policy Hardening

Same policy engine from Phase 3-4, pushed through three more rounds of fixes after my manager caught a real bug and then asked for two more improvements on top of it.

## Phase 5 — Fixed a parameter order bug

The Phase 4 policy checked CIDR ranges like this:

```rego
net.cidr_contains(cidr, "0.0.0.0/0")
```

Looked fine, passed all my tests. My manager caught it in review. `net.cidr_contains(A, B)` checks if A contains B — so this was asking "does the user's CIDR contain the whole internet," which is only true if someone typed the exact string `0.0.0.0/0`. Anyone using `0.0.0.0/1` or `128.0.0.0/1` (each one still covers half the internet) would slide right past the check.

Fix was flipping the order:

```rego
net.cidr_contains("0.0.0.0/0", cidr)
```

Now it asks "does the whole internet contain the user's CIDR" — which correctly catches any public range, not just the one exact string.

Wrote two new tests before fixing anything, confirmed they failed against the broken policy, then confirmed they passed after the fix — `test_evasion_lower_bound` and `test_evasion_upper_bound`.

## Phase 6 — Stopped repeating myself

I had one whole `deny` block for port 22 and a second, nearly identical block for port 3389. Adding a new restricted port meant copy-pasting the entire thing again, which is exactly how bugs get introduced.

Replaced both with a single set:

```rego
restricted_ports := {22, 3389, 3306, 5432}
```

Added the two common database ports (MySQL, PostgreSQL) without writing any new logic, just adding two numbers to the set.

Also closed a gap I hadn't thought of until it was pointed out: a security group rule opening ports 20 through 80 would let port 22 through untouched, because my old checks only looked at exact `from_port`/`to_port` matches, not whether a restricted port was hiding somewhere inside a wider range. Fixed using `numbers.range(ingress.from_port, ingress.to_port)[_]`, which expands the whole range and checks every port inside it against the restricted set.

Added RFC 1918 exceptions (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) so normal internal traffic doesn't get flagged.

New test: `test_deny_port_range_overlap`, using a rule that opens 20-80 to prove the hidden-port case gets caught.

## Phase 7 — IPv6 and the "-1" wildcard

Two gaps left after Phase 6:

1. Everything I'd written only checked `cidr_blocks` (IPv4). A rule using `ipv6_cidr_blocks` with `::/0` — the IPv6 version of wide open — would pass through completely unchecked.
2. AWS lets you set `protocol = "-1"`, meaning "all protocols, all ports." A rule like that combined with a public CIDR opens every restricted port at once, without ever naming a specific port number my existing checks were looking for.

Added a helper that checks both IPv4 and IPv6 CIDR fields, and a separate deny rule specifically for the `-1` wildcard case, so it gets caught outright instead of relying on the port-range logic to somehow catch it.

Two new tests: `test_deny_ipv6_ssh_open` and `test_deny_wildcard_protocol`.

## Where things stand

`aegis_guardrail_v7.rego` is the current version. v5 and v6 aren't kept as live files here, each one just got replaced by the next once its fix was folded in — the point of this README is showing what changed and why at each step, not maintaining old versions side by side.

```
opa test aegis_guardrail_v7.rego aegis_guardrail_test.rego -v

data.aegis_test.test_deny_ssh_open: PASS
data.aegis_test.test_deny_db_open: PASS
data.aegis_test.test_deny_ipv6_ssh_open: PASS
data.aegis_test.test_deny_wildcard_protocol: PASS
data.aegis_test.test_deny_port_range_overlap: PASS
data.aegis_test.test_allow_clean_sg: PASS
--------------------------------------------------------------------------------
PASS: 6/6
```

## Usage

```bash
# run the full test suite
opa test aegis_guardrail_v7.rego aegis_guardrail_test.rego -v

# check a real Terraform plan
opa eval -d aegis_guardrail_v7.rego --input tfplan.json "data.aegis.deny"

# use as a pipeline gate (non-zero exit if anything is denied)
opa eval -d aegis_guardrail_v7.rego --input tfplan.json --fail-defined "data.aegis.deny[x]"
```

## Stack

Open Policy Agent, Rego, Terraform, Kali Linux
