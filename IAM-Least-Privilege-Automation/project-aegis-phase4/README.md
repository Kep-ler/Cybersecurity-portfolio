# Project Aegis Phase 4: Scaled Rego Arrays, Semantic CIDR Parsing, and Policy Unit Testing

Extends the Phase 3 OPA policy engine into an enterprise-grade,
verifiable validation framework.

## What Changed From Phase 3

| Area | Phase 3 | Phase 4 |
|---|---|---|
| Testing | Manual `opa eval` commands | Automated `opa test . -v` suite |
| Array iteration | Named indexes (`some i`) | Universal quantifiers (`[_]`) |
| CIDR matching | String comparison (`== "0.0.0.0/0"`) | Semantic network math (`net.cidr_contains`) |

## Stack

- Open Policy Agent (OPA) v0.68.0
- Rego policy language
- Kali Linux (aarch64)

## Policy Rules

`aegis_guardrail_v4.rego` contains three deny rules:

1. Security groups exposing port 22 (SSH) to any public IP range
2. Security groups exposing port 3389 (RDP) to any public IP range
3. S3 buckets with `block_public_acls` disabled

## Unit Tests

`aegis_guardrail_test.rego` contains two tests:

- `test_deny_ssh_open` — insecure config triggers deny
- `test_allow_clean_sg` — clean config passes with zero flags

## Test Results
