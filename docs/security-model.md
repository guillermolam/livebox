# Security model and safety boundaries

This document defines the trust model, scope controls, and two-lane policy for
`livebox audit` and related features. It is a cross-cutting requirement for all
audit, tool-bridge, AI-orchestration, playbook, and wireless-lab work.

## Actor model

The audit commands are designed for the **authorized internal security
operator** who already has administrative access to their own Livebox router
and their own devices.

```yaml
actor:
  role: authorized_internal_security_operator
  starting_position: authenticated_router_administrator
  target_scope: owned_router_and_explicitly_owned_devices

  goals:
    - accurate_device_inventory
    - exposure_and_misconfiguration_detection
    - independent_finding_corroboration
    - backup_controlled_remediation
    - verified_retests

  excluded_capabilities:
    - active_directory_attacks
    - wifi_password_cracking
    - handshake_capture_or_offline_password_recovery
    - credential_spraying_or_brute_force
    - deauthentication_or_evil_twin_attacks
    - persistence_or_backdoor_deployment
```

The router is the authoritative source of truth for the device inventory: MAC
addresses, private IPv4/IPv6 assignments, SSID/band/interface association, and
online status. The operator explicitly approves which of those devices may be
actively probed. A device appearing later with a new MAC starts as
`unclassified` and is not scanned automatically.

## Two-lane policy

### Lane 1 — Live router / LAN (read-first, reversible)

- Prefer read-only inventory from the router CGI telemetry.
- Any mutative action (router config change, temporary test rule, etc.) requires
  a preview, an explicit approval, a backup, a rollback plan, and a restore-state
  verification.
- Captures and probes run only for approved devices and only for the duration
  requested by the operator.
- No silent background capture, no DNS/routing interception, no packet
  redirection, no credential harvesting.

### Lane 2 — Isolated lab (mutative / validation)

- Exploit validation, OOB interaction servers, and wireless attack exercises run
  only in isolated environments against explicitly approved targets.
- Prefer disposable clones. When the real router or a real device is used, the
  operator must first save a configuration snapshot and restore it afterward.
- All test artifacts are removed and cleanup is verified.

## Scope manifest

Every active probe is gated by a scope manifest (`audit.Manifest`). The schema
is documented in the source at `src/audit/scope.go`.

Key rules enforced by `Manifest.Check`:

- Unknown MAC → rejected.
- Unknown IP → rejected.
- Approved MAC with a different current IP → rejected (stale-lease protection).
- `approval_status != approved` → rejected.

## Baseline snapshot format

Before running an audit or making changes, capture a timestamped snapshot of the
router state:

```json
{
  "actor": "authenticated_router_admin",
  "source_of_authority": "router_admin_session",
  "not_exploited_to_gain_access": true,
  "timestamp_utc": "2026-11-20T10:00:00Z",
  "scope_approval_id": "scope-2026-11-20-001",
  "config_snapshot_hash": "sha256:...",
  "secrets_redacted": true
}
```

The snapshot includes router configuration data (clients, leases, NAT, DMZ,
UPnP, firewall, DNS, IPv6, Wi-Fi state) but **must not** include Wi-Fi
passphrases, credentials, or session tokens.

## Redaction rules

Audit reports and evidence files:

- Must not contain the Wi-Fi PSK or admin password.
- Must not contain raw session cookies or httokens.
- Should avoid exposing device hostnames unless they are operationally relevant.
- Use stable device IDs derived from MACs (see `audit.DeviceIDFromMAC`) instead
  of raw MACs in shared reports.

## Finding confidence levels

A finding must progress through evidence states before it is reported with
confidence:

| State | Meaning |
|-------|---------|
| `detected` | Tool or router telemetry observed the condition. |
| `corroborated` | A second, independent source confirms the condition. |
| `verified_in_authorized_lab` | A benign replayable proof capsule validated the condition in an isolated lab. |
| `inconclusive` | Evidence is conflicting or insufficient. |
| `false_positive` | A contradictory control disproves the condition. |

A banner match or single-tool verdict alone is never sufficient to mark a
finding as verified.

## Stop conditions

Any command must abort when:

- The scope manifest is missing, unreadable, or empty.
- A target resolves to an out-of-scope IP or MAC.
- A critical router configuration change is requested without an approval record.
- A human approval gate returns a denial or timeout.
- The operator presses Ctrl-C / the context is cancelled.
