# livebox

A command-line tool to manage an **Orange Livebox 6** (Arcadyan) router.

Forked from [maelvls/livebox](https://github.com/maelvls/livebox), which
targets the Livebox 4 and 5 through their `/ws` JSON API, and re-implemented
for the Livebox 6 web-UI flow: authentication via `login.cgi`, reads via
`cgi/*.js`, and writes via `apply_abstract.cgi` — all with the router's own
AES obfuscation. Use the upstream project for Livebox 4/5.

```
┌──────────┐   login.cgi (AES fields)   ┌──────────┐
│ livebox  │ ─────────────────────────► │ Livebox 6│
│   CLI    │   cgi/*.js  (reads)        │ (Arcadyan)│
│          │   apply_abstract.cgi(writes)         │
└──────────┘ ◄───────────────────────── └──────────┘
```

## Install

Requires Go 1.27 or later:

```sh
go install github.com/guillermolam/livebox@latest
```

or build from source:

```sh
git clone https://github.com/guillermolam/livebox.git
cd livebox && go build .
```

A container image is also available (build from the repo root):

```sh
podman build -f ~/livebox-podman/Containerfile -t livebox-cli .
```

## Quickstart

```sh
livebox login                  # save address + password (~/.config/livebox.yml)
livebox ls                     # devices on the LAN
livebox wifi                   # Wi-Fi status per band
livebox dmz get                # current DMZ host
livebox static-lease set --mac AA:BB:CC:DD:EE:FF --ip 192.168.1.50 --name nas
livebox reboot
```

## Commands

| Group | Command | Type | Description |
|---|---|---|---|
| — | `login` | — | Save credentials and test the login |
| — | `ls` | read | Devices and their IP/MAC addresses |
| — | `speed` | read | WAN sync rates (DSL only; errors on fiber) |
| — | `fiber` | read | GPON/ONT transceiver diagnostics + ONT password |
| — | `reboot` | write | Restart the router (~2–3 min downtime) |
| — | `api <page\|/path>` | read | Raw `cgi_*.js` data or any UI page |
| `wifi` | `wifi` / `wifi status` | read | Per-band SSID, security and key |
| `wifi` | `wifi enable` / `disable` | write | Toggle both radio bands |
| `wifi` | `wifi config` | — | *Not yet implemented* |
| `dmz` | `dmz get` | read | Current DMZ host |
| `dmz` | `dmz set <ip>` / `rm` | write | Enable/clear the DMZ |
| `port-forward` | `port-forward ls` | read | NAT forwarding rules |
| `port-forward` | `port-forward set` / `rm` | write | Add/remove a forwarding rule |
| `static-lease` | `static-lease ls` | read | Static DHCP leases |
| `static-lease` | `static-lease set` / `rm` | write | Reserve/clear a lease |
| `dns` | `dns ls` | read | Static DNS entries |
| `dns` | `dns set` / `rm` | write | Add/remove a static DNS entry |
| `pinhole` | `pinhole ls` | read | IPv4 firewall (pinhole) rules |
| `pinhole` | `pinhole set` / `rm` | write | Add/remove a pinhole rule |
| `phone` | `phone` | — | *Not yet implemented* |

Full usage, flags and sample outputs: **[docs/commands.md](docs/commands.md)**.

## Configuration

`livebox login` stores the connection settings in `~/.config/livebox.yml`
(mode `0600`):

```yaml
address: 192.168.1.1
username: admin
password: <your admin password>
```

Defaults are `192.168.1.1` / `admin` / no password. Any invocation can
override them with the global flags `--address`, `--username`,
`--password` (and get more detail with `--debug`).

> **Note:** the Livebox allows one web session at a time — logging in from
> the CLI evicts the browser session and vice-versa. This is normal.

## How it works

The Livebox 6 web UI is a frameset of static `.htm` pages plus JavaScript
data files. There is no documented API, so this CLI speaks the same
protocol the browser does:

1. **Login** — `POST /login.cgi` with the username/password obfuscated as
   AES-256-CBC fields keyed by the login page's *spacer image*.
2. **Reads** — `GET /cgi/cgi_<page>.js?_tn=<token>` returns `addCfg(name, id, value)`
   calls; the numeric IDs address the writable fields.
3. **Writes** — `POST /apply_abstract.cgi` with one AES-encrypted field per
   *changed* cfg entry, plus the action name, page token and a fresh
   `gui_cehck_token` (the typo is the router's).

Details, diagrams and captured payload examples:

| Document | Contents |
|---|---|
| [docs/protocol.md](docs/protocol.md) | The reverse-engineered wire protocol: spacer layout, `do_encode`, login/read/write flows |
| [docs/writes.md](docs/writes.md) | Action table, cfg field IDs, per-command write recipes |
| [docs/architecture.md](docs/architecture.md) | Go package layout and request flow |
| [docs/commands.md](docs/commands.md) | Every command with flags and sample output |

## Development

```sh
gofmt -l . && go vet ./... && go test ./...
go build -o livebox .
```

Tests run against captured router fixtures in `testdata/livebox6/` (real
`cgi/*.js` bodies and pages), so no live router is needed. The golden test
in `api/login_test.go` verifies the spacer→token derivation against the
router's own `ArcBase._t(1)` JavaScript.

Protocol support was reverse-engineered from browser HAR captures and
in-page dry-run interception of the UI's own submit path (nothing sent),
cross-checked against the router's own JavaScript (`js/global.js`,
`js/subformvar.js`, `cgi/cgi_*.js`). Captured payloads and the decrypted
action table live in the audit output described in
[docs/writes.md](docs/writes.md).

To help add support for the remaining commands (`wifi config`, `phone`):
reproduce the action in the Livebox web UI, export the HAR from the browser
developer tools, and open an issue with it.
