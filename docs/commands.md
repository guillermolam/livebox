# Command reference

All commands accept the global flags:

| Flag | Default | Meaning |
|---|---|---|
| `--address` | `192.168.1.1` (or config) | Router IP or hostname |
| `--username` | `admin` (or config) | Admin username |
| `--password` | — (or config) | Admin password (default on the box: Wi-Fi key) |
| `--debug` | `false` | Verbose HTTP logging |

Credentials come from `~/.config/livebox.yml` unless overridden. Every
invocation logs in, does its work, and leaves — there is no daemon.

Sample outputs below are from a live Livebox 6 (fiber).

---

## Session

### `login`

Interactive form (address / username / password), validates the login
against the router first, and saves to `~/.config/livebox.yml` (`0600`).
If the saved credentials already work it tells you before prompting.

```sh
livebox login
```

---

## Read commands

### `ls` — LAN devices

DHCP leases from the router table.

```sh
$ livebox ls
┌─────────────┬──────────────┬───────────────────┐
│Name         │IP Address    │MAC Address        │
├─────────────┼──────────────┼───────────────────┤
│13PARRA13    │192.168.1.87  │A0:51:0B:B3:B4:33  │
│LivingTV     │192.168.1.42  │C8:3C:90:11:22:33  │
└─────────────┴──────────────┴───────────────────┘
```

Source: `cgi_infoLan.js` (falls back to `cgi_clients.js`).

### `wifi` / `wifi status` — Wi-Fi per band

```sh
$ livebox wifi
┌────┬─────────────┬───────┬──────┬────────┬────────────┐
│Band│SSID         │Enabled│Hidden│Security│Key         │
├────┼─────────────┼───────┼──────┼────────┼────────────┤
│24G │Livebox6-729B│yes    │no    │wpa2    │••••••••••••│
│5G  │Livebox6-729B│yes    │no    │wpa2    │••••••••••••│
└────┴─────────────┴───────┴──────┴────────┴────────────┘
```

Source: `cgi_wlan_combine.js`. The primary BSS of each band; guest BSSes
are not listed.

### `dmz get`

```sh
$ livebox dmz get
192.168.1.50
$ livebox dmz get
No DMZ configured
```

Source: `cgi_fw_dmz_osp.js`.

### `port-forward ls`

```sh
$ livebox port-forward ls
┌──┬────┬─────┬───────┐
│ID│from│to IP│to port│
├──┼────┼─────┼───────┤
└──┴────┴─────┴───────┘
```

Columns: rule description (also its ID), external port, internal IP,
internal port. Source: `cgi_nat_osp.js`.

### `static-lease ls`

```sh
$ livebox static-lease ls
┌────┬───────────┬──────────┬──────┐
│Name│MAC address│IP address│Active│
├────┼───────────┼──────────┼──────┤
└────┴───────────┴──────────┴──────┘
```

Source: `cgi_lan_dhcp_static.js`.

### `dns ls`

```sh
$ livebox dns ls
┌────────┬────────────┐
│Hostname│IP address  │
├────────┼────────────┤
│        │192.168.1.87│
└────────┴────────────┘
```

Entries the router creates itself (from leases) can have an empty
hostname. Source: `cgi_dns.js`.

### `pinhole ls` — IPv4 firewall rules

```sh
$ livebox pinhole ls
┌────────┬─────────────────────────┬──────────────────┬─────┬──────┐
│ID      │from                     │to                │proto│action│
├────────┼─────────────────────────┼──────────────────┼─────┼──────┤
│HTTP    │                         │:80               │both │ACCEPT│
│HTTPS   │                         │:443              │both │ACCEPT│
│clitest │192.168.1.0/255.255.255.0│192.168.1.242:8080│tcp  │ACCEPT│
└────────┴─────────────────────────┴──────────────────┴─────┴──────┘
```

The router ships with ~19 default ACCEPT rules — they are listed and can
be removed like any other. Source: `cgi_firewall_customize.js`.

### `fiber` — GPON/ONT diagnostics

```sh
$ livebox fiber        # alias: livebox ont
┌────────┬──────────────┬──────────────┬─────────┬───────────┬─────────┬────────────┐
│PHY link│RX power (dBm)│TX power (dBm)│Temp (°C)│Voltage (V)│Bias (mA)│ONT password│
├────────┼──────────────┼──────────────┼─────────┼───────────┼─────────┼────────────┤
│up      │-22.1         │4.5           │52.6     │3.29       │37.4     │•••••••••   │
└────────┴──────────────┴──────────────┴─────────┴───────────┴─────────┴────────────┘
```

Source: `cgi_infoFtth.js`. The ONT password is what you need to register
third-party SFP ONT gear on the fiber line.

### `speed` — WAN sync rates

```sh
$ livebox speed
↓ 499.7 Mbps
↑ 499.7 Mbps
```

Reads the DSL sync counters (`cgi_infoInternet.js`); on a fiber Livebox
there are no DSL rates, so this errors **by design** — use `fiber`.

### `api <page|/path>` — raw data access

Explore the router's own data without writing code:

```sh
livebox api nat_osp                  # cgi_nat_osp.js (addCfg table)
livebox api wlan_combine             # cgi_wlan_combine.js
livebox api /advanced_network_dmz.htm  # any UI page, verbatim
livebox api /js/global.js            # router JavaScript (protocol source)
```

With a bare name it fetches `GET /cgi/cgi_<name>.js` and prints the raw
JS body; with a leading `/` it fetches that path verbatim.

---

## Write commands

Semantics and captured payloads per command:
[writes.md](writes.md). All writes are **revertible** — every `rm`
restores the slot to empty.

### `static-lease set|rm`

```sh
livebox static-lease set --mac aa:bb:cc:dd:ee:ff --ip 192.168.1.10 --name nas
livebox static-lease rm aa:bb:cc:dd:ee:ff
```

| Flag | Required | Notes |
|---|---|---|
| `--mac` | yes | Normalized + uppercased |
| `--ip` | yes | Reserved address |
| `--name` | no | Device label |

`set` uses the first free slot of the main LAN pool; `rm` matches by MAC.

### `port-forward set|rm`

```sh
livebox port-forward set --description ssh --public-port 22 --ip 192.168.1.10 [--private-port 22] [--protocol tcp|udp]
livebox port-forward rm ssh
```

| Flag | Required | Notes |
|---|---|---|
| `--description` | yes | Doubles as the rule ID for `rm` |
| `--public-port` | yes | External (WAN) port |
| `--ip` | yes | Internal destination |
| `--private-port` | no | Defaults to the public port |
| `--protocol` | no | `tcp` (default) or `udp`; `both` not yet captured |

### `dns set|rm`

```sh
livebox dns set nas 192.168.1.10
livebox dns rm nas
```

Positional args: `<hostname> <ip>` for set, `<hostname>` for rm.

### `dmz set|rm`

```sh
livebox dmz set 192.168.1.50   # expose one host to the whole WAN
livebox dmz rm                 # back to "No DMZ configured"
```

### `wifi enable|disable`

```sh
livebox wifi enable
livebox wifi disable   # both bands
```

⚠️ **Only safe from a wired host.** Disabling the radios drops any Wi-Fi
client — including the machine running the CLI — with no way back until
the radios come up again (power-cycle or wait for a scheduled enable).
The command is implemented and capture-verified but not round-trip-tested
for this reason.

`wifi config` (SSID/security/key changes) is **not implemented**; it
returns a clear placeholder error.

### `pinhole set|rm`

```sh
livebox pinhole set --name web --protocol tcp \
    --source-ip 192.168.1.0 --source-mask 255.255.255.0 \
    --dest-ip 192.168.1.10 --dest-port 8080
livebox pinhole rm web
```

| Flag | Default | Notes |
|---|---|---|
| `--name` | — | Rule ID used by `rm` |
| `--protocol` | `tcp` | `tcp` or `udp` |
| `--source-ip` | empty (any) | `0.0.0.0`/`255.255.255.255` rejected, as the UI does |
| `--source-mask` | empty | `255.255.255.255`/`.255.0`/`.0.0`/`255.0.0.0` |
| `--source-port` | empty | Port or range |
| `--dest-ip` | — | **Required** |
| `--dest-mask` | `255.255.255.255` | |
| `--dest-port` | — | Port or range |
| `--action` | `ACCEPT` | |

`set` writes into the first free rule slot; `rm` clears the slot whose
name matches — including a default rule if you name it.

### `reboot`

```sh
$ livebox reboot
Rebooting the Livebox...
```

Triggers the same `reboot` + `RebootFromGUI` request as the UI's "sí".
Expect ~2–3 minutes of downtime; the CLI exits as soon as the request is
accepted. Implemented and capture-verified, intentionally not exercised
live during the audit.

### `phone` — not implemented

Returns the placeholder error until the VoIP payloads
(`cgi_infoSip.js` is already captured) are wired up.

---

## Exit codes and errors

- `0` on success; `1` on any error, with a one-line `Error: …` message.
- Typical failures: wrong password (*"the Livebox rejected the username or
  password"*), evicted session after someone opens the UI in a browser
  (re-run the command), and missing required flags (with the flag names).
- `--debug` prints each HTTP request/response for protocol triage.
