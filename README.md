# livebox-cli — a CLI for the Livebox 6 (Orange)

A command-line tool to manage a Livebox 6 router. Forked from
[maelvls/livebox](https://github.com/maelvls/livebox) (which targets the
Livebox 4 and 5 through their `/ws` JSON API) and ported to the Livebox 6
(Arcadyan) web-UI flow: login via `POST /login.cgi` with AES-obfuscated
fields, reads via `GET /cgi/cgi_<page>.js`, and (eventually) writes via
`POST /apply_abstract.cgi`.

Livebox 4 and 5 are **not** supported by this fork; use
[maelvls/livebox](https://github.com/maelvls/livebox) for those.

## Getting started

You will need Go 1.27 or later to build the CLI:

```sh
go install github.com/guillermolam/livebox@latest
```

or build from source:

```sh
git clone https://github.com/guillermolam/livebox.git
cd livebox
go build .
```

To get started:

```sh
livebox login
```

## What works (read-only)

```sh
livebox ls                 # Devices and their IP/MAC addresses
livebox port-forward ls    # Port forwarding rules
livebox dmz get            # Current DMZ host
livebox dns ls             # Static DNS entries
livebox static-lease ls    # Static DHCP leases
livebox wifi               # Wi-Fi status per band (alias: wifi status)
livebox speed              # WAN sync rates (DSL only; not available on fiber)
livebox api <cgi-page>     # Raw cgi data file, e.g. livebox api nat_osp
```

## Not yet implemented (write)

The following commands return a clear error until the corresponding
`apply_abstract.cgi` payloads have been captured from the web UI:

```sh
livebox reboot
livebox wifi enable|disable|config
livebox port-forward set|rm
livebox dmz set|rm
livebox static-lease set|rm
livebox dns set
livebox pinhole ls|set|rm
livebox phone
```

To help add support: capture the browser action in the Livebox web UI (HAR
export from the developer tools) and open an issue with the payload.

## Configuration

`livebox login` stores the address, username and password in
`~/.config/livebox.yml` (mode `0600`). You can override them per invocation
with `--address`, `--username` and `--password`.

## Container image

A Containerfile is available at `~/livebox-podman/Containerfile`; build it
with the repository root as the context:

```sh
podman build -f ~/livebox-podman/Containerfile -t livebox-cli .
```
