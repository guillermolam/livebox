# Write support (apply_abstract.cgi)

How each write command is built, and the evidence it was derived from.
Protocol fundamentals are in [protocol.md](protocol.md).

## Action table

All actions were confirmed from the router's `js/subformvar.js` and from
dry-run captures of the UI's own submits. The CLI currently implements the
bold ones.

| Action | Form page (`submit_button`) | `action_params` | Purpose |
|---|---|---|---|
| **`reboot`** | `index.htm` | `RebootFromGUI` | Restart the router |
| **`ui_wireless`** | `advanced_wifi.htm` | — | Wi-Fi bands/config |
| `ui_wireless_guest` | `wifi_guest.htm` | — | Guest Wi-Fi |
| `ui_wireless_single` | per-band page | — | Single-band change |
| `ui_wps` | WPS page | — | WPS |
| **`ui_firewall`** | `advanced_network_dmz.htm` | — | Firewall level, **DMZ**, MAC filter |
| **`ui_firewall_all`** | `advanced_firewall_customize.htm` | — | IPv4 pinhole rules |
| `ui_firewall6` | `advanced_firewall_customizev6.htm` | — | IPv6 firewall |
| `FW_FILTER_DEL` | firewall page | — | Delete pinhole (legacy) |
| **`ui_pcp_nat`** | `advanced_network_nat.htm` | — | Port forwarding |
| **`ui_dhcp_static`** | `advanced_network_configuration.htm` | `br0` | Static DHCP leases |
| **`ui_dns`** | `advanced_network_dns.htm` | — | Static DNS entries |
| `ui_upnp` | `advanced_network_upnp.htm` | — | UPnP toggle |
| `ui_lan` | LAN page | — | LAN config |
| `ui_ntp` | NTP page | — | NTP |
| `ui_routing` / `ui_del_route` | routes page | — | Static routes |
| `ui_management` | remote access page | — | Remote mgmt |
| `ui_tr69` | TR-069 page | — | TR-069 |
| `ui_qos` | QoS page | — | QoS |
| `wan_start` / `wan_stop` | WAN page | — | WAN connect/disconnect |
| `ui_factory_defaults` | factory page | — | Factory reset (not implemented here) |
| `ui_scheduler` | `support_restart.htm` | — | Auto-reboot schedule |
| `ui_add_pclist` | devices page | `"<mac>,<name>"` | Rename device |
| `ui_call_log_del_all`, `ui_voip_*` | phone pages | — | Telephony |
| `ui_clear_log`, `ui_site_survey_all`, `ui_system_p`, `ui_usb_*` | support pages | — | Misc |

## Field IDs

cfg IDs are **firmware-version specific** — the CLI never hard-codes them;
it reads them at write time from the `addCfg("name","id","value")` calls of
the matching `cgi_<page>.js`. Known values on the audited firmware:

| cfg key | addCfg ID | cgi source | Example value |
|---|---|---|---|
| `wl_enable24G` | `196637000000` | `cgi_wlan_combine.js` | `1` |
| `wl_enable5G` | `196701000000` | `cgi_wlan_combine.js` | `1` |
| `wl_enable_change` | `983267000000` | `cgi_wlan_combine.js` | `1` (forces radio restart) |
| `dmz_enable` | `655398000000` | `cgi_fw_dmz_osp.js` | `0` / `1` |
| `host_ip` | `655402001000` | `cgi_fw_dmz_osp.js` | `192.168.1.50` |
| `upnp_enable` | `917504000000` | `cgi_upnp_osp.js` | `1` |
| `firewall_rules_app0` | `983149001000` | `cgi_firewall_customize.js` | `HTTP` |
| `firewall_rules_action0` | `983157001000` | `cgi_firewall_customize.js` | `ACCEPT` |
| `gui_cehck_token` | (nonce field `805443298771`) | `/js/global.js` | server-issued |

ID pattern: `<major><slot><minor>` — e.g. `983149_00_1000` is rule field
`app`, slot `00`. Slot N shifts the middle digits.

## Per-command write semantics

### static-lease set / rm (`ui_dhcp_static`, params `br0`)

- Picks the first slot with empty `static_mac_0_<i>` and `static_ip_0_<i>`.
- Writes `static_active`, `static_name`, `static_mac` (uppercased),
  `static_ip` of that slot plus `static_enable=1`.
- `rm` clears the four slot fields and sets `static_enable=0` (as captured
  from the UI's delete).

### port-forward set / rm (`ui_pcp_nat`)

- Picks the first slot with empty `nat_enable<i>` and `nat_description<i>`.
- The rule is mirrored into **two tables**: `pcp_rule_*<slot>` (PCP/NAT
  semantics) and `nat_*<slot>` — 15 fields total, including
  `pcp_rule_port_proposal=1`, `nat_group_key=<ip>`, `nat_groups=0`.
- Protocol numbering differs per table: `pcp_rule_protocol` uses IP numbers
  (6/17), `nat_protocol` uses 0=TCP, 1=UDP.
- `rm` clears all 15 fields of the slot.

### dns set / rm (`ui_dns`)

- First slot with both `dns_hostname<i>` and `dns_ip<i>` empty; `rm`
  clears the pair.

### dmz set / rm (`ui_firewall`)

- `set`: `dmz_enable=1` + `host_ip=<ip>`.
- `rm`: **only** `host_ip=""` (captured from the UI's `noDMZ` flow —
  `dmz_enable` is left out; the cleared IP implies disabled).

### wifi enable / disable (`ui_wireless`)

- Writes `wl_enable24G` and `wl_enable5G` to `1`/`0` together, plus
  `wl_enable_change=1` so the router restarts the radios.
- ⚠️ Disabling drops the Wi-Fi the machine may be connected through — the
  CLI does the equivalent of the UI's warning modal: none. Use from a wired
  host.

### pinhole set / rm (`ui_firewall_all`)

- `set` fills the first slot whose `firewall_rules_enable<i>` is empty with
  ten fields: `app` (name), `proto`, `startip`, `startmask`, `srcport`,
  `endip`, `endmask`, `desport`, `action`, `enable=1`.
- `rm` (mirroring the UI's `DelRule`) clears all ten fields of the rule's
  slot.
- The UI's own validation (captured client-side, replicated in the CLI
  flags): source IP may not be `0.0.0.0`/`255.255.255.255`; masks limited
  to `/32 /24 /16 /8`; ports `1–65535` or ranges.

### reboot

- `action=reboot`, `action_params=RebootFromGUI`, no cfg fields,
  `submit_button=index.htm`. The UI checks `cgi_have_phone_call.js` first;
  the CLI does not.

## Captured payloads (audit evidence)

From the dry-run browser audit (`chrome-devtools` interception of
`HTMLFormElement.submit`, submit events, XHR POSTs and `subForm()` —
nothing sent; full captures in the audit output `network-traffic.json`):

| Trigger | Decrypted form |
|---|---|
| Wi-Fi switch off → save | `action=ui_wireless`, `wl_enable24G=0`, `wl_enable5G=0`, `wl_enable_change=1` |
| DMZ "nuevo" + IP → save | `action=ui_firewall`, `dmz_enable=1`, `host_ip=192.168.1.242` |
| DMZ "noDMZ" → save | `action=ui_firewall`, `host_ip=""` |
| Reboot "sí" | `action=reboot`, `action_params=RebootFromGUI`, `next=index.htm` |
| Pinhole add | `action=ui_firewall_all`, ten `firewall_rules_*<slot>` fields |
| Pinhole delete | same action, same ten fields cleared |

Every implemented command was additionally **live-verified against the
router** (dummy values written, then restored to a pre-captured baseline),
except `wifi enable/disable` (needs a wired host) and `reboot` (intentionally
not exercised).
