package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// The web UI submits changes with a POST to apply_abstract.cgi. Every value
// is encrypted with the AES key and IV carried by the spacer image of the
// page the form belongs to (do_encode() in js/global.js), and the form
// carries:
//
//	action=<do_encode(action name)>
//	httoken=<plain token of that page, ArcBase._t(1)>
//	submit_button=<page to return to>
//	action_params=<do_encode(param)>            (only when non-empty)
//	805443298771=<do_encode(gui_cehck_token)>   (server-issued anti-replay
//	                                             value injected into js/global.js;
//	                                             the typo is the router's)
//	<cfg ID>=<do_encode(value)>                 (one per changed field; the
//	                                             field name is the numeric ID
//	                                             from the cgi/*.js file; empty
//	                                             fields are posted plain)
//
// All of this was recovered from browser HAR captures and the router's own
// js/global.js.

// nonceField is the form field carrying the encrypted gui_cehck_token.
const nonceField = "805443298771"

// Port-forward protocol numbers used by the router's pcp_rule_protocol field.
const (
	ProtoICMP    = "1"
	ProtoTCP     = "6"
	ProtoUDP     = "17"
	ProtoTCPBoth = "256"
)

var guiCheckTokenRe = regexp.MustCompile(`addCfg\("gui_cehck_token",\s*"[^"]*",\s*"([^"]*)"\)`)

// guiCheckToken extracts the server-issued gui_cehck_token from js/global.js.
// The router injects a fresh value into the file on every load.
func (c *Client) guiCheckToken(ctx context.Context) (string, error) {
	js, err := httpGet(ctx, c.client, c.base+"/js/global.js")
	if err != nil {
		return "", fmt.Errorf("fetching js/global.js: %w", err)
	}
	m := guiCheckTokenRe.FindStringSubmatch(js)
	if m == nil {
		return "", fmt.Errorf("gui_cehck_token not found in js/global.js")
	}
	return m[1], nil
}

// formField is one cfg field of an apply_abstract.cgi form.
type formField struct {
	ID    string // numeric cfg ID (form field name)
	Value string // value to set; empty means "clear this field"
}

// apply builds and submits one apply_abstract.cgi form. The page is fetched
// fresh so its spacer provides the key, IV and httoken, mirroring the browser.
func (c *Client) apply(ctx context.Context, page, action, actionParams string, fields []formField) error {
	body, err := httpGet(ctx, c.client, c.base+"/"+page)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", page, err)
	}
	spacer, err := spacerPayload(body)
	if err != nil {
		return fmt.Errorf("reading the spacer of %s: %w", page, err)
	}
	key, iv := spacer[:32], spacer[32:48]
	if len(spacer) <= 48 {
		return fmt.Errorf("no httoken in the spacer of %s", page)
	}
	token := string(spacer[48:])

	check, err := c.guiCheckToken(ctx)
	if err != nil {
		return err
	}

	form := url.Values{
		"action":        {""},
		"action_params": {""},
		"httoken":       {token},
		"submit_button": {page},
	}
	if action != "" {
		enc, err := encode(action, key, iv)
		if err != nil {
			return err
		}
		form.Set("action", enc)
	}
	if actionParams != "" {
		enc, err := encode(actionParams, key, iv)
		if err != nil {
			return err
		}
		form.Set("action_params", enc)
	}
	checkEnc, err := encode(check, key, iv)
	if err != nil {
		return err
	}
	form.Set(nonceField, checkEnc)

	// Empty fields are posted plain: that is how the web UI clears a slot
	// (seen in the delete captures).
	for _, f := range fields {
		if f.Value == "" {
			form.Set(f.ID, "")
			continue
		}
		enc, err := encode(f.Value, key, iv)
		if err != nil {
			return fmt.Errorf("encoding field %s: %w", f.ID, err)
		}
		form.Set(f.ID, enc)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.base+"/apply_abstract.cgi", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Referer", c.base+"/"+page)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting %s to apply_abstract.cgi: %w", action, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading apply_abstract.cgi response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("apply_abstract.cgi (%s) returned HTTP %d: %s", action, resp.StatusCode, string(respBody))
	}
	return nil
}

// fieldID resolves the addCfg id of one key, erroring when absent.
func fieldID(data Data, key string) (string, error) {
	id := data.ID(key)
	if id == "" {
		return "", fmt.Errorf("no addCfg id for key %q", key)
	}
	return id, nil
}

// StaticLeaseSet creates or updates a static DHCP lease. The lease is placed
// in the first free slot of the main LAN pool (pool 0), matching
// examine_UI_data() in lan_dhcp_static.js: the slot fields plus
// static_enable=1, posted as ui_dhcp_static with action_params "br0".
func (c *Client) StaticLeaseSet(ctx context.Context, mac, ip, name string) error {
	data, err := c.CGI(ctx, "lan_dhcp_static")
	if err != nil {
		return err
	}

	slot := -1
	for i := 0; data.Has(fmt.Sprintf("static_mac_0_%d", i)); i++ {
		if data.Get(fmt.Sprintf("static_mac_0_%d", i)) == "" &&
			data.Get(fmt.Sprintf("static_ip_0_%d", i)) == "" {
			slot = i
			break
		}
	}
	if slot == -1 {
		return fmt.Errorf("no free static lease slot")
	}

	fields, err := staticSlotFields(data, slot, map[string]string{
		"static_active": "1",
		"static_name":   name,
		"static_mac":    strings.ToUpper(mac),
		"static_ip":     ip,
	})
	if err != nil {
		return err
	}
	enableID, err := fieldID(data, "static_enable")
	if err != nil {
		return err
	}
	fields = append(fields, formField{enableID, "1"})

	return c.apply(ctx, "advanced_network_configuration.htm", "ui_dhcp_static", "br0", fields)
}

// StaticLeaseRm removes the static lease with the given MAC address by
// clearing its slot, and disables static DHCP the way the web UI's delete
// does (static_enable=0, seen in the HAR captures).
func (c *Client) StaticLeaseRm(ctx context.Context, mac string) error {
	data, err := c.CGI(ctx, "lan_dhcp_static")
	if err != nil {
		return err
	}

	slot := -1
	for i := 0; data.Has(fmt.Sprintf("static_mac_0_%d", i)); i++ {
		if normalizeMAC(data.Get(fmt.Sprintf("static_mac_0_%d", i))) == normalizeMAC(mac) {
			slot = i
			break
		}
	}
	if slot == -1 {
		return fmt.Errorf("no static lease with MAC %s", mac)
	}

	fields, err := staticSlotFields(data, slot, map[string]string{
		"static_active": "",
		"static_name":   "",
		"static_mac":    "",
		"static_ip":     "",
	})
	if err != nil {
		return err
	}
	enableID, err := fieldID(data, "static_enable")
	if err != nil {
		return err
	}
	fields = append(fields, formField{enableID, "0"})

	return c.apply(ctx, "advanced_network_configuration.htm", "ui_dhcp_static", "br0", fields)
}

// staticSlotFields builds the apply fields of one static lease slot from a
// prefix -> value map.
func staticSlotFields(data Data, slot int, values map[string]string) ([]formField, error) {
	fields := make([]formField, 0, len(values))
	for _, prefix := range []string{"static_active", "static_name", "static_mac", "static_ip"} {
		id, err := fieldID(data, fmt.Sprintf("%s_0_%d", prefix, slot))
		if err != nil {
			return nil, err
		}
		fields = append(fields, formField{id, values[prefix]})
	}
	return fields, nil
}

// natSlotKeys are the per-slot key prefixes posted by the NAT form, in the
// order they appear in the captured web UI request. The form mirrors the rule
// into both the pcp_rule_* and the nat_* tables.
var natSlotKeys = []string{
	"pcp_rule_ext_port",
	"pcp_rule_protocol",
	"pcp_rule_int_ip",
	"pcp_rule_int_port",
	"pcp_rule_port_proposal",
	"pcp_rule_description",
	"nat_group_enable",
	"nat_group_key",
	"nat_enable",
	"nat_description",
	"nat_groups",
	"nat_public_port",
	"nat_protocol",
	"nat_private_ip",
	"nat_private_port",
}

// natSlotValues maps each natSlotKeys prefix to the value for a rule, as
// captured from the web UI. Note that the two tables number the protocol
// differently: pcp_rule_protocol uses the IP protocol number (6/17) while
// nat_protocol uses 0 for TCP and 1 for UDP (only TCP is confirmed by a
// capture; UDP follows the same pattern).
func natSlotValues(description, fromPort, toPort, toIP string, udp bool) map[string]string {
	pcpProto, natProto := ProtoTCP, "0"
	if udp {
		pcpProto, natProto = ProtoUDP, "1"
	}
	return map[string]string{
		"pcp_rule_ext_port":      fromPort,
		"pcp_rule_protocol":      pcpProto,
		"pcp_rule_int_ip":        toIP,
		"pcp_rule_int_port":      toPort,
		"pcp_rule_port_proposal": "1",
		"pcp_rule_description":   description,
		"nat_group_enable":       "1",
		"nat_group_key":          toIP,
		"nat_enable":             "1",
		"nat_description":        description,
		"nat_groups":             "0",
		"nat_public_port":        fromPort,
		"nat_protocol":           natProto,
		"nat_private_ip":         toIP,
		"nat_private_port":       toPort,
	}
}

// SetPortForward adds a NAT port forwarding rule in the first free slot,
// posted as ui_pcp_nat from advanced_network_nat.htm.
func (c *Client) SetPortForward(ctx context.Context, description, fromPort, toPort, toIP string, udp bool) error {
	data, err := c.CGI(ctx, "nat_osp")
	if err != nil {
		return err
	}

	slot := -1
	for i := 0; data.Has(fmt.Sprintf("nat_enable%d", i)); i++ {
		if data.Get(fmt.Sprintf("nat_enable%d", i)) == "" &&
			data.Get(fmt.Sprintf("nat_description%d", i)) == "" {
			slot = i
			break
		}
	}
	if slot == -1 {
		return fmt.Errorf("no free port forwarding slot")
	}

	values := natSlotValues(description, fromPort, toPort, toIP, udp)
	fields := make([]formField, 0, len(natSlotKeys))
	for _, prefix := range natSlotKeys {
		id, err := fieldID(data, fmt.Sprintf("%s%d", prefix, slot))
		if err != nil {
			return err
		}
		fields = append(fields, formField{id, values[prefix]})
	}
	return c.apply(ctx, "advanced_network_nat.htm", "ui_pcp_nat", "", fields)
}

// PortForwardRm removes the NAT rule with the given description by clearing
// all fields of its slot (the way the web UI's delete submits an empty form
// for that slot).
func (c *Client) PortForwardRm(ctx context.Context, description string) error {
	data, err := c.CGI(ctx, "nat_osp")
	if err != nil {
		return err
	}

	slot := -1
	for i := 0; data.Has(fmt.Sprintf("nat_description%d", i)); i++ {
		if data.Get(fmt.Sprintf("nat_description%d", i)) == description {
			slot = i
			break
		}
	}
	if slot == -1 {
		return fmt.Errorf("no port forwarding rule named %q", description)
	}

	fields := make([]formField, 0, len(natSlotKeys))
	for _, prefix := range natSlotKeys {
		id, err := fieldID(data, fmt.Sprintf("%s%d", prefix, slot))
		if err != nil {
			return err
		}
		fields = append(fields, formField{id, ""})
	}
	return c.apply(ctx, "advanced_network_nat.htm", "ui_pcp_nat", "", fields)
}

// DNSSet adds a static DNS entry in the first free slot, posted as ui_dns
// from advanced_network_dns.htm.
func (c *Client) DNSSet(ctx context.Context, hostname, ip string) error {
	data, err := c.CGI(ctx, "dns")
	if err != nil {
		return err
	}

	slot := -1
	for i := 0; data.Has(fmt.Sprintf("dns_hostname%d", i)); i++ {
		if data.Get(fmt.Sprintf("dns_hostname%d", i)) == "" &&
			data.Get(fmt.Sprintf("dns_ip%d", i)) == "" {
			slot = i
			break
		}
	}
	if slot == -1 {
		return fmt.Errorf("no free DNS entry slot")
	}

	hostID, err := fieldID(data, fmt.Sprintf("dns_hostname%d", slot))
	if err != nil {
		return err
	}
	ipID, err := fieldID(data, fmt.Sprintf("dns_ip%d", slot))
	if err != nil {
		return err
	}

	return c.apply(ctx, "advanced_network_dns.htm", "ui_dns", "", []formField{
		{hostID, hostname},
		{ipID, ip},
	})
}

// DNSRm removes the static DNS entry with the given hostname by clearing its
// slot, the way the web UI clears fields (action ui_dns).
func (c *Client) DNSRm(ctx context.Context, hostname string) error {
	data, err := c.CGI(ctx, "dns")
	if err != nil {
		return err
	}

	slot := -1
	for i := 0; data.Has(fmt.Sprintf("dns_hostname%d", i)); i++ {
		if data.Get(fmt.Sprintf("dns_hostname%d", i)) == hostname {
			slot = i
			break
		}
	}
	if slot == -1 {
		return fmt.Errorf("no DNS entry named %q", hostname)
	}

	hostID, err := fieldID(data, fmt.Sprintf("dns_hostname%d", slot))
	if err != nil {
		return err
	}
	ipID, err := fieldID(data, fmt.Sprintf("dns_ip%d", slot))
	if err != nil {
		return err
	}

	return c.apply(ctx, "advanced_network_dns.htm", "ui_dns", "", []formField{
		{hostID, ""},
		{ipID, ""},
	})
}
