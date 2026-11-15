package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// livebox6Client talks to a Livebox 6/7 (Arcadyan) router using the web-UI
// endpoints: login.cgi for authentication and cgi/*.js for data.
type livebox6Client struct {
	base   string
	client *http.Client
	token  string
}

var livebox6AddCfgRe = regexp.MustCompile(`addCfg\("([^"]+)",\s*"[^"]*",\s*"([^"]*)"\)`)

// newLivebox6Client logs in and extracts the httoken needed for subsequent
// cgi/*.js requests.
func newLivebox6Client(ctx context.Context, address, username, password string) (*livebox6Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	base := fmt.Sprintf("http://%s", address)

	// 1. Fetch the login page and extract the AES key and IV from its spacer
	// image.
	page, err := livebox6Get(ctx, client, base+"/login.htm")
	if err != nil {
		return nil, fmt.Errorf("fetching the login page: %w", err)
	}
	key, iv, err := livebox6Keys(page)
	if err != nil {
		return nil, err
	}

	userField, err := livebox6Field(username, key, iv)
	if err != nil {
		return nil, err
	}
	passField, err := livebox6Field(password, key, iv)
	if err != nil {
		return nil, err
	}

	// 2. Post the login form.
	form := url.Values{
		"dfr597hf": {userField},
		"cnlvd2xh": {passField},
		"login":    {"Login"},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/login.cgi", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", base+"/login.htm")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting the login form: %w", err)
	}
	resp.Body.Close()

	if loc := resp.Header.Get("Location"); strings.Contains(loc, "login.htm") {
		return nil, fmt.Errorf("the Livebox rejected the username or password")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("login failed with HTTP status %s", resp.Status)
	}

	// 3. Fetch a logged-in page to extract the httoken from its spacer image.
	page, err = livebox6Get(ctx, client, base+"/network_connected.htm")
	if err != nil {
		return nil, fmt.Errorf("fetching the network page: %w", err)
	}
	token, err := livebox6TokenFromPage(page)
	if err != nil {
		return nil, fmt.Errorf("extracting httoken: %w", err)
	}

	return &livebox6Client{
		base:   base,
		client: client,
		token:  token,
	}, nil
}

// livebox6Get fetches a page and returns its body.
func livebox6Get(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// livebox6TokenFromPage decodes ArcBase._t(1) from the spacer image on a
// logged-in page. The spacer payload layout is: bytes 0-31 the encrypted key,
// bytes 32-47 the IV, and bytes 48-end the httoken as ASCII.
func livebox6TokenFromPage(page string) (string, error) {
	data, err := livebox6SpacerPayload(page)
	if err != nil {
		return "", err
	}
	return string(data[48:]), nil
}

// cgiData holds the key/value pairs parsed from a cgi/*.js response, plus the
// raw body for files that embed data outside addCfg calls.
type cgiData struct {
	entries map[string]string
	raw     string
}

// get returns the value for a key, or the empty string if absent.
func (d cgiData) get(key string) string {
	return d.entries[key]
}

// has reports whether a key is present, even if its value is empty.
func (d cgiData) has(key string) bool {
	_, ok := d.entries[key]
	return ok
}

// parseCGIBody parses the addCfg("name", "id", "value") calls of a cgi/*.js
// response body.
func parseCGIBody(body string) cgiData {
	data := cgiData{entries: make(map[string]string), raw: body}
	for _, m := range livebox6AddCfgRe.FindAllStringSubmatch(body, -1) {
		data.entries[m[1]] = m[2]
	}
	return data
}

// getCGI fetches a cgi/*.js data file and parses its addCfg calls.
func (c *livebox6Client) getCGI(ctx context.Context, page string) (cgiData, error) {
	now := time.Now().UnixMilli()
	u := fmt.Sprintf("%s/cgi/cgi_%s.js?_tn=%s&_t=%d&_=%d", c.base, page, c.token, now, now)

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return cgiData{}, err
	}
	req.Header.Set("Accept", "text/javascript, application/javascript, */*; q=0.01")
	req.Header.Set("Referer", c.base+"/network_connected.htm")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.client.Do(req)
	if err != nil {
		return cgiData{}, fmt.Errorf("fetching cgi_%s.js: %w", page, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return cgiData{}, fmt.Errorf("reading cgi_%s.js: %w", page, err)
	}
	if resp.StatusCode != http.StatusOK {
		return cgiData{}, fmt.Errorf("cgi_%s.js returned HTTP %d: %s", page, resp.StatusCode, string(body))
	}

	return parseCGIBody(string(body)), nil
}

// Devices returns the DHCP leases. The leases live in infoLan.js as
// var dhcp_leaseTime=[...]; on some firmware the same 5-tuples are exposed in
// clients.js as var dhcp_client=[...].
func (c *livebox6Client) Devices(ctx context.Context) ([]livebox6Device, error) {
	var errs []error
	for _, page := range []string{"infoLan", "clients"} {
		data, err := c.getCGI(ctx, page)
		if err != nil {
			return nil, err
		}
		devices, err := livebox6ParseDevices(data.raw)
		if err == nil {
			return devices, nil
		}
		errs = append(errs, fmt.Errorf("cgi_%s.js: %w", page, err))
	}
	return nil, errors.Join(errs...)
}

// PortForwards returns the NAT port forwarding rules from nat_osp.js.
func (c *livebox6Client) PortForwards(ctx context.Context) ([]livebox6PortForward, error) {
	data, err := c.getCGI(ctx, "nat_osp")
	if err != nil {
		return nil, err
	}
	return livebox6ParsePortForwards(data), nil
}

// DMZ returns the DMZ configuration from fw_dmz_osp.js.
func (c *livebox6Client) DMZ(ctx context.Context) (livebox6DMZ, error) {
	data, err := c.getCGI(ctx, "fw_dmz_osp")
	if err != nil {
		return livebox6DMZ{}, err
	}
	return livebox6ParseDMZ(data), nil
}

// DNSRecords returns the static DNS entries from dns.js.
func (c *livebox6Client) DNSRecords(ctx context.Context) ([]livebox6DNSRecord, error) {
	data, err := c.getCGI(ctx, "dns")
	if err != nil {
		return nil, err
	}
	return livebox6ParseDNS(data), nil
}

// StaticLeases returns the static DHCP leases from lan_dhcp_static.js.
func (c *livebox6Client) StaticLeases(ctx context.Context) ([]livebox6StaticLease, error) {
	data, err := c.getCGI(ctx, "lan_dhcp_static")
	if err != nil {
		return nil, err
	}
	return livebox6ParseStaticLeases(data), nil
}

// WLAN returns the Wi-Fi configuration from wlan_combine.js.
func (c *livebox6Client) WLAN(ctx context.Context) (livebox6WLAN, error) {
	data, err := c.getCGI(ctx, "wlan_combine")
	if err != nil {
		return livebox6WLAN{}, err
	}
	return livebox6ParseWLAN(data), nil
}

// Speed returns the WAN sync rates from infoInternet.js.
func (c *livebox6Client) Speed(ctx context.Context) (livebox6Speed, error) {
	data, err := c.getCGI(ctx, "infoInternet")
	if err != nil {
		return livebox6Speed{}, err
	}
	return livebox6ParseSpeed(data)
}
