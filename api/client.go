package api

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

// Client talks to a Livebox 6/7 (Arcadyan) router using the web-UI endpoints:
// login.cgi for authentication and cgi/*.js for data.
type Client struct {
	base   string
	client *http.Client
	token  string
}

var addCfgRe = regexp.MustCompile(`addCfg\("([^"]+)",\s*"[^"]*",\s*"([^"]*)"\)`)

// NewClient logs in and extracts the httoken needed for subsequent cgi/*.js
// requests.
func NewClient(ctx context.Context, address, username, password string) (*Client, error) {
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
	page, err := httpGet(ctx, client, base+"/login.htm")
	if err != nil {
		return nil, fmt.Errorf("fetching the login page: %w", err)
	}
	key, iv, err := loginKeys(page)
	if err != nil {
		return nil, err
	}

	userField, err := loginField(username, key, iv)
	if err != nil {
		return nil, err
	}
	passField, err := loginField(password, key, iv)
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
	page, err = httpGet(ctx, client, base+"/network_connected.htm")
	if err != nil {
		return nil, fmt.Errorf("fetching the network page: %w", err)
	}
	token, err := tokenFromPage(page)
	if err != nil {
		return nil, fmt.Errorf("extracting httoken: %w", err)
	}

	return &Client{
		base:   base,
		client: client,
		token:  token,
	}, nil
}

// httpGet fetches a page and returns its body.
func httpGet(ctx context.Context, client *http.Client, url string) (string, error) {
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

// Data holds the key/value pairs parsed from a cgi/*.js response, plus the
// raw body for files that embed data outside addCfg calls.
type Data struct {
	entries map[string]string
	Raw     string
}

// Get returns the value for a key, or the empty string if absent.
func (d Data) Get(key string) string {
	return d.entries[key]
}

// Has reports whether a key is present, even if its value is empty.
func (d Data) Has(key string) bool {
	_, ok := d.entries[key]
	return ok
}

// parseCGIBody parses the addCfg("name", "id", "value") calls of a cgi/*.js
// response body.
func parseCGIBody(body string) Data {
	data := Data{entries: make(map[string]string), Raw: body}
	for _, m := range addCfgRe.FindAllStringSubmatch(body, -1) {
		data.entries[m[1]] = m[2]
	}
	return data
}

// CGI fetches a cgi/*.js data file and parses its addCfg calls.
func (c *Client) CGI(ctx context.Context, page string) (Data, error) {
	now := time.Now().UnixMilli()
	u := fmt.Sprintf("%s/cgi/cgi_%s.js?_tn=%s&_t=%d&_=%d", c.base, page, c.token, now, now)

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return Data{}, err
	}
	req.Header.Set("Accept", "text/javascript, application/javascript, */*; q=0.01")
	req.Header.Set("Referer", c.base+"/network_connected.htm")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.client.Do(req)
	if err != nil {
		return Data{}, fmt.Errorf("fetching cgi_%s.js: %w", page, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Data{}, fmt.Errorf("reading cgi_%s.js: %w", page, err)
	}
	if resp.StatusCode != http.StatusOK {
		return Data{}, fmt.Errorf("cgi_%s.js returned HTTP %d: %s", page, resp.StatusCode, string(body))
	}

	return parseCGIBody(string(body)), nil
}

// Devices returns the DHCP leases. The leases live in infoLan.js as
// var dhcp_leaseTime=[...]; on some firmware the same 5-tuples are exposed in
// clients.js as var dhcp_client=[...].
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var errs []error
	for _, page := range []string{"infoLan", "clients"} {
		data, err := c.CGI(ctx, page)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		devices, err := parseDevices(data.Raw)
		if err == nil {
			return devices, nil
		}
		errs = append(errs, fmt.Errorf("cgi_%s.js: %w", page, err))
	}
	return nil, errors.Join(errs...)
}

// PortForwards returns the NAT port forwarding rules from nat_osp.js.
func (c *Client) PortForwards(ctx context.Context) ([]PortForward, error) {
	data, err := c.CGI(ctx, "nat_osp")
	if err != nil {
		return nil, err
	}
	return parsePortForwards(data), nil
}

// DMZ returns the DMZ configuration from fw_dmz_osp.js.
func (c *Client) DMZ(ctx context.Context) (DMZ, error) {
	data, err := c.CGI(ctx, "fw_dmz_osp")
	if err != nil {
		return DMZ{}, err
	}
	return parseDMZ(data), nil
}

// DNSRecords returns the static DNS entries from dns.js.
func (c *Client) DNSRecords(ctx context.Context) ([]DNSRecord, error) {
	data, err := c.CGI(ctx, "dns")
	if err != nil {
		return nil, err
	}
	return parseDNS(data), nil
}

// StaticLeases returns the static DHCP leases from lan_dhcp_static.js.
func (c *Client) StaticLeases(ctx context.Context) ([]StaticLease, error) {
	data, err := c.CGI(ctx, "lan_dhcp_static")
	if err != nil {
		return nil, err
	}
	return parseStaticLeases(data), nil
}

// WLAN returns the Wi-Fi configuration from wlan_combine.js.
func (c *Client) WLAN(ctx context.Context) (WLAN, error) {
	data, err := c.CGI(ctx, "wlan_combine")
	if err != nil {
		return WLAN{}, err
	}
	return parseWLAN(data), nil
}

// Speed returns the WAN sync rates from infoInternet.js.
func (c *Client) Speed(ctx context.Context) (Speed, error) {
	data, err := c.CGI(ctx, "infoInternet")
	if err != nil {
		return Speed{}, err
	}
	return parseSpeed(data)
}
