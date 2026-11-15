package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// FTTH holds the GPON/ONT diagnostics from infoFtth.js: the SFP transceiver
// optics and the ONT password (SLID), which is needed when replacing the
// Livebox with a third-party ONT/router.
type FTTH struct {
	PhyLink int    `json:"phy_link"`
	Temp    string `json:"temp"`
	Volt    string `json:"volt"`
	Bias    string `json:"bias"`
	TxPower string `json:"tx_power"`
	RxPower string `json:"rx_power"`

	ONTPassword string // decoded from the hex ont_pwd variable
}

var ontpwdRe = regexp.MustCompile(`var ont_pwd='([0-9a-fA-F]+)'`)

// FTTH returns the fiber/ONT diagnostics from infoFtth.js.
func (c *Client) FTTH(ctx context.Context) (FTTH, error) {
	data, err := c.CGI(ctx, "infoFtth")
	if err != nil {
		return FTTH{}, err
	}
	return parseFTTH(data.Raw)
}

// parseFTTH parses the traciver_status object and the ont_pwd variable of an
// infoFtth.js response. The file first declares an empty object
// (var traciver_status={};) and then assigns the real one, so the last
// assignment wins.
func parseFTTH(raw string) (FTTH, error) {
	obj, err := lastAssignedJSONObject(raw, "traciver_status")
	if err != nil {
		return FTTH{}, err
	}
	var ftth FTTH
	if err := json.Unmarshal([]byte(obj), &ftth); err != nil {
		return FTTH{}, fmt.Errorf("parsing traciver_status: %w", err)
	}

	if m := ontpwdRe.FindStringSubmatch(raw); m != nil {
		decoded, err := hex.DecodeString(m[1])
		if err == nil {
			ftth.ONTPassword = string(decoded)
		}
	}
	return ftth, nil
}

// lastAssignedJSONObject extracts the JSON object of the last assignment to
// the given JavaScript variable.
func lastAssignedJSONObject(raw, varName string) (string, error) {
	idx := strings.LastIndex(raw, varName+"=")
	if idx == -1 {
		return "", fmt.Errorf("%s not found", varName)
	}
	rest := strings.TrimLeft(raw[idx+len(varName)+1:], " \t")
	if rest == "" || rest[0] != '{' {
		return "", fmt.Errorf("%s is not assigned an object", varName)
	}

	depth := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:i+1], nil
			}
		}
	}
	return "", fmt.Errorf("%s object not terminated", varName)
}
