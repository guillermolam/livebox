// Command hardecode decrypts the apply_abstract.cgi payloads of a HAR
// capture. Each page of the router web UI carries a spacer image with the
// session AES key (bytes 0-31), IV (32-47) and httoken (48+); the write
// fields posted to apply_abstract.cgi are do_encode()d with that key/IV, so
// correlating every POST with the spacer of its submit_button page recovers
// the plaintext action, action_params and field values.
//
// Usage: go run ./tools/hardecode <file.har>
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type har struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method   string `json:"method"`
				URL      string `json:"url"`
				PostData struct {
					Params []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"params"`
				} `json:"postData"`
			} `json:"request"`
			Response struct {
				Content struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

var spacerRe = regexp.MustCompile(`data:image/gif;base64,([A-Za-z0-9+/=]+)`)

// spacer decodes a page spacer payload: key (0-31), IV (32-47), token (48+).
// The capture group starts after "data:image/gif;base64,", so only the
// 56-character GIF header is skipped.
func spacer(page string) (key, iv []byte, ok bool) {
	m := spacerRe.FindStringSubmatch(page)
	if m == nil || len(m[1]) < 56 {
		return nil, nil, false
	}
	data, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(m[1][56:], "="))
	if err != nil || len(data) < 48 {
		return nil, nil, false
	}
	return data[:32], data[32:48], true
}

// decode reverses do_encode(): strip the outer form encoding, turn every %xx
// into a byte, and AES-CBC decrypt, trimming trailing zero padding.
func decode(value string, key, iv []byte) (string, error) {
	unescaped, err := url.QueryUnescape(value)
	if err != nil {
		return "", err
	}
	var ct []byte
	for i := 0; i+3 <= len(unescaped); i += 3 {
		if unescaped[i] != '%' {
			return "", fmt.Errorf("not a %%xx string at %d: %q", i, unescaped[i:])
		}
		var b int
		if _, err := fmt.Sscanf(unescaped[i+1:i+3], "%02x", &b); err != nil {
			return "", err
		}
		ct = append(ct, byte(b))
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length %d is not a multiple of 16", len(ct))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return strings.TrimRight(string(pt), "\x00"), nil
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var h har
	if err := json.Unmarshal(raw, &h); err != nil {
		panic(err)
	}

	// Track the most recent spacer seen per page path.
	spacers := map[string][2][]byte{}
	for i, e := range h.Log.Entries {
		u, _ := url.Parse(e.Request.URL)
		if key, iv, ok := spacer(e.Response.Content.Text); ok {
			spacers[u.Path] = [2][]byte{key, iv}
		}

		if e.Request.Method != "POST" || u.Path != "/apply_abstract.cgi" {
			continue
		}

		params := map[string]string{}
		for _, p := range e.Request.PostData.Params {
			params[p.Name] = p.Value
		}
		page := "/" + params["submit_button"]

		fmt.Printf("\n=== entry %d: POST %s (page %s, httoken %s)\n", i, u.Path, page, params["httoken"])

		kv, ok := spacers[page]
		if !ok {
			// Fall back to any spacer seen so far.
			for _, s := range spacers {
				kv, ok = s, true
				break
			}
		}
		if !ok {
			fmt.Println("  no spacer captured yet, cannot decrypt")
			continue
		}
		key, iv := kv[0], kv[1]

		for _, p := range e.Request.PostData.Params {
			switch p.Name {
			case "httoken", "submit_button":
				continue
			}
			if p.Value == "" {
				fmt.Printf("  %-16s = <empty>\n", p.Name)
				continue
			}
			plain, err := decode(p.Value, key, iv)
			if err != nil {
				fmt.Printf("  %-16s = <decrypt failed: %v>\n", p.Name, err)
				continue
			}
			fmt.Printf("  %-16s = %q\n", p.Name, plain)
		}
	}
}
