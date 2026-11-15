// Package api implements a client for the Livebox 6/7 (Arcadyan) web UI:
// login.cgi for authentication and the cgi/*.js files for reading data.
package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// The Livebox 6 and 7 web UI does not accept the JSON login used by the
// Livebox 4 and 5. Instead, login.htm posts two obfuscated fields to
// login.cgi. The AES key and IV are carried by the spacer image of the login
// page, and the fields are built the same way as checkfwVersion() in
// login.htm and do_encode() in global.js.

var spacerRe = regexp.MustCompile(`<img[^>]*src="(data:image/gif;base64,[^"]+)"`)

// spacerSkip is the number of characters the web UI skips in the
// spacer image data URI: the "data:image/gif;base64," prefix and the GIF
// header.
const spacerSkip = 78

// spacerPayload decodes the payload carried by the spacer image of a
// Livebox 6/7 page: bytes 0-31 the encrypted key, bytes 32-47 the IV, and
// bytes 48-end the httoken as ASCII.
func spacerPayload(page string) ([]byte, error) {
	m := spacerRe.FindStringSubmatch(page)
	if m == nil {
		return nil, fmt.Errorf("spacer image not found in the page")
	}
	if len(m[1]) < spacerSkip {
		return nil, fmt.Errorf("spacer image data is too short: %d characters", len(m[1]))
	}
	payload := strings.TrimRight(m[1][spacerSkip:], "=")
	data, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decoding the spacer image: %w", err)
	}
	if len(data) < 48 {
		return nil, fmt.Errorf("spacer payload is too short: %d bytes", len(data))
	}
	return data, nil
}

// loginKeys returns the AES-256 key (bytes 0-31) and CBC IV (bytes 32-47)
// stored in the spacer image of the login page.
func loginKeys(page string) (key, iv []byte, err error) {
	data, err := spacerPayload(page)
	if err != nil {
		return nil, nil, err
	}
	return data[0:32], data[32:48], nil
}

// tokenFromPage decodes ArcBase._t(1) from the spacer image on a logged-in
// page. The payload layout is the same as on the login page: bytes 0-31 the
// encrypted key, bytes 32-47 the IV, and bytes 48-end the httoken as ASCII.
//
// This layout was verified two ways:
//   - Running the router's own ArcBase._t(1) (extracted from global.js) on a
//     captured network_connected.htm returns "57985181", which equals
//     data[48:]; see testdata/livebox6/p_network_connected.htm and the golden
//     test below.
//   - With the correct token, the CLI reads cgi/*.js successfully; with
//     data[0:32] (the encrypted key) the router answers HTTP 404.
func tokenFromPage(page string) (string, error) {
	data, err := spacerPayload(page)
	if err != nil {
		return "", err
	}
	if len(data) <= 48 {
		return "", fmt.Errorf("no token in the spacer payload: %d bytes", len(data))
	}
	return string(data[48:]), nil
}

// encode mirrors do_encode() in global.js: zero-pad the plaintext to a
// multiple of 16 bytes, encrypt with AES-CBC, and write every ciphertext byte
// as %xx.
func encode(plain string, key, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pt := []byte(plain)
	if rem := len(pt) % aes.BlockSize; rem != 0 {
		pt = append(pt, make([]byte, aes.BlockSize-rem)...)
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, pt)

	const hexdigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(ct) * 3)
	for _, c := range ct {
		b.WriteByte('%')
		b.WriteByte(hexdigits[c>>4])
		b.WriteByte(hexdigits[c&0x0f])
	}
	return b.String(), nil
}

// randomPrefix mirrors generatepassword() in login.htm: 32 random
// characters from [0-9a-z].
func randomPrefix() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for range 32 {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// loginField builds one login field the way checkfwVersion() does:
// do_encode(btoa(prefix + " " + md5hex(btoa(value)))).
func loginField(value string, key, iv []byte) (string, error) {
	prefix, err := randomPrefix()
	if err != nil {
		return "", err
	}
	sum := md5.Sum([]byte(base64.StdEncoding.EncodeToString([]byte(value))))
	inner := prefix + " " + hex.EncodeToString(sum[:])
	return encode(base64.StdEncoding.EncodeToString([]byte(inner)), key, iv)
}
