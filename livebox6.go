package main

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

var livebox6SpacerRe = regexp.MustCompile(`<img[^>]*src="(data:image/gif;base64,[^"]+)"`)

// livebox6SpacerSkip is the number of characters the web UI skips in the
// spacer image data URI: the "data:image/gif;base64," prefix and the GIF
// header.
const livebox6SpacerSkip = 78

// livebox6SpacerPayload decodes the 48-byte payload carried by the spacer
// image of a Livebox 6/7 page.
func livebox6SpacerPayload(page string) ([]byte, error) {
	m := livebox6SpacerRe.FindStringSubmatch(page)
	if m == nil {
		return nil, fmt.Errorf("spacer image not found in the page")
	}
	if len(m[1]) < livebox6SpacerSkip {
		return nil, fmt.Errorf("spacer image data is too short: %d characters", len(m[1]))
	}
	payload := strings.TrimRight(m[1][livebox6SpacerSkip:], "=")
	data, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decoding the spacer image: %w", err)
	}
	if len(data) < 48 {
		return nil, fmt.Errorf("spacer payload is too short: %d bytes", len(data))
	}
	return data, nil
}

// livebox6Keys returns the AES-256 key (bytes 0-31) and CBC IV (bytes 32-47)
// stored in the spacer image of the login page.
func livebox6Keys(page string) (key, iv []byte, err error) {
	data, err := livebox6SpacerPayload(page)
	if err != nil {
		return nil, nil, err
	}
	return data[0:32], data[32:48], nil
}

// livebox6Encode mirrors do_encode() in global.js: zero-pad the plaintext to a
// multiple of 16 bytes, encrypt with AES-CBC, and write every ciphertext byte
// as %xx.
func livebox6Encode(plain string, key, iv []byte) (string, error) {
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

// livebox6RandomPrefix mirrors generatepassword() in login.htm: 32 random
// characters from [0-9a-z].
func livebox6RandomPrefix() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(livebox6Alphabet)))
	for range 32 {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(livebox6Alphabet[n.Int64()])
	}
	return b.String(), nil
}

const livebox6Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// livebox6Field builds one login field the way checkfwVersion() does:
// do_encode(btoa(prefix + " " + md5hex(btoa(value)))).
func livebox6Field(value string, key, iv []byte) (string, error) {
	prefix, err := livebox6RandomPrefix()
	if err != nil {
		return "", err
	}
	sum := md5.Sum([]byte(base64.StdEncoding.EncodeToString([]byte(value))))
	inner := prefix + " " + hex.EncodeToString(sum[:])
	return livebox6Encode(base64.StdEncoding.EncodeToString([]byte(inner)), key, iv)
}
