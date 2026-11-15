package api

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The spacer data URI starts with the "data:image/gif;base64," prefix and a
// 56-character GIF header (78 characters in total); the base64 payload after
// that decodes to key(32) + IV(16) + httoken(ASCII).
const testSpacerPrefix = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
const testKey = "J7mz1T8JVsk31jj8nhwvaUM71uX4dbZD"
const testIV = "DWnBv4OFkvqfL+4Z"
const testToken = "1234567890"

// Reference values produced by the router's own global.js (do_encode and
// ArcBase._t) for this spacer image.
const livebox6TestPage = `<img title=spacer src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7SjdtejFUOEpWc2szMWpqOG5od3ZhVU03MXVYNGRiWkREV25CdjRPRmt2cWZMKzRaMTU2Nzg0MTUx" border=0>`

// spacerPage builds a page whose spacer image carries the given payload
// (raw bytes after the 78-character prefix).
func spacerPage(payload []byte) string {
	enc := base64.StdEncoding.EncodeToString(payload)
	return fmt.Sprintf(`<html><img title=spacer src="%s%s" border=0></html>`, testSpacerPrefix, enc)
}

// keyIV returns the 48-byte key+IV blob the login page carries.
func keyIV() []byte {
	return append([]byte(testKey), testIV...)
}

// loadTestData reads a captured router response from the repo's testdata
// directory.
func loadTestData(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "livebox6", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

func TestLoginKeys(t *testing.T) {
	key, iv, err := loginKeys(livebox6TestPage)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(key), testKey; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
	if got, want := string(iv), testIV; got != want {
		t.Errorf("iv = %q, want %q", got, want)
	}
}

func TestTokenFromPage(t *testing.T) {
	// The logged-in page carries key+IV+token; the token sits at bytes 48+.
	tok, err := tokenFromPage(spacerPage(append(keyIV(), testToken...)))
	if err != nil {
		t.Fatal(err)
	}
	if tok != testToken {
		t.Errorf("token = %q, want %q", tok, testToken)
	}
}

func TestTokenFromCapturedPage(t *testing.T) {
	// Golden test against a real page captured from the router: the spacer
	// image of network_connected.htm carries the httoken.
	page := loadTestData(t, "p_network_connected.htm")
	tok, err := tokenFromPage(page)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "57985181" {
		t.Errorf("token = %q, want %q", tok, "57985181")
	}
}

func TestEncode(t *testing.T) {
	key, iv, err := loginKeys(livebox6TestPage)
	if err != nil {
		t.Fatal(err)
	}
	got, err := encode("abcdefghijklmnopqrstuvwxyz0123456789", key, iv)
	if err != nil {
		t.Fatal(err)
	}
	want := "%c8%ea%16%e0%e3%c7%c9%c6%57%e4%23%91%a4%1a%7c%9c%8d%38%bf%2e%62%25%54%7f%a9%67%d9%2b%dc%ae%7a%27%09%11%84%1a%43%fa%a0%e6%96%57%de%0b%bb%e5%70%70"
	if got != want {
		t.Errorf("encode mismatch\n got: %s\nwant: %s", got, want)
	}
}
