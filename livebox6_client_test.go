package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The spacer data URI starts with the "data:image/gif;base64," prefix and a
// 56-character GIF header (78 characters in total); the base64 payload after
// that decodes to key(32) + IV(16) + httoken(ASCII).
const testSpacerPrefix = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
const testKey = "J7mz1T8JVsk31jj8nhwvaUM71uX4dbZD"
const testIV = "DWnBv4OFkvqfL+4Z"
const testToken = "1234567890"

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

func TestClientSpacerPages(t *testing.T) {
	// Sanity-check the test fixtures against the real parsers before using
	// them in the HTTP tests.
	if _, _, err := livebox6Keys(spacerPage(keyIV())); err != nil {
		t.Fatalf("login fixture invalid: %v", err)
	}
	// The logged-in page carries key+IV+token; the token sits at bytes 48+.
	tok, err := livebox6TokenFromPage(spacerPage(append(keyIV(), testToken...)))
	if err != nil {
		t.Fatalf("network fixture invalid: %v", err)
	}
	if tok != testToken {
		t.Errorf("token = %q, want %q", tok, testToken)
	}
}

func TestLivebox6ClientGetCGI(t *testing.T) {
	var requestURL string
	var requestHeaders http.Header
	var loggedIn bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.htm":
			io.WriteString(w, spacerPage(keyIV()))
		case "/login.cgi":
			loggedIn = true
			http.Redirect(w, r, "/network_connected.htm", http.StatusFound)
		case "/network_connected.htm":
			if !loggedIn {
				http.Redirect(w, r, "/login.htm", http.StatusFound)
				return
			}
			io.WriteString(w, spacerPage(append(keyIV(), testToken...)))
		case "/cgi/cgi_test.js":
			requestURL = r.URL.String()
			requestHeaders = r.Header.Clone()
			io.WriteString(w, `addCfg("foo", "123", "bar");`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client, err := newLivebox6Client(context.Background(), strings.TrimPrefix(ts.URL, "http://"), "admin", "password")
	if err != nil {
		t.Fatalf("newLivebox6Client: %v", err)
	}

	data, err := client.getCGI(context.Background(), "test")
	if err != nil {
		t.Fatalf("getCGI: %v", err)
	}
	if got, want := data.get("foo"), "bar"; got != want {
		t.Errorf("foo = %q, want %q", got, want)
	}

	if requestURL == "" {
		t.Fatal("cgi endpoint was not called")
	}
	if !strings.Contains(requestURL, "_tn="+testToken) {
		t.Errorf("request URL missing token: %s", requestURL)
	}
	if !strings.Contains(requestURL, "_t=") || !strings.Contains(requestURL, "_=") {
		t.Errorf("request URL missing cache busters: %s", requestURL)
	}
	if requestHeaders.Get("X-Requested-With") != "XMLHttpRequest" {
		t.Errorf("X-Requested-With = %q, want XMLHttpRequest", requestHeaders.Get("X-Requested-With"))
	}
	if !strings.HasPrefix(requestHeaders.Get("Referer"), ts.URL) {
		t.Errorf("Referer = %q, want prefix %s", requestHeaders.Get("Referer"), ts.URL)
	}
}

func TestLivebox6ClientBadCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.htm":
			io.WriteString(w, spacerPage(keyIV()))
		case "/login.cgi":
			// Redirect back to login page on failure.
			http.Redirect(w, r, "/login.htm", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	_, err := newLivebox6Client(context.Background(), strings.TrimPrefix(ts.URL, "http://"), "admin", "wrong")
	if err == nil {
		t.Fatal("expected authentication error")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error = %v, want rejection message", err)
	}
}

func TestLivebox6ClientUnauthenticatedCGI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.htm":
			io.WriteString(w, spacerPage(keyIV()))
		case "/login.cgi":
			http.Redirect(w, r, "/network_connected.htm", http.StatusFound)
		case "/network_connected.htm":
			io.WriteString(w, spacerPage(append(keyIV(), testToken...)))
		case "/cgi/cgi_test.js":
			// An expired session redirects to the login page.
			http.Redirect(w, r, "/login.htm", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client, err := newLivebox6Client(context.Background(), strings.TrimPrefix(ts.URL, "http://"), "admin", "password")
	if err != nil {
		t.Fatalf("newLivebox6Client: %v", err)
	}

	_, err = client.getCGI(context.Background(), "test")
	if err == nil {
		t.Fatal("expected an error when the router redirects the data request to the login page")
	}
}
