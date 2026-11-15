package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientGetCGI(t *testing.T) {
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

	client, err := NewClient(context.Background(), strings.TrimPrefix(ts.URL, "http://"), "admin", "password")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	data, err := client.CGI(context.Background(), "test")
	if err != nil {
		t.Fatalf("CGI: %v", err)
	}
	if got, want := data.Get("foo"), "bar"; got != want {
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

func TestClientBadCredentials(t *testing.T) {
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

	_, err := NewClient(context.Background(), strings.TrimPrefix(ts.URL, "http://"), "admin", "wrong")
	if err == nil {
		t.Fatal("expected authentication error")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error = %v, want rejection message", err)
	}
}

func TestClientUnauthenticatedCGI(t *testing.T) {
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

	client, err := NewClient(context.Background(), strings.TrimPrefix(ts.URL, "http://"), "admin", "password")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.CGI(context.Background(), "test")
	if err == nil {
		t.Fatal("expected an error when the router redirects the data request to the login page")
	}
}
