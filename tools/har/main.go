// Command har extracts the write-relevant traffic from a HAR capture.
// Usage: go run ./tools/har <file.har> [paths-only | dump <path>]
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

type har struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method   string `json:"method"`
				URL      string `json:"url"`
				PostData struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
					Params   []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"params"`
				} `json:"postData"`
			} `json:"request"`
			Response struct {
				Status  int `json:"status"`
				Content struct {
					MimeType string `json:"mimeType"`
					Size     int    `json:"size"`
					Text     string `json:"text"`
					Encoding string `json:"encoding"`
				} `json:"content"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
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

	if len(os.Args) > 3 && os.Args[2] == "dump" {
		want := os.Args[3]
		for _, e := range h.Log.Entries {
			u, _ := url.Parse(e.Request.URL)
			if u.Path != want {
				continue
			}
			text := e.Response.Content.Text
			if e.Response.Content.Encoding == "base64" {
				raw, err := base64.StdEncoding.DecodeString(text)
				if err != nil {
					panic(err)
				}
				text = string(raw)
			}
			fmt.Print(text)
			return
		}
		fmt.Fprintf(os.Stderr, "not found: %s\n", want)
		os.Exit(1)
	}

	type key struct{ method, path string }
	counts := map[key]int{}
	for _, e := range h.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil {
			continue
		}
		counts[key{e.Request.Method, u.Path}]++
	}
	var keys []key
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		return keys[i].method < keys[j].method
	})
	for _, k := range keys {
		fmt.Printf("%-6s %-45s x%d\n", k.method, k.path, counts[k])
	}

	if len(os.Args) > 2 && os.Args[2] == "paths-only" {
		return
	}

	fmt.Println("\n=== POST bodies ===")
	for _, e := range h.Log.Entries {
		if e.Request.Method != "POST" {
			continue
		}
		u, _ := url.Parse(e.Request.URL)
		fmt.Printf("\n--- POST %s -> %d (%s)\n", u.Path, e.Response.Status, e.Response.Content.MimeType)
		pd := e.Request.PostData
		if len(pd.Params) > 0 {
			for _, p := range pd.Params {
				v := p.Value
				if len(v) > 120 {
					v = v[:120] + "…"
				}
				fmt.Printf("  %s = %s\n", p.Name, v)
			}
		} else if pd.Text != "" {
			text := strings.ReplaceAll(pd.Text, "\n", " ")
			if len(text) > 400 {
				text = text[:400] + "…"
			}
			fmt.Printf("  body: %s\n", text)
		}
	}
}
