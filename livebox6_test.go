package main

import "testing"

// Reference values produced by the router's own global.js (do_encode and
// ArcBase._t) for this spacer image.
const livebox6TestPage = `<img title=spacer src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7SjdtejFUOEpWc2szMWpqOG5od3ZhVU03MXVYNGRiWkREV25CdjRPRmt2cWZMKzRaMTU2Nzg0MTUx" border=0>`

func TestLivebox6Keys(t *testing.T) {
	key, iv, err := livebox6Keys(livebox6TestPage)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(key), "J7mz1T8JVsk31jj8nhwvaUM71uX4dbZD"; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
	if got, want := string(iv), "DWnBv4OFkvqfL+4Z"; got != want {
		t.Errorf("iv = %q, want %q", got, want)
	}
}

func TestLivebox6Encode(t *testing.T) {
	key, iv, err := livebox6Keys(livebox6TestPage)
	if err != nil {
		t.Fatal(err)
	}
	got, err := livebox6Encode("abcdefghijklmnopqrstuvwxyz0123456789", key, iv)
	if err != nil {
		t.Fatal(err)
	}
	want := "%c8%ea%16%e0%e3%c7%c9%c6%57%e4%23%91%a4%1a%7c%9c%8d%38%bf%2e%62%25%54%7f%a9%67%d9%2b%dc%ae%7a%27%09%11%84%1a%43%fa%a0%e6%96%57%de%0b%bb%e5%70%70"
	if got != want {
		t.Errorf("encode mismatch\n got: %s\nwant: %s", got, want)
	}
}
