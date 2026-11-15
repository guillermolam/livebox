package commands

import (
	"testing"

	"github.com/guillermolam/livebox/api"
)

func TestFilterClients(t *testing.T) {
	clients := []api.ClientDetail{
		{Name: "Laptop", IP: "192.168.1.10", MAC: "AA:BB:CC:DD:EE:FF"},
		{Name: "Phone", IP: "192.168.1.20", MAC: "11:22:33:44:55:66"},
	}

	cases := []struct {
		name    string
		target  string
		wantLen int
	}{
		{"all", "", 2},
		{"by IP", "192.168.1.10", 1},
		{"by MAC with dashes", "aa-bb-cc-dd-ee-ff", 1},
		{"by name substring", "phone", 1},
		{"no match", "nope", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterClients(clients, tc.target)
			if len(got) != tc.wantLen {
				t.Fatalf("filterClients(%q) returned %d client(s), want %d", tc.target, len(got), tc.wantLen)
			}
		})
	}
}
