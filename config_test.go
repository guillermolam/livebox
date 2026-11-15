package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := Config{Address: "192.168.1.1", Username: "admin", Password: "s3cret"}
	if err := saveConfig(want); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(home, ".config", "livebox.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}

	got, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("loadConfig() = %+v, want %+v", got, want)
	}
}
