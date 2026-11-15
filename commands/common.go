// Package commands defines the CLI command tree of the livebox tool.
package commands

import (
	"errors"
	"fmt"
	"os"

	"github.com/guillermolam/livebox/api"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// Config is the saved connection configuration (~/.config/livebox.yml).
type Config struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to find the home directory: %w", err)
	}
	return home + "/.config/livebox.yml", nil
}

func loadConfig() (Config, error) {
	config := Config{
		Address:  "192.168.1.1",
		Username: "admin",
	}

	path, err := configPath()
	if err != nil {
		return config, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return config, nil // Use default config if file doesn't exist
	}

	configFile, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return config, nil
}

func saveConfig(config Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	configFile, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create the necessary directories if they don't exist.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to find the home directory: %w", err)
	}
	err = os.MkdirAll(home+"/.config", 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	err = os.WriteFile(path, configFile, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// connection resolves the connection settings for a command: the command-line
// flags take precedence over the saved configuration.
func connection(cmd *cobra.Command) (address, username, password string, err error) {
	config, err := loadConfig()
	if err != nil {
		return "", "", "", err
	}
	if v, err := cmd.Flags().GetString("address"); err == nil && v != "" {
		config.Address = v
	}
	if v, err := cmd.Flags().GetString("username"); err == nil && v != "" {
		config.Username = v
	}
	if v, err := cmd.Flags().GetString("password"); err == nil && v != "" {
		config.Password = v
	}
	return config.Address, config.Username, config.Password, nil
}

// clientFromConfig logs in to the Livebox using the flags and configuration.
func clientFromConfig(cmd *cobra.Command) (*api.Client, error) {
	address, username, password, err := connection(cmd)
	if err != nil {
		return nil, err
	}
	return api.NewClient(cmd.Context(), address, username, password)
}

// errWriteNotImplemented is returned by every command that changes the router
// configuration: the apply_abstract.cgi payloads are not known yet.
var errWriteNotImplemented = errors.New("this command is not yet implemented for Livebox 6/7; capture the browser action and send the HAR to add support")

// writeStub builds a placeholder command for actions whose apply_abstract.cgi
// payload has not been captured yet. Unknown flags are tolerated so the
// command tree shape can already be used in scripts and tests.
func writeStub(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return errWriteNotImplemented
		},
	}
}
