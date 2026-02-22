package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config holds the application configuration loaded from environment variables.
type Config struct {
	DiscordKey string
	DBPath     string
}

// Load loads environment variables from the specified path and returns a Config.
// If path is empty, it loads from the current working directory using godotenv.Load().
// It validates that DISCORD_KEY is set and non-empty.
func Load(path string) (*Config, error) {
	var err error
	if path == "" {
		err = godotenv.Load()
	} else {
		err = godotenv.Load(path)
	}
	if err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	discordKey := os.Getenv("DISCORD_KEY")
	if discordKey == "" {
		return nil, fmt.Errorf("DISCORD_KEY is not set")
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "database.db" // Default value
	}

	return &Config{
		DiscordKey: discordKey,
		DBPath:     dbPath,
	}, nil
}
