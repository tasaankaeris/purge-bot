package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/bwmarrin/discordgo"
	"github.com/keshon/purge-bot/internal/bot"
	"github.com/keshon/purge-bot/internal/config"
	"github.com/keshon/purge-bot/internal/logger"
	"gopkg.in/natefinch/lumberjack.v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// discordgoAdapter adapts discordgo.Session to bot.MessageFetcherDeleter interface.
type discordgoAdapter struct {
	session *discordgo.Session
}

func (a *discordgoAdapter) ChannelMessages(channelID string, limit int, beforeID, afterID, aroundID string) ([]*discordgo.Message, error) {
	return a.session.ChannelMessages(channelID, limit, beforeID, afterID, aroundID)
}

func (a *discordgoAdapter) ChannelMessageDelete(channelID, msgID string) error {
	return a.session.ChannelMessageDelete(channelID, msgID)
}

func main() {
	envPath := flag.String("env", "", "Path to .env file (empty = load from current working directory)")
	dbPath := flag.String("db", "database.db", "Path to database file")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	logFormat := flag.String("log-format", "text", "Log format: text or json")
	logFile := flag.String("log-file", "", "Optional path to log file (stdout/stderr if empty); supports rotation by size if using lumberjack")
	flag.Parse()

	// Build logger output (stderr or file with size-based rotation)
	var logOutput io.Writer = os.Stderr
	if *logFile != "" {
		logOutput = &lumberjack.Logger{
			Filename:   *logFile,
			MaxSize:    100, // MB
			MaxBackups: 3,
			MaxAge:     28, // days
			Compress:   true,
		}
	}

	l := logger.New(logger.Config{
		Level:  logger.ParseLevel(*logLevel),
		Format: *logFormat,
		Output: logOutput,
	})

	cfg, err := config.Load(*envPath)
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}

	// CLI flag overrides env/config value
	cfg.DBPath = *dbPath

	l.Info("starting", "db_path", cfg.DBPath, "log_level", *logLevel, "log_format", *logFormat)

	db, err := gorm.Open(sqlite.Open(cfg.DBPath), &gorm.Config{})
	if err != nil {
		log.Fatal("Error opening database: ", err)
	}

	if err := db.AutoMigrate(&bot.Task{}, &bot.ThreadCleanupTask{}, &bot.UserPermission{}, &bot.RolePermission{}); err != nil {
		log.Fatal("Error migrating database: ", err)
	}

	dg, err := discordgo.New("Bot " + cfg.DiscordKey)
	if err != nil {
		log.Fatal("Error creating Discord session: ", err)
	}

	adapter := &discordgoAdapter{session: dg}
	b := bot.NewBot(db, adapter)
	b.SetSession(dg)
	b.SetLogger(l)

	dg.AddHandler(b.Ready)
	dg.AddHandler(b.MessageCreate)

	if err := dg.Open(); err != nil {
		log.Fatal("Error opening Discord session: ", err)
	}

	l.Info("bot running", "purge_interval", "33s", "min_duration", "30s", "max_duration", "3333d")
	fmt.Println("Bot is now running. Press CTRL+C to exit.")
	select {}
}
