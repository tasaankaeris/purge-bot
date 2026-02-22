package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/bwmarrin/discordgo"
	"github.com/keshon/purge-bot/internal/bot"
	"github.com/keshon/purge-bot/internal/config"
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
	flag.Parse()

	cfg, err := config.Load(*envPath)
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}

	// CLI flag overrides env/config value
	cfg.DBPath = *dbPath

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

	dg.AddHandler(b.Ready)
	dg.AddHandler(b.MessageCreate)

	if err := dg.Open(); err != nil {
		log.Fatal("Error opening Discord session: ", err)
	}

	fmt.Println("Bot is now running. Press CTRL+C to exit.")
	select {}
}
