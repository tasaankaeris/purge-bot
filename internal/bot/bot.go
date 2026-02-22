package bot

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"gorm.io/gorm"
)

// MessageFetcherDeleter abstracts Discord message operations for testing.
type MessageFetcherDeleter interface {
	ChannelMessages(channelID string, limit int, beforeID, afterID, aroundID string) ([]*discordgo.Message, error)
	ChannelMessageDelete(channelID, msgID string) error
}

// Bot represents the purge bot instance.
type Bot struct {
	activeTasks        map[string]*time.Ticker
	activeThreadTasks  map[string]*time.Ticker
	db                 *gorm.DB
	purgeInterval      time.Duration
	maxDuration        time.Duration
	minDuration        time.Duration
	messageAPI         MessageFetcherDeleter
	session            *discordgo.Session // Kept for non-purge operations (permissions, etc.)
}

// Task represents a purge task stored in the database.
type Task struct {
	ChannelID            string `gorm:"primaryKey"`
	PurgeDurationSeconds int
}

// ThreadCleanupTask represents a thread cleanup task stored in the database.
type ThreadCleanupTask struct {
	ParentChannelID      string `gorm:"primaryKey"`
	PurgeDurationSeconds int
}

// UserPermission represents a user permission stored in the database.
type UserPermission struct {
	ID       uint `gorm:"primaryKey"`
	UserID   string
	GuildID  string
	CanPurge bool
}

// RolePermission represents a role permission stored in the database.
type RolePermission struct {
	ID       uint `gorm:"primaryKey"`
	RoleID   string
	GuildID  string
	CanPurge bool
}

// NewBot creates a new Bot instance with the provided database and message API interface.
func NewBot(db *gorm.DB, messageAPI MessageFetcherDeleter) *Bot {
	return &Bot{
		activeTasks:       make(map[string]*time.Ticker),
		activeThreadTasks: make(map[string]*time.Ticker),
		db:                db,
		purgeInterval:     33 * time.Second,
		maxDuration:       3333 * 24 * time.Hour,
		minDuration:       30 * time.Second,
		messageAPI:        messageAPI,
	}
}

// SetSession sets the Discord session for non-purge operations.
func (b *Bot) SetSession(s *discordgo.Session) {
	b.session = s
}

// Ready handles the Discord ready event.
func (b *Bot) Ready(s *discordgo.Session, event *discordgo.Ready) {
	fmt.Println("Bot is ready")
	fmt.Printf("Logged in as: %s\n", s.State.User.Username)

	// AutoMigrate ThreadCleanupTask
	if err := b.db.AutoMigrate(&ThreadCleanupTask{}); err != nil {
		log.Println("Error migrating ThreadCleanupTask:", err)
	}

	var tasks []Task
	if err := b.db.Find(&tasks).Error; err != nil {
		log.Println("Error querying tasks:", err)
		return
	}

	for _, task := range tasks {
		channelID := task.ChannelID
		duration := time.Duration(task.PurgeDurationSeconds) * time.Second

		// Fetch channel directly from Discord API
		channel, err := s.Channel(channelID)
		if err != nil {
			log.Printf("Error fetching channel %s: %v", channelID, err)
			b.deleteTaskDB(channelID)
			continue
		}

		if channel.Type != discordgo.ChannelTypeGuildText {
			log.Printf("Channel %s is not a text channel", channelID)
			b.deleteTaskDB(channelID)
			continue
		}

		b.setPurgeTaskLoop(s, channelID, duration)
	}

	// Load thread cleanup tasks
	var threadTasks []ThreadCleanupTask
	if err := b.db.Find(&threadTasks).Error; err != nil {
		log.Println("Error querying thread cleanup tasks:", err)
		return
	}

	for _, task := range threadTasks {
		parentChannelID := task.ParentChannelID
		duration := time.Duration(task.PurgeDurationSeconds) * time.Second

		// Fetch channel directly from Discord API
		channel, err := s.Channel(parentChannelID)
		if err != nil {
			log.Printf("Error fetching parent channel %s: %v", parentChannelID, err)
			b.deleteThreadCleanupTaskDB(parentChannelID)
			continue
		}

		if channel.Type != discordgo.ChannelTypeGuildText {
			log.Printf("Parent channel %s is not a text channel", parentChannelID)
			b.deleteThreadCleanupTaskDB(parentChannelID)
			continue
		}

		b.setThreadCleanupTaskLoop(s, parentChannelID, duration)
	}
}

// MessageCreate handles incoming Discord messages.
func (b *Bot) MessageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	log.Printf("Received message from %s: %s", m.Author.ID, m.Content)

	if strings.HasPrefix(m.Content, "<@") && strings.Contains(m.Content, s.State.User.ID) {
		log.Println("Bot mentioned in message")

		if !b.isAdminOrOwner(s, m.GuildID, m.Author.ID) && !b.checkUserPermission(s, m.GuildID, m.Author.ID) {
			s.ChannelMessageSend(m.ChannelID, "You don't have the necessary permissions to use this bot. You must be either the server owner, an administrator, or a user with special permissions assigned by an admin.")
			return
		}

		args := strings.Fields(m.Content)
		if len(args) < 2 {
			s.ChannelMessageSend(m.ChannelID, "Insufficient arguments. Type @bot help for available commands.")
			return
		}

		command := strings.ToLower(args[1])
		channelID := m.ChannelID

		botMention := fmt.Sprintf("<@%s>", s.State.User.ID)

		switch command {
		case "help":
			helpMessage := fmt.Sprintf(`
**PURGING COMMANDS**
_by default only for admins and server owners_

purge old messages:
%s 3d
%s messages 3d
(or any custom duration like 30s, 5m, 24h, 2d)

delete old threads:
%s threads 6d
(or any custom duration)

stop tasks:
%s stop (stops both message purge and thread cleanup)
%s messages stop (stops message purge only)
%s threads stop (stops thread cleanup only)

list purge tasks:
%s list

**USER/ROLE MANAGEMENT**
list permissions:
%s listpermissions

user permission to manage purge tasks:
%s adduser <username>
%s adduserid <user id>
%s removeuser <username>
%s removeuserid <user id>

role permission to manage purge tasks:
%s addrole <role name>
%s addroleid <role id>
%s removerole <role name>
%s removeroleid <role id>

get help:
%s help`,
				botMention, botMention,
				botMention, botMention,
				botMention, botMention,
				botMention, botMention,
				botMention, botMention,
				botMention, botMention,
				botMention, botMention,
				botMention, botMention, botMention)
			s.ChannelMessageSend(m.ChannelID, helpMessage)

		case "messages":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a duration (e.g., '3d') or 'stop'. Usage: @bot messages 3d or @bot messages stop")
				return
			}
			if args[2] == "stop" {
				b.stopAndDeleteTask(channelID)
				s.ChannelMessageSend(m.ChannelID, "Message purging stopped for this channel.")
			} else {
				duration, err := ParseDuration(args[2])
				if err != nil {
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Invalid duration: %v. Type @bot help for available commands.", err))
					return
				}
				b.setPurgeTaskLoop(s, channelID, duration)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Messages older than %s will be deleted on a rolling basis in this channel.", FormatDuration(duration)))
			}

		case "threads":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a duration (e.g., '6d') or 'stop'. Usage: @bot threads 6d or @bot threads stop")
				return
			}
			if args[2] == "stop" {
				b.stopThreadCleanupTask(channelID)
				b.deleteThreadCleanupTaskDB(channelID)
				s.ChannelMessageSend(m.ChannelID, "Thread cleanup stopped for this channel.")
			} else {
				duration, err := ParseDuration(args[2])
				if err != nil {
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Invalid duration: %v. Type @bot help for available commands.", err))
					return
				}
				b.setThreadCleanupTaskLoop(s, channelID, duration)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Threads older than %s will be deleted on a rolling basis under this channel.", FormatDuration(duration)))
			}

		case "stop":
			b.stopAndDeleteTask(channelID)
			b.stopThreadCleanupTask(channelID)
			b.deleteThreadCleanupTaskDB(channelID)
			s.ChannelMessageSend(m.ChannelID, "All purge tasks stopped for this channel.")

		case "list":
			b.listPurgeTasks(s, m.GuildID, m.ChannelID)

		case "adduser":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a username.")
				return
			}
			username := strings.Join(args[2:], " ")
			userID, err := b.getUserIDByName(s, m.GuildID, username)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("User '%s' not found.", username))
				return
			}
			b.addUserPermission(m.GuildID, userID, true)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("User '%s' can now manage purge tasks.", username))
		case "removeuser":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a username.")
				return
			}
			username := strings.Join(args[2:], " ")
			userID, err := b.getUserIDByName(s, m.GuildID, username)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("User '%s' not found.", username))
				return
			}
			b.removeUserPermission(m.GuildID, userID)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("User '%s' can no longer manage purge tasks.", username))
		case "addrole":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a role name.")
				return
			}
			roleName := strings.Join(args[2:], " ")
			roleID, err := b.getRoleIDByName(s, m.GuildID, roleName)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Role '%s' not found.", roleName))
				return
			}
			b.addRolePermission(m.GuildID, roleID, true)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Role '%s' can now manage purge tasks.", roleName))
		case "removerole":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a role name.")
				return
			}
			roleName := strings.Join(args[2:], " ")
			roleID, err := b.getRoleIDByName(s, m.GuildID, roleName)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Role '%s' not found.", roleName))
				return
			}
			b.removeRolePermission(m.GuildID, roleID)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Role '%s' can no longer manage purge tasks.", roleName))
		case "adduserid":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a username.")
				return
			}
			userID := args[2]
			b.addUserPermission(m.GuildID, userID, true)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("User %s can now manage purge tasks.", userID))
			return
		case "removeuserid":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a user ID.")
				return
			}
			userID := args[2]
			if err := b.removeUserPermission(m.GuildID, userID); err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Failed to remove user %s's permissions: %v", userID, err))
			} else {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("User %s can no longer manage purge tasks.", userID))
			}
		case "addroleid":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a role name.")
				return
			}
			roleID := args[2]
			b.addRolePermission(m.GuildID, roleID, true)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Role %s can now manage purge tasks.", roleID))
			return
		case "removeroleid":
			if len(args) < 3 {
				s.ChannelMessageSend(m.ChannelID, "Please provide a role ID.")
				return
			}
			roleID := args[2]
			if err := b.removeRolePermission(m.GuildID, roleID); err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Failed to remove role %s's permissions: %v", roleID, err))
			} else {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Role %s can no longer manage purge tasks.", roleID))
			}
		case "listpermissions":
			users, err := b.listUserPermissions(s, m.GuildID)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Failed to retrieve user permissions: %v", err))
				return
			}

			roles, err := b.listRolePermissions(s, m.GuildID)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Failed to retrieve role permissions: %v", err))
				return
			}

			var message strings.Builder
			message.WriteString("**Registered Users and Roles for Purge Tasks:**\n\n")

			if len(users) == 0 && len(roles) == 0 {
				message.WriteString("No users or roles are registered to manage purge tasks.")
			} else {
				if len(users) > 0 {
					message.WriteString("**Users:**\n")
					for _, user := range users {
						message.WriteString(fmt.Sprintf("- %s\n", user))
					}
				}

				if len(roles) > 0 {
					message.WriteString("**Roles:**\n")
					for _, role := range roles {
						message.WriteString(fmt.Sprintf("- %s\n", role))
					}
				}
			}

			s.ChannelMessageSend(m.ChannelID, message.String())
		default:
			duration, err := ParseDuration(command)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, "Invalid duration. Type @bot help for available commands.")
				return
			}
			b.setPurgeTaskLoop(s, channelID, duration)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Messages older than %s will be deleted on a rolling basis in this channel.", FormatDuration(duration)))
		}
	}
}

func (b *Bot) isAdminOrOwner(s *discordgo.Session, guildID, userID string) bool {
	// Fetch member directly if state cache is not available
	member, err := s.GuildMember(guildID, userID)
	if err != nil {
		log.Println("Error fetching member from API:", err)
		return false
	}

	// Fetch guild directly if state cache is not available
	guild, err := s.Guild(guildID)
	if err != nil {
		log.Println("Error fetching guild from API:", err)
		return false
	}

	// Check if the user is the owner
	if guild.OwnerID == userID {
		return true
	}

	// Check if the user has the Administrator permission
	for _, roleID := range member.Roles {
		role, err := s.State.Role(guildID, roleID)
		if err != nil {
			log.Println("Error fetching role from API:", err)
			continue
		}
		if role.Permissions&discordgo.PermissionAdministrator != 0 {
			return true
		}
	}

	return false
}

// ParseDuration parses a duration string (e.g., "30s", "5m", "24h", "2d") into a time.Duration.
func ParseDuration(input string) (time.Duration, error) {
	re := regexp.MustCompile(`^(\d+)([smhd])$`)
	match := re.FindStringSubmatch(input)
	if len(match) != 3 {
		return 0, fmt.Errorf("invalid duration format")
	}

	num, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("error parsing number: %v", err)
	}

	fmt.Printf("Parsed number: %d, unit: %s\n", num, match[2])

	switch match[2] {
	case "s":
		return time.Duration(num) * time.Second, nil
	case "m":
		return time.Duration(num) * time.Minute, nil
	case "h":
		return time.Duration(num) * time.Hour, nil
	case "d":
		return time.Duration(num) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid duration unit: %s", match[2])
	}
}

func (b *Bot) setPurgeTaskLoop(s *discordgo.Session, channelID string, duration time.Duration) {
	if duration < b.minDuration {
		duration = b.minDuration
	} else if duration > b.maxDuration {
		duration = b.maxDuration
	}

	fmt.Printf("Setting purge task for channel %s with duration %v\n", channelID, duration)

	b.stopTask(channelID)
	ticker := time.NewTicker(b.purgeInterval)
	b.activeTasks[channelID] = ticker

	go func() {
		for range ticker.C {
			b.purgeChannel(channelID, duration)
		}
	}()

	b.updateTaskDB(channelID, int(duration.Seconds()))
}

func (b *Bot) stopTask(channelID string) {
	if ticker, ok := b.activeTasks[channelID]; ok {
		ticker.Stop()
		delete(b.activeTasks, channelID)
	}
}

func (b *Bot) stopAndDeleteTask(channelID string) {
	b.stopTask(channelID)
	b.deleteTaskDB(channelID)
}

func (b *Bot) purgeChannel(channelID string, duration time.Duration) {
	var lastMessageID string
	threshold := time.Now().Add(-duration)

	for {
		messages, err := b.messageAPI.ChannelMessages(channelID, 100, lastMessageID, "", "")
		if err != nil {
			log.Println("Error fetching messages:", err)
			return
		}

		if len(messages) == 0 {
			break
		}

		for _, msg := range messages {
			// log.Printf("Checking message %s from %s, timestamp: %s", msg.ID, msg.Author.ID, msg.Timestamp)

			if msg.Timestamp.Before(threshold) {
				err = b.messageAPI.ChannelMessageDelete(channelID, msg.ID)
				if err != nil {
					log.Printf("Error deleting message %s: %v", msg.ID, err)
				} else {
					log.Printf("Deleted message %s", msg.ID)
				}
			}
		}

		lastMessageID = messages[len(messages)-1].ID
	}
}

func (b *Bot) updateTaskDB(channelID string, durationSeconds int) {
	task := Task{ChannelID: channelID, PurgeDurationSeconds: durationSeconds}
	if err := b.db.Save(&task).Error; err != nil {
		log.Println("Error updating database:", err)
	}
}

func (b *Bot) deleteTaskDB(channelID string) {
	if err := b.db.Delete(&Task{}, "channel_id = ?", channelID).Error; err != nil {
		log.Println("Error deleting from database:", err)
	}
}

func (b *Bot) setThreadCleanupTaskLoop(s *discordgo.Session, parentChannelID string, duration time.Duration) {
	if duration < b.minDuration {
		duration = b.minDuration
	} else if duration > b.maxDuration {
		duration = b.maxDuration
	}

	fmt.Printf("Setting thread cleanup task for parent channel %s with duration %v\n", parentChannelID, duration)

	b.stopThreadCleanupTask(parentChannelID)
	ticker := time.NewTicker(b.purgeInterval)
	b.activeThreadTasks[parentChannelID] = ticker

	go func() {
		for range ticker.C {
			b.runThreadCleanup(s, parentChannelID, duration)
		}
	}()

	b.updateThreadCleanupTaskDB(parentChannelID, int(duration.Seconds()))
}

func (b *Bot) stopThreadCleanupTask(parentChannelID string) {
	if ticker, ok := b.activeThreadTasks[parentChannelID]; ok {
		ticker.Stop()
		delete(b.activeThreadTasks, parentChannelID)
	}
}

func (b *Bot) runThreadCleanup(s *discordgo.Session, parentChannelID string, duration time.Duration) {
	threshold := time.Now().Add(-duration)

	// Get parent channel to find guild ID
	channel, err := s.Channel(parentChannelID)
	if err != nil {
		log.Printf("Error fetching parent channel %s: %v", parentChannelID, err)
		return
	}

	// Try to list active threads for the channel
	// Note: Check discordgo API documentation for correct method names.
	// Discord API endpoints are:
	// - GET /channels/{channel.id}/threads/active
	// - GET /guilds/{guild.id}/threads/active
	// If discordgo doesn't expose these methods, the code below will need to be updated
	// with the correct method names or REST API calls.
	var threads []*discordgo.Channel

	// List active threads for the channel (discordgo v0.28.1: ThreadsActive / GuildThreadsActive)
	threadsList, err := s.ThreadsActive(parentChannelID)
	if err != nil {
		// Fallback: try to get threads from guild
		guildThreads, err := s.GuildThreadsActive(channel.GuildID)
		if err != nil {
			// If both methods fail, log that thread list is not implemented
			// This indicates discordgo may not expose thread listing API
			log.Printf("Thread list not implemented: discordgo may not expose thread listing API. Error: %v", err)
			log.Printf("Need to verify correct discordgo method names for listing threads or implement REST API call directly")
			return
		}

		// Filter threads that belong to this parent channel
		for _, thread := range guildThreads.Threads {
			if thread.ParentID == parentChannelID {
				threads = append(threads, thread)
			}
		}
	} else {
		threads = threadsList.Threads
	}

	if len(threads) == 0 {
		return
	}

	for _, thread := range threads {
		// Get thread creation time from Discord snowflake ID (discordgo has no ThreadMetadata.CreatedAt or Channel.CreatedAt)
		creationTime, err := discordgo.SnowflakeTimestamp(thread.ID)
		if err != nil {
			log.Printf("Could not parse thread ID %s: %v", thread.ID, err)
			continue
		}

		if creationTime.Before(threshold) {
			_, err = s.ChannelDelete(thread.ID)
			if err != nil {
				log.Printf("Error deleting thread %s: %v", thread.ID, err)
			} else {
				log.Printf("Deleted thread %s", thread.ID)
			}
		}
	}
}

func (b *Bot) updateThreadCleanupTaskDB(parentChannelID string, durationSeconds int) {
	task := ThreadCleanupTask{ParentChannelID: parentChannelID, PurgeDurationSeconds: durationSeconds}
	if err := b.db.Save(&task).Error; err != nil {
		log.Println("Error updating thread cleanup task database:", err)
	}
}

func (b *Bot) deleteThreadCleanupTaskDB(parentChannelID string) {
	if err := b.db.Delete(&ThreadCleanupTask{}, "parent_channel_id = ?", parentChannelID).Error; err != nil {
		log.Println("Error deleting thread cleanup task from database:", err)
	}
}

func (b *Bot) listPurgeTasks(s *discordgo.Session, guildID, channelID string) {
	var tasks []Task
	if err := b.db.Find(&tasks).Error; err != nil {
		log.Println("Error querying tasks:", err)
		s.ChannelMessageSend(channelID, "Error retrieving tasks.")
		return
	}

	var threadTasks []ThreadCleanupTask
	if err := b.db.Find(&threadTasks).Error; err != nil {
		log.Println("Error querying thread cleanup tasks:", err)
		s.ChannelMessageSend(channelID, "Error retrieving thread cleanup tasks.")
		return
	}

	// Build a map of channel ID to task info
	channelTasks := make(map[string]struct {
		messageDuration string
		threadDuration  string
	})

	// Process message purge tasks
	for _, task := range tasks {
		ch, err := s.State.Channel(task.ChannelID)
		if err != nil {
			// Try fetching directly if not in state
			ch, err = s.Channel(task.ChannelID)
			if err != nil {
				log.Println("Error fetching channel:", err)
				continue
			}
		}
		if ch.GuildID == guildID {
			duration := time.Duration(task.PurgeDurationSeconds) * time.Second
			info := channelTasks[task.ChannelID]
			info.messageDuration = FormatDuration(duration)
			channelTasks[task.ChannelID] = info
		}
	}

	// Process thread cleanup tasks
	for _, task := range threadTasks {
		ch, err := s.State.Channel(task.ParentChannelID)
		if err != nil {
			// Try fetching directly if not in state
			ch, err = s.Channel(task.ParentChannelID)
			if err != nil {
				log.Println("Error fetching parent channel:", err)
				continue
			}
		}
		if ch.GuildID == guildID {
			duration := time.Duration(task.PurgeDurationSeconds) * time.Second
			info := channelTasks[task.ParentChannelID]
			info.threadDuration = FormatDuration(duration)
			channelTasks[task.ParentChannelID] = info
		}
	}

	if len(channelTasks) == 0 {
		s.ChannelMessageSend(channelID, "No purge tasks found for this guild.")
		return
	}

	var sb strings.Builder
	for chID, info := range channelTasks {
		var parts []string
		if info.messageDuration != "" {
			parts = append(parts, fmt.Sprintf("messages %s", info.messageDuration))
		}
		if info.threadDuration != "" {
			parts = append(parts, fmt.Sprintf("threads %s", info.threadDuration))
		}
		if len(parts) > 0 {
			sb.WriteString(fmt.Sprintf("<#%s>: %s\n", chID, strings.Join(parts, ", ")))
		}
	}

	s.ChannelMessageSend(channelID, sb.String())
}

func (b *Bot) getUserIDByName(s *discordgo.Session, guildID, username string) (string, error) {
	members, err := s.GuildMembers(guildID, "", 1000) // Increase limit if necessary
	if err != nil {
		return "", err
	}
	for _, member := range members {
		if member.User.Username == username {
			return member.User.ID, nil
		}
	}

	return "", fmt.Errorf("user not found, try user ID instead")
}

func (b *Bot) addUserPermission(guildID, userID string, canPurge bool) {
	permission := UserPermission{
		UserID:   userID,
		GuildID:  guildID,
		CanPurge: canPurge,
	}
	b.db.Save(&permission)
}

func (b *Bot) removeUserPermission(guildID, userID string) error {
	if err := b.db.Where("guild_id = ? AND user_id = ?", guildID, userID).Delete(&UserPermission{}).Error; err != nil {
		return fmt.Errorf("failed to remove user permission: %v", err)
	}
	return nil
}

func (b *Bot) getRoleIDByName(s *discordgo.Session, guildID, roleName string) (string, error) {
	// Fetch all roles in the guild
	roles, err := s.GuildRoles(guildID)
	if err != nil {
		return "", err
	}

	// Loop through the roles to find the role by name
	for _, role := range roles {
		if role.Name == roleName {
			return role.ID, nil
		}
	}

	return "", fmt.Errorf("role not found")
}

func (b *Bot) addRolePermission(guildID, roleID string, canPurge bool) {
	permission := RolePermission{
		RoleID:   roleID,
		GuildID:  guildID,
		CanPurge: canPurge,
	}
	b.db.Save(&permission)
}

func (b *Bot) removeRolePermission(guildID, roleID string) error {
	if err := b.db.Where("guild_id = ? AND role_id = ?", guildID, roleID).Delete(&RolePermission{}).Error; err != nil {
		return fmt.Errorf("failed to remove role permission: %v", err)
	}
	return nil
}

func (b *Bot) checkUserPermission(s *discordgo.Session, guildID, userIDOrName string) bool {
	// First, assume the input is a user ID and try to check by ID
	var permission UserPermission
	if err := b.db.Where("guild_id = ? AND user_id = ?", guildID, userIDOrName).First(&permission).Error; err == nil {
		return permission.CanPurge
	}

	// If no user-specific permission is found, resolve the name to an ID if necessary
	member, err := s.GuildMember(guildID, userIDOrName)
	if err != nil {
		// If the input is not a user ID, try to resolve it as a username or nickname
		userID, err := b.getUserIDByName(s, guildID, userIDOrName)
		if err != nil {
			return false // User not found by name either
		}

		// Check user-specific permissions with the resolved user ID
		if err := b.db.Where("guild_id = ? AND user_id = ?", guildID, userID).First(&permission).Error; err == nil {
			return permission.CanPurge
		}

		// Now that we have a valid user ID, get the GuildMember object
		member, err = s.GuildMember(guildID, userID)
		if err != nil {
			return false
		}
	}

	// Check role permissions if no specific user permission is found
	for _, roleID := range member.Roles {
		var rolePermission RolePermission
		if err := b.db.Where("guild_id = ? AND role_id = ?", guildID, roleID).First(&rolePermission).Error; err == nil {
			if rolePermission.CanPurge {
				return true
			}
		}
	}

	return false
}

func (b *Bot) listUserPermissions(s *discordgo.Session, guildID string) ([]string, error) {
	var permissions []UserPermission
	err := b.db.Where("guild_id = ?", guildID).Find(&permissions).Error
	if err != nil {
		return nil, err
	}

	var users []string
	for _, permission := range permissions {
		member, err := s.GuildMember(guildID, permission.UserID)
		if err != nil {
			users = append(users, fmt.Sprintf("%s (unknown name)", permission.UserID))
		} else {
			users = append(users, fmt.Sprintf("%s (%s)", member.User.ID, member.User.Username))
		}
	}

	return users, nil
}

func (b *Bot) listRolePermissions(s *discordgo.Session, guildID string) ([]string, error) {
	var permissions []RolePermission
	err := b.db.Where("guild_id = ?", guildID).Find(&permissions).Error
	if err != nil {
		return nil, err
	}

	var roles []string
	guild, err := s.Guild(guildID)
	if err != nil {
		return nil, err
	}

	for _, permission := range permissions {
		role, err := s.State.Role(guildID, permission.RoleID)
		if err != nil {
			// Attempt to fetch the role if not present in the state
			for _, r := range guild.Roles {
				if r.ID == permission.RoleID {
					role = r
					break
				}
			}
		}
		if role.ID == "" {
			roles = append(roles, fmt.Sprintf("%s (unknown name)", permission.RoleID))
		} else {
			roles = append(roles, fmt.Sprintf("%s (%s)", role.ID, role.Name))
		}
	}

	return roles, nil
}

// FormatDuration formats a time.Duration into a human-readable string.
func FormatDuration(duration time.Duration) string {
	if duration%(24*time.Hour) == 0 {
		days := duration / (24 * time.Hour)
		if days > 1 {
			return fmt.Sprintf("%d days", days)
		}
		return "1 day"
	}
	if duration%time.Hour == 0 {
		hours := duration / time.Hour
		if hours > 1 {
			return fmt.Sprintf("%d hours", hours)
		}
		return "1 hour"
	}
	if duration%time.Minute == 0 {
		minutes := duration / time.Minute
		if minutes > 1 {
			return fmt.Sprintf("%d minutes", minutes)
		}
		return "1 minute"
	}
	seconds := duration / time.Second
	if seconds > 1 {
		return fmt.Sprintf("%d seconds", seconds)
	}
	return "1 second"
}
