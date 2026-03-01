package bot

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"gorm.io/gorm"
)

// Logger provides leveled logging. If nil, log calls are no-ops.
type Logger interface {
	Debug(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
	Warn(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
}

// MessageFetcherDeleter abstracts Discord message operations for testing.
type MessageFetcherDeleter interface {
	ChannelMessages(channelID string, limit int, beforeID, afterID, aroundID string) ([]*discordgo.Message, error)
	ChannelMessageDelete(channelID, msgID string) error
}

// Bot represents the purge bot instance.
type Bot struct {
	ctx                     context.Context
	cancel                  context.CancelFunc
	cancelOnce              sync.Once
	taskMu                  sync.Mutex
	activeTasks             map[string]*time.Ticker
	activeTaskCancels       map[string]context.CancelFunc
	activeThreadTasks       map[string]*time.Ticker
	activeThreadTaskCancels map[string]context.CancelFunc
	db                      *gorm.DB
	purgeInterval           time.Duration
	maxDuration             time.Duration
	minDuration             time.Duration
	messageAPI              MessageFetcherDeleter
	session                 *discordgo.Session // Kept for non-purge operations (permissions, etc.)
	log                     Logger
	permErrorLastLog        map[string]time.Time // channelID -> last time we logged permission error
	permErrorMu             sync.Mutex
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
	ctx, cancel := context.WithCancel(context.Background())
	return &Bot{
		ctx:                     ctx,
		cancel:                  cancel,
		activeTasks:             make(map[string]*time.Ticker),
		activeTaskCancels:       make(map[string]context.CancelFunc),
		activeThreadTasks:       make(map[string]*time.Ticker),
		activeThreadTaskCancels: make(map[string]context.CancelFunc),
		db:                      db,
		purgeInterval:           33 * time.Second,
		maxDuration:             3333 * 24 * time.Hour,
		minDuration:             30 * time.Second,
		messageAPI:              messageAPI,
		permErrorLastLog:        make(map[string]time.Time),
	}
}

// SetSession sets the Discord session for non-purge operations.
func (b *Bot) SetSession(s *discordgo.Session) {
	b.session = s
}

// SetLogger sets the logger. If nil, logging is a no-op.
func (b *Bot) SetLogger(l Logger) {
	b.log = l
}

// Stop stops all purge and thread cleanup tickers and releases resources.
// It is safe to call multiple times. Use for graceful shutdown.
func (b *Bot) Stop() {
	b.cancelOnce.Do(b.cancel)
	b.taskMu.Lock()
	defer b.taskMu.Unlock()
	for _, cancel := range b.activeTaskCancels {
		cancel()
	}
	b.activeTaskCancels = make(map[string]context.CancelFunc)
	for _, cancel := range b.activeThreadTaskCancels {
		cancel()
	}
	b.activeThreadTaskCancels = make(map[string]context.CancelFunc)
	for channelID, ticker := range b.activeTasks {
		ticker.Stop()
		delete(b.activeTasks, channelID)
	}
	for parentChannelID, ticker := range b.activeThreadTasks {
		ticker.Stop()
		delete(b.activeThreadTasks, parentChannelID)
	}
}

func (b *Bot) logDebug(msg string, keyvals ...interface{}) {
	if b.log != nil {
		b.log.Debug(msg, keyvals...)
	}
}
func (b *Bot) logInfo(msg string, keyvals ...interface{}) {
	if b.log != nil {
		b.log.Info(msg, keyvals...)
	}
}
func (b *Bot) logWarn(msg string, keyvals ...interface{}) {
	if b.log != nil {
		b.log.Warn(msg, keyvals...)
	}
}

// sendChannelMessage sends a message to a channel and logs a warning on failure.
// Uses AllowedMentions with empty Parse to prevent @everyone/@here abuse from user-supplied text.
func (b *Bot) sendChannelMessage(s *discordgo.Session, channelID, content string) {
	msg := &discordgo.MessageSend{
		Content: content,
		AllowedMentions: &discordgo.MessageAllowedMentions{
			Parse: []discordgo.AllowedMentionType{},
		},
	}
	if _, err := s.ChannelMessageSendComplex(channelID, msg); err != nil {
		b.logWarn("failed to send message", "channel_id", channelID, "error", err)
	}
}
func (b *Bot) logError(msg string, keyvals ...interface{}) {
	if b.log != nil {
		b.log.Error(msg, keyvals...)
	}
}

const permErrorBackoff = 5 * time.Minute

// logPermissionErrorOnce logs a permission-denied error at most once per channel per permErrorBackoff.
func (b *Bot) logPermissionErrorOnce(channelID, guildID, userID string) {
	if b.log == nil {
		return
	}
	b.permErrorMu.Lock()
	last := b.permErrorLastLog[channelID]
	now := time.Now()
	if now.Sub(last) < permErrorBackoff {
		b.permErrorMu.Unlock()
		return
	}
	b.permErrorLastLog[channelID] = now
	b.permErrorMu.Unlock()
	b.log.Warn("permission denied", "channel_id", channelID, "guild_id", guildID, "user_id", userID)
}

// Ready handles the Discord ready event.
func (b *Bot) Ready(s *discordgo.Session, event *discordgo.Ready) {
	b.logInfo("bot ready", "username", s.State.User.Username)

	// AutoMigrate ThreadCleanupTask
	if err := b.db.AutoMigrate(&ThreadCleanupTask{}); err != nil {
		b.logError("migrating ThreadCleanupTask failed", "error", err)
	}

	var tasks []Task
	if err := b.db.Find(&tasks).Error; err != nil {
		b.logError("querying tasks failed", "error", err)
		return
	}

	for _, task := range tasks {
		channelID := task.ChannelID
		duration := time.Duration(task.PurgeDurationSeconds) * time.Second

		channel, err := s.Channel(channelID)
		if err != nil {
			b.logError("fetching channel failed", "channel_id", channelID, "error", err)
			b.deleteTaskDB(channelID)
			continue
		}

		if channel.Type != discordgo.ChannelTypeGuildText {
			b.logWarn("channel is not guild text, skipping restore", "channel_id", channelID)
			b.deleteTaskDB(channelID)
			continue
		}

		b.setPurgeTaskLoop(s, channelID, duration)
	}

	var threadTasks []ThreadCleanupTask
	if err := b.db.Find(&threadTasks).Error; err != nil {
		b.logError("querying thread cleanup tasks failed", "error", err)
		return
	}

	for _, task := range threadTasks {
		parentChannelID := task.ParentChannelID
		duration := time.Duration(task.PurgeDurationSeconds) * time.Second

		channel, err := s.Channel(parentChannelID)
		if err != nil {
			b.logError("fetching parent channel failed", "parent_channel_id", parentChannelID, "error", err)
			b.deleteThreadCleanupTaskDB(parentChannelID)
			continue
		}

		if channel.Type != discordgo.ChannelTypeGuildText {
			b.logWarn("parent channel is not guild text, skipping thread restore", "parent_channel_id", parentChannelID)
			b.deleteThreadCleanupTaskDB(parentChannelID)
			continue
		}

		b.setThreadCleanupTaskLoop(s, parentChannelID, duration)
	}

	b.logInfo("ready: restored tasks", "message_purge_tasks", len(tasks), "thread_cleanup_tasks", len(threadTasks))
}

// isBotMentionPrefix returns true if content (after trimming leading/trailing space)
// starts with the bot's mention. Discord format is <@USER_ID> or <@!USER_ID>.
func isBotMentionPrefix(content, botID string) bool {
	trimmed := strings.TrimSpace(content)
	return strings.HasPrefix(trimmed, "<@"+botID+">") || strings.HasPrefix(trimmed, "<@!"+botID+">")
}

// stripBotMentionPrefix removes the bot mention prefix from content and returns the rest.
// Discord format is <@USER_ID> or <@!USER_ID>.
func stripBotMentionPrefix(content, botID string) string {
	trimmed := strings.TrimSpace(content)
	for _, prefix := range []string{"<@!" + botID + ">", "<@" + botID + ">"} {
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return trimmed
}

// MessageCreate handles incoming Discord messages.
func (b *Bot) MessageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	b.logDebug("received message", "author_id", m.Author.ID, "channel_id", m.ChannelID, "guild_id", m.GuildID, "message_id", m.ID)

	if isBotMentionPrefix(m.Content, s.State.User.ID) {
		b.logDebug("bot mentioned", "channel_id", m.ChannelID, "guild_id", m.GuildID)

		if !b.isAdminOrOwner(s, m.GuildID, m.Author.ID) && !b.checkUserPermission(s, m.GuildID, m.Author.ID) {
			b.logPermissionErrorOnce(m.ChannelID, m.GuildID, m.Author.ID)
			b.sendChannelMessage(s, m.ChannelID, "You don't have the necessary permissions to use this bot. You must be either the server owner, an administrator, or a user with special permissions assigned by an admin. If you are the server owner or an administrator, ensure the bot has the Server Members intent and required permissions in the Discord Developer Portal and server settings.")
			return
		}

		rest := stripBotMentionPrefix(m.Content, s.State.User.ID)
		args := strings.Fields(rest)
		if len(args) < 1 {
			b.sendChannelMessage(s, m.ChannelID, "No command. Type @bot help for available commands.")
			return
		}

		command := strings.ToLower(args[0])
		channelID := m.ChannelID

		// Permission management commands require admin/owner; CanPurge users cannot run these.
		permMgmtCommands := map[string]bool{
			"adduser": true, "removeuser": true, "addrole": true, "removerole": true,
			"adduserid": true, "removeuserid": true, "addroleid": true, "removeroleid": true,
			"listpermissions": true,
		}
		if permMgmtCommands[command] && !b.isAdminOrOwner(s, m.GuildID, m.Author.ID) {
			b.sendChannelMessage(s, m.ChannelID, "Only server owners and administrators can manage permissions.")
			return
		}

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
Username matches the first user found in the member list; for accuracy prefer adduserid/removeuserid with a user ID.

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
			b.sendChannelMessage(s, m.ChannelID, helpMessage)

		case "messages":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a duration (e.g., '3d') or 'stop'. Usage: @bot messages 3d or @bot messages stop")
				return
			}
			if args[1] == "stop" {
				b.stopAndDeleteTask(channelID)
				b.sendChannelMessage(s, m.ChannelID, "Message purging stopped for this channel.")
			} else {
				duration, err := ParseDuration(args[1])
				if err != nil {
					b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Invalid duration: %v. Type @bot help for available commands.", err))
					return
				}
				effective := b.setPurgeTaskLoop(s, channelID, duration)
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Messages older than %s will be deleted on a rolling basis in this channel.", FormatDuration(effective)))
			}

		case "threads":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a duration (e.g., '6d') or 'stop'. Usage: @bot threads 6d or @bot threads stop")
				return
			}
			if args[1] == "stop" {
				b.stopThreadCleanupTask(channelID)
				b.deleteThreadCleanupTaskDB(channelID)
				b.sendChannelMessage(s, m.ChannelID, "Thread cleanup stopped for this channel.")
			} else {
				duration, err := ParseDuration(args[1])
				if err != nil {
					b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Invalid duration: %v. Type @bot help for available commands.", err))
					return
				}
				effective := b.setThreadCleanupTaskLoop(s, channelID, duration)
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Threads older than %s will be deleted on a rolling basis under this channel.", FormatDuration(effective)))
			}

		case "stop":
			b.stopAndDeleteTask(channelID)
			b.stopThreadCleanupTask(channelID)
			b.deleteThreadCleanupTaskDB(channelID)
			b.sendChannelMessage(s, m.ChannelID, "All purge tasks stopped for this channel.")

		case "list":
			b.listPurgeTasks(s, m.GuildID, m.ChannelID)

		case "adduser":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a username.")
				return
			}
			username := strings.Join(args[1:], " ")
			userID, err := b.getUserIDByName(s, m.GuildID, username)
			if err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("User '%s' not found.", username))
				return
			}
			if err := b.addUserPermission(m.GuildID, userID, true); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to add permission: %v", err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("User '%s' can now manage purge tasks.", username))
			}
		case "removeuser":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a username.")
				return
			}
			username := strings.Join(args[1:], " ")
			userID, err := b.getUserIDByName(s, m.GuildID, username)
			if err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("User '%s' not found.", username))
				return
			}
			if err := b.removeUserPermission(m.GuildID, userID); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to remove user '%s' permissions: %v", username, err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("User '%s' can no longer manage purge tasks.", username))
			}
		case "addrole":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a role name.")
				return
			}
			roleName := strings.Join(args[1:], " ")
			roleID, err := b.getRoleIDByName(s, m.GuildID, roleName)
			if err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Role '%s' not found.", roleName))
				return
			}
			if err := b.addRolePermission(m.GuildID, roleID, true); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to add permission: %v", err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Role '%s' can now manage purge tasks.", roleName))
			}
		case "removerole":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a role name.")
				return
			}
			roleName := strings.Join(args[1:], " ")
			roleID, err := b.getRoleIDByName(s, m.GuildID, roleName)
			if err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Role '%s' not found.", roleName))
				return
			}
			if err := b.removeRolePermission(m.GuildID, roleID); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to remove role '%s' permissions: %v", roleName, err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Role '%s' can no longer manage purge tasks.", roleName))
			}
		case "adduserid":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a user ID.")
				return
			}
			userID := args[1]
			if err := b.addUserPermission(m.GuildID, userID, true); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to add permission: %v", err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("User %s can now manage purge tasks.", userID))
			}
			return
		case "removeuserid":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a user ID.")
				return
			}
			userID := args[1]
			if err := b.removeUserPermission(m.GuildID, userID); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to remove user %s's permissions: %v", userID, err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("User %s can no longer manage purge tasks.", userID))
			}
		case "addroleid":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a role ID.")
				return
			}
			roleID := args[1]
			if err := b.addRolePermission(m.GuildID, roleID, true); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to add permission: %v", err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Role %s can now manage purge tasks.", roleID))
			}
			return
		case "removeroleid":
			if len(args) < 2 {
				b.sendChannelMessage(s, m.ChannelID, "Please provide a role ID.")
				return
			}
			roleID := args[1]
			if err := b.removeRolePermission(m.GuildID, roleID); err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to remove role %s's permissions: %v", roleID, err))
			} else {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Role %s can no longer manage purge tasks.", roleID))
			}
		case "listpermissions":
			users, err := b.listUserPermissions(s, m.GuildID)
			if err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to retrieve user permissions: %v", err))
				return
			}

			roles, err := b.listRolePermissions(s, m.GuildID)
			if err != nil {
				b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Failed to retrieve role permissions: %v", err))
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
						fmt.Fprintf(&message, "- %s\n", user)
					}
				}

				if len(roles) > 0 {
					message.WriteString("**Roles:**\n")
					for _, role := range roles {
						fmt.Fprintf(&message, "- %s\n", role)
					}
				}
			}

			b.sendChannelMessage(s, m.ChannelID, message.String())
		default:
			duration, err := ParseDuration(command)
			if err != nil {
				b.sendChannelMessage(s, m.ChannelID, "Invalid duration. Type @bot help for available commands.")
				return
			}
			effective := b.setPurgeTaskLoop(s, channelID, duration)
			b.sendChannelMessage(s, m.ChannelID, fmt.Sprintf("Messages older than %s will be deleted on a rolling basis in this channel.", FormatDuration(effective)))
		}
	}
}

func (b *Bot) isAdminOrOwner(s *discordgo.Session, guildID, userID string) bool {
	// Fetch member directly if state cache is not available
	member, err := s.GuildMember(guildID, userID)
	if err != nil {
		b.logError("fetching member failed", "guild_id", guildID, "user_id", userID, "error", err)
		return false
	}

	// Fetch guild directly if state cache is not available
	guild, err := s.Guild(guildID)
	if err != nil {
		b.logError("fetching guild failed", "guild_id", guildID, "error", err)
		return false
	}

	// Check if the user is the owner
	if guild.OwnerID == userID {
		return true
	}

	// Local cache of guild roles for fallback when State is not populated
	var rolesByID map[string]*discordgo.Role

	// Check if the user has the Administrator permission
	for _, roleID := range member.Roles {
		role, err := s.State.Role(guildID, roleID)
		if err != nil {
			// Fallback: fetch all roles once when State.Role fails (e.g. State not populated)
			if rolesByID == nil {
				guildRoles, fetchErr := s.GuildRoles(guildID)
				if fetchErr != nil {
					b.logError("fetching guild roles failed", "guild_id", guildID, "error", fetchErr)
					return false
				}
				rolesByID = make(map[string]*discordgo.Role, len(guildRoles))
				for _, r := range guildRoles {
					rolesByID[r.ID] = r
				}
			}
			role = rolesByID[roleID]
			if role == nil {
				continue
			}
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
		return 0, fmt.Errorf("error parsing number: %w", err)
	}

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

func (b *Bot) setPurgeTaskLoop(_ *discordgo.Session, channelID string, duration time.Duration) time.Duration {
	if duration < b.minDuration {
		duration = b.minDuration
	} else if duration > b.maxDuration {
		duration = b.maxDuration
	}

	b.logInfo("setting purge task", "channel_id", channelID, "duration", duration)

	b.taskMu.Lock()
	b.stopTaskUnlocked(channelID)
	ticker := time.NewTicker(b.purgeInterval)
	taskCtx, taskCancel := context.WithCancel(b.ctx)
	b.activeTasks[channelID] = ticker
	b.activeTaskCancels[channelID] = taskCancel

	if err := b.updateTaskDB(channelID, int(duration.Seconds())); err != nil {
		b.stopTaskUnlocked(channelID)
		b.taskMu.Unlock()
		b.logError("updating task in database failed", "channel_id", channelID, "error", err)
		return duration
	}
	b.taskMu.Unlock()

	go func() {
		for {
			select {
			case <-taskCtx.Done():
				return
			case <-ticker.C:
				b.purgeChannel(taskCtx, channelID, duration)
			}
		}
	}()

	return duration
}

// stopTaskUnlocked stops the purge task for channelID. Caller must hold taskMu.
func (b *Bot) stopTaskUnlocked(channelID string) {
	if cancel, ok := b.activeTaskCancels[channelID]; ok {
		cancel()
		delete(b.activeTaskCancels, channelID)
	}
	if ticker, ok := b.activeTasks[channelID]; ok {
		ticker.Stop()
		delete(b.activeTasks, channelID)
	}
}

func (b *Bot) stopTask(channelID string) {
	b.taskMu.Lock()
	b.stopTaskUnlocked(channelID)
	b.taskMu.Unlock()
}

func (b *Bot) stopAndDeleteTask(channelID string) {
	b.stopTask(channelID)
	b.deleteTaskDB(channelID)
}

func (b *Bot) purgeChannel(ctx context.Context, channelID string, duration time.Duration) {
	var lastMessageID string
	threshold := time.Now().Add(-duration)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		messages, err := b.messageAPI.ChannelMessages(channelID, 100, lastMessageID, "", "")
		if err != nil {
			b.logError("fetching messages failed", "channel_id", channelID, "error", err)
			return
		}

		if len(messages) == 0 {
			break
		}

		for _, msg := range messages {

			if msg.Timestamp.Before(threshold) {
				err = b.messageAPI.ChannelMessageDelete(channelID, msg.ID)
				if err != nil {
					b.logError("deleting message failed", "channel_id", channelID, "message_id", msg.ID, "error", err)
				} else {
					b.logDebug("deleted message", "channel_id", channelID, "message_id", msg.ID)
				}
			}
		}

		lastMessageID = messages[len(messages)-1].ID
	}
}

func (b *Bot) updateTaskDB(channelID string, durationSeconds int) error {
	task := Task{ChannelID: channelID, PurgeDurationSeconds: durationSeconds}
	return b.db.Save(&task).Error
}

func (b *Bot) deleteTaskDB(channelID string) {
	if err := b.db.Delete(&Task{}, "channel_id = ?", channelID).Error; err != nil {
		b.logError("deleting task from database failed", "channel_id", channelID, "error", err)
	}
}

func (b *Bot) setThreadCleanupTaskLoop(s *discordgo.Session, parentChannelID string, duration time.Duration) time.Duration {
	if duration < b.minDuration {
		duration = b.minDuration
	} else if duration > b.maxDuration {
		duration = b.maxDuration
	}

	b.logInfo("setting thread cleanup task", "parent_channel_id", parentChannelID, "duration", duration)

	b.taskMu.Lock()
	b.stopThreadCleanupTaskUnlocked(parentChannelID)
	ticker := time.NewTicker(b.purgeInterval)
	taskCtx, taskCancel := context.WithCancel(b.ctx)
	b.activeThreadTasks[parentChannelID] = ticker
	b.activeThreadTaskCancels[parentChannelID] = taskCancel

	if err := b.updateThreadCleanupTaskDB(parentChannelID, int(duration.Seconds())); err != nil {
		b.stopThreadCleanupTaskUnlocked(parentChannelID)
		b.taskMu.Unlock()
		b.logError("updating thread cleanup task in database failed", "parent_channel_id", parentChannelID, "error", err)
		return duration
	}
	b.taskMu.Unlock()

	go func() {
		for {
			select {
			case <-taskCtx.Done():
				return
			case <-ticker.C:
				b.runThreadCleanup(taskCtx, s, parentChannelID, duration)
			}
		}
	}()

	return duration
}

// stopThreadCleanupTaskUnlocked stops the thread cleanup task for parentChannelID. Caller must hold taskMu.
func (b *Bot) stopThreadCleanupTaskUnlocked(parentChannelID string) {
	if cancel, ok := b.activeThreadTaskCancels[parentChannelID]; ok {
		cancel()
		delete(b.activeThreadTaskCancels, parentChannelID)
	}
	if ticker, ok := b.activeThreadTasks[parentChannelID]; ok {
		ticker.Stop()
		delete(b.activeThreadTasks, parentChannelID)
	}
}

func (b *Bot) stopThreadCleanupTask(parentChannelID string) {
	b.taskMu.Lock()
	b.stopThreadCleanupTaskUnlocked(parentChannelID)
	b.taskMu.Unlock()
}

func (b *Bot) runThreadCleanup(ctx context.Context, s *discordgo.Session, parentChannelID string, duration time.Duration) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	threshold := time.Now().Add(-duration)

	// Get parent channel to find guild ID
	channel, err := s.Channel(parentChannelID)
	if err != nil {
		b.logError("fetching parent channel failed", "parent_channel_id", parentChannelID, "error", err)
		return
	}

	// Collect active and archived threads, merged and deduplicated by thread ID
	threadsByID := make(map[string]*discordgo.Channel)

	// List active threads for the channel (discordgo: ThreadsActive / GuildThreadsActive)
	threadsList, err := s.ThreadsActive(parentChannelID)
	if err != nil {
		// Fallback: try to get threads from guild
		guildThreads, err := s.GuildThreadsActive(channel.GuildID)
		if err != nil {
			b.logError("listing active threads failed", "parent_channel_id", parentChannelID, "guild_id", channel.GuildID, "error", err)
			return
		}
		for _, thread := range guildThreads.Threads {
			if thread.ParentID == parentChannelID {
				threadsByID[thread.ID] = thread
			}
		}
	} else {
		for _, thread := range threadsList.Threads {
			threadsByID[thread.ID] = thread
		}
	}

	// List archived public threads for the channel (discordgo: ThreadsArchived)
	var before *time.Time
	for {
		archivedList, err := s.ThreadsArchived(parentChannelID, before, 100)
		if err != nil {
			b.logDebug("listing archived threads failed (archived threads may not be supported for this channel)", "parent_channel_id", parentChannelID, "error", err)
			break
		}
		if archivedList == nil || len(archivedList.Threads) == 0 {
			break
		}
		for _, thread := range archivedList.Threads {
			threadsByID[thread.ID] = thread
		}
		// Use last thread's archive timestamp for pagination (next page = threads archived before this)
		if last := archivedList.Threads[len(archivedList.Threads)-1]; last.ThreadMetadata != nil {
			before = &last.ThreadMetadata.ArchiveTimestamp
		} else {
			break
		}
		if len(archivedList.Threads) < 100 {
			break
		}
	}

	// List archived private threads for the channel (discordgo: ThreadsPrivateArchived)
	before = nil
	for {
		archivedList, err := s.ThreadsPrivateArchived(parentChannelID, before, 100)
		if err != nil {
			b.logDebug("listing private archived threads failed", "parent_channel_id", parentChannelID, "error", err)
			break
		}
		if archivedList == nil || len(archivedList.Threads) == 0 {
			break
		}
		for _, thread := range archivedList.Threads {
			threadsByID[thread.ID] = thread
		}
		if last := archivedList.Threads[len(archivedList.Threads)-1]; last.ThreadMetadata != nil {
			before = &last.ThreadMetadata.ArchiveTimestamp
		} else {
			break
		}
		if len(archivedList.Threads) < 100 {
			break
		}
	}

	threads := make([]*discordgo.Channel, 0, len(threadsByID))
	for _, thread := range threadsByID {
		threads = append(threads, thread)
	}

	if len(threads) == 0 {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}
	// Thread age is based on creation time (snowflake id). Archived threads are included.
	var deleted int
	var deletedAges []time.Duration
	for _, thread := range threads {
		select {
		case <-ctx.Done():
			return
		default:
		}
		creationTime, err := discordgo.SnowflakeTimestamp(thread.ID)
		if err != nil {
			b.logWarn("could not parse thread ID", "thread_id", thread.ID, "parent_channel_id", parentChannelID, "error", err)
			continue
		}

		if creationTime.Before(threshold) {
			age := time.Since(creationTime)
			_, err = s.ChannelDelete(thread.ID)
			if err != nil {
				b.logError("deleting thread failed", "thread_id", thread.ID, "parent_channel_id", parentChannelID, "guild_id", channel.GuildID, "error", err)
			} else {
				deleted++
				deletedAges = append(deletedAges, age)
				b.logDebug("deleted thread", "thread_id", thread.ID, "parent_channel_id", parentChannelID, "age", age)
			}
		}
	}
	if deleted > 0 {
		b.logInfo("thread cleanup: deleted threads", "parent_channel_id", parentChannelID, "guild_id", channel.GuildID, "count", deleted, "ages", deletedAges)
	}
}

func (b *Bot) updateThreadCleanupTaskDB(parentChannelID string, durationSeconds int) error {
	task := ThreadCleanupTask{ParentChannelID: parentChannelID, PurgeDurationSeconds: durationSeconds}
	return b.db.Save(&task).Error
}

func (b *Bot) deleteThreadCleanupTaskDB(parentChannelID string) {
	if err := b.db.Delete(&ThreadCleanupTask{}, "parent_channel_id = ?", parentChannelID).Error; err != nil {
		b.logError("deleting thread cleanup task from database failed", "parent_channel_id", parentChannelID, "error", err)
	}
}

func (b *Bot) listPurgeTasks(s *discordgo.Session, guildID, channelID string) {
	var tasks []Task
	if err := b.db.Find(&tasks).Error; err != nil {
		b.logError("querying tasks failed", "guild_id", guildID, "channel_id", channelID, "error", err)
		b.sendChannelMessage(s, channelID, "Error retrieving tasks.")
		return
	}

	var threadTasks []ThreadCleanupTask
	if err := b.db.Find(&threadTasks).Error; err != nil {
		b.logError("querying thread cleanup tasks failed", "guild_id", guildID, "channel_id", channelID, "error", err)
		b.sendChannelMessage(s, channelID, "Error retrieving thread cleanup tasks.")
		return
	}

	// Build a map of channel ID to task info
	channelTasks := make(map[string]struct {
		messageDuration string
		threadDuration  string
	})

	// Process message purge tasks
	// Tasks from deleted or inaccessible channels are skipped; API errors are logged and the task is omitted from the list.
	for _, task := range tasks {
		ch, err := s.State.Channel(task.ChannelID)
		if err != nil {
			// Try fetching directly if not in state
			ch, err = s.Channel(task.ChannelID)
			if err != nil {
				b.logError("fetching channel failed in list", "channel_id", task.ChannelID, "guild_id", guildID, "error", err)
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
				b.logError("fetching parent channel failed in list", "parent_channel_id", task.ParentChannelID, "guild_id", guildID, "error", err)
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
		b.sendChannelMessage(s, channelID, "No purge tasks found for this guild.")
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
			fmt.Fprintf(&sb, "<#%s>: %s\n", chID, strings.Join(parts, ", "))
		}
	}

	b.sendChannelMessage(s, channelID, sb.String())
}

// Usernames are not unique; returns the first match. Prefer user ID or mention when possible.
// getUserIDByName looks up a user ID by username. Paginates through all guild members for large guilds.
func (b *Bot) getUserIDByName(s *discordgo.Session, guildID, username string) (string, error) {
	const limit = 1000
	after := ""
	for {
		members, err := s.GuildMembers(guildID, after, limit)
		if err != nil {
			return "", err
		}
		for _, member := range members {
			if member.User.Username == username {
				return member.User.ID, nil
			}
		}
		if len(members) < limit {
			break
		}
		after = members[len(members)-1].User.ID
	}
	return "", fmt.Errorf("user not found, try user ID instead")
}

func (b *Bot) addUserPermission(guildID, userID string, canPurge bool) error {
	permission := UserPermission{
		UserID:   userID,
		GuildID:  guildID,
		CanPurge: canPurge,
	}
	if err := b.db.Save(&permission).Error; err != nil {
		return fmt.Errorf("failed to add user permission: %w", err)
	}
	return nil
}

func (b *Bot) removeUserPermission(guildID, userID string) error {
	if err := b.db.Where("guild_id = ? AND user_id = ?", guildID, userID).Delete(&UserPermission{}).Error; err != nil {
		return fmt.Errorf("failed to remove user permission: %w", err)
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

func (b *Bot) addRolePermission(guildID, roleID string, canPurge bool) error {
	permission := RolePermission{
		RoleID:   roleID,
		GuildID:  guildID,
		CanPurge: canPurge,
	}
	if err := b.db.Save(&permission).Error; err != nil {
		return fmt.Errorf("failed to add role permission: %w", err)
	}
	return nil
}

func (b *Bot) removeRolePermission(guildID, roleID string) error {
	if err := b.db.Where("guild_id = ? AND role_id = ?", guildID, roleID).Delete(&RolePermission{}).Error; err != nil {
		return fmt.Errorf("failed to remove role permission: %w", err)
	}
	return nil
}

func (b *Bot) checkUserPermission(s *discordgo.Session, guildID, userIDOrName string) bool {
	// First, assume the input is a user ID and try to check by ID
	var permission UserPermission
	if queryErr := b.db.Where("guild_id = ? AND user_id = ?", guildID, userIDOrName).First(&permission).Error; queryErr == nil {
		return permission.CanPurge
	} else if !errors.Is(queryErr, gorm.ErrRecordNotFound) {
		b.logWarn("permission check: user query failed", "guild_id", guildID, "user_id_or_name", userIDOrName, "error", queryErr)
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
		if queryErr := b.db.Where("guild_id = ? AND user_id = ?", guildID, userID).First(&permission).Error; queryErr == nil {
			return permission.CanPurge
		} else if queryErr != nil && !errors.Is(queryErr, gorm.ErrRecordNotFound) {
			b.logWarn("permission check: user query failed", "guild_id", guildID, "user_id", userID, "error", queryErr)
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
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			b.logWarn("permission check: role query failed", "guild_id", guildID, "role_id", roleID, "error", err)
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
