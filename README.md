# 🗑️ PurgeBot 🗑️

Welcome to **PurgeBot**! This bot helps manage and clean up your Discord server by automatically purging old messages from channels based on your specified duration. Whether you need to clear out outdated messages or keep your channels tidy, PurgeBot has you covered.

## 🚀 Features

- **Purge Old Messages**: Automatically delete messages older than a specified duration.
- **Stop Purging**: Easily stop the purging task for a channel.
- **List Purge Tasks**: Get a list of all active purge tasks in your guild.
- **Add or Remove Users/Roles**: Grant or revoke permission for specific users or roles to manage purge tasks.

## 🛠️ Setup

### 1. Prerequisites

- **Go**: Ensure you have Go installed on your system.
- **Discord Bot Token**: Create a bot on [Discord Developer Portal](https://discord.com/developers/applications) and get your token.
- **SQLite**: The bot uses SQLite for database storage.

### 2. Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/keshon/purge-bot.git
    cd purge-bot
    ```

2. **Install dependencies:**

    ```bash
    go mod tidy
    ```

3. **Set up your environment:**

    Provide your Discord bot token in one of these ways:

    - **Option A:** Set the `DISCORD_KEY` environment variable (no .env file required):
      ```bash
      export DISCORD_KEY=your-discord-bot-token   # Linux/macOS
      set DISCORD_KEY=your-discord-bot-token      # Windows cmd
      $env:DISCORD_KEY="your-discord-bot-token"   # PowerShell
      ```
    - **Option B:** Create a `.env` file in the root directory (or use `-env path`):
      ```env
      DISCORD_KEY=your-discord-bot-token
      ```
      If no `-env` flag is given, the bot will try to load `.env` from the current working directory; if the file is missing, it will use environment variables instead.

4. **Run the bot:**

    ```bash
    go run main.go
    ```

    **Command-line options:**
    
    - `-env` (or `-env-file`): Path to `.env` file. If omitted or empty, the bot tries to load `.env` from the current working directory; if that file is missing, it uses existing environment variables (e.g. `DISCORD_KEY`). No .env file is required if `DISCORD_KEY` is already set in the environment.
      ```bash
      go run main.go -env /path/to/.env
      ```
    
    - `-db`: Path to database file. Defaults to `database.db`. This overrides the `DB_PATH` environment variable if set.
      ```bash
      go run main.go -db /var/data/purge.db
      ```
    
    - `-log-level`: Log level: `debug`, `info`, `warn`, `error`. Default: `info`. At `debug`, incoming messages and per-message deletions are logged; at `info` and above only task changes, errors, and thread cleanup summaries are logged.
    
    - `-log-format`: Log format: `text` or `json`. Default: `text`. Use `json` for structured logs (e.g. for log aggregation).
    
    - `-log-file`: Optional path to a log file. When set, logs are written to this file with size-based rotation (100 MB max, 3 backups, 28-day retention, compressed). If omitted, logs go to stderr.
    
    **Examples:**
    
    ```bash
    # Use custom .env file location
    go run main.go -env /etc/purgebot/.env
    
    # Use custom database path
    go run main.go -db /var/lib/purgebot/purge.db
    
    # Use both custom .env and database paths
    go run main.go -env /etc/purgebot/.env -db /var/lib/purgebot/purge.db
    ```

## 🧪 Testing

Run tests the same way as CI (so you catch the same failures locally):

- **Unix / macOS / Git Bash:**  
  `./test.sh`  
  (Make it executable once: `chmod +x test.sh`)

- **Windows (cmd):**  
  `test.bat`

- **Or run the CI command directly:**  
  `CGO_ENABLED=1 go test -v ./... -count=1`

**Requirements for full tests:** A C compiler (e.g. `gcc`) is required so the SQLite driver can build and the database-backed tests run. If you don't have one, use `CGO_ENABLED=0 go test ./... -count=1`; the same tests that run in CI will be skipped locally.

**Lint (optional):**  
`golangci-lint run ./...`

## 📜 Commands

### Purge Old Messages

Automatically purge old messages in the channel. You can use a bare duration or the `messages` subcommand.

- **Usage:** `@PurgeBot <duration>` or `@PurgeBot messages <duration>`
- **Example:** `@PurgeBot 3d` or `@PurgeBot messages 3d` (purges messages older than 3 days)
- **Stop messages only:** `@PurgeBot messages stop`

### Delete Old Threads

Delete threads under this channel that are older than the given duration (the thread itself is deleted, not its messages). Uses a separate duration from message purge (e.g. messages 3d, threads 6d).

- **Usage:** `@PurgeBot threads <duration>`
- **Example:** `@PurgeBot threads 6d` (deletes threads under this channel older than 6 days)
- **Stop threads only:** `@PurgeBot threads stop`

### Stop All Tasks

Stop both message purge and thread cleanup for this channel.

- **Usage:** `@PurgeBot stop`

### List Purge Tasks

Get a list of all channels with active purge tasks in the guild.

- **Usage:** `@PurgeBot list`

### Add User

Grant a user permission to manage purge tasks. You can use either username or user ID.

- **Usage:** `@PurgeBot adduser <username>` or `@PurgeBot adduserid <userID>`
- **Example:** `@PurgeBot adduser JohnDoe` or `@PurgeBot adduserid 339767128292982785`

### Remove User

Revoke a user's permission to manage purge tasks. You can use either username or user ID.

- **Usage:** `@PurgeBot removeuser <username>` or `@PurgeBot removeuserid <userID>`
- **Example:** `@PurgeBot removeuser JohnDoe` or `@PurgeBot removeuserid 339767128292982785`

### Add Role

Grant a role permission to manage purge tasks. You can use either role name or role ID.

- **Usage:** `@PurgeBot addrole <roleName>` or `@PurgeBot addroleid <roleID>`
- **Example:** `@PurgeBot addrole Admin` or `@PurgeBot addroleid 1274017921756172403`

### Remove Role

Revoke a role's permission to manage purge tasks. You can use either role name or role ID.

- **Usage:** `@PurgeBot removerole <roleName>` or `@PurgeBot removeroleid <roleID>`
- **Example:** `@PurgeBot removerole Admin` or `@PurgeBot removeroleid 1274017921756172403`

### List Permissions

Get a list of all users and roles registered to manage purge tasks, including their names.

- **Usage:** `@PurgeBot listpermissions`

### Help

Get detailed usage instructions and a list of available commands.

- **Usage:** `@PurgeBot help`

## ⚙️ Configuration

- **Purge Interval**: The interval at which the bot checks for messages to purge (default: 33 seconds).
- **Minimum Duration**: The minimum duration for purging tasks (default: 30 seconds).
- **Maximum Duration**: The maximum duration for purging tasks (default: 3333 days).

## 🗳️ Invite the Bot

To invite **PurgeBot** to your server, use the following invite link format:

`https://discord.com/oauth2/authorize?client_id=YOUR_APPLICATION_ID&scope=bot&permissions=75776`

**Required Permissions:**
- **Read Messages**
- **Send Messages**
- **Manage Messages** (for purging messages)
- **Read Message History**

Replace `YOUR_APPLICATION_ID` in the URL with your bot's actual application ID from the Discord Developer Portal.

## 📝 Example

Here's how you can use PurgeBot in your server:

1. **Start purging messages older than 1 hour:**

    ```markdown
    @PurgeBot 1h
    ```

2. **Stop purging in a channel:**

    ```markdown
    @PurgeBot stop
    ```

3. **Get a list of all purge tasks:**

    ```markdown
    @PurgeBot list
    ```

4. **Add a user to manage purge tasks:**

    ```markdown
    @PurgeBot adduser JohnDoe
    ```

5. **Remove a user from managing purge tasks:**

    ```markdown
    @PurgeBot removeuser JohnDoe
    ```

6. **Add a role to manage purge tasks:**

    ```markdown
    @PurgeBot addrole Admin
    ```

7. **Remove a role from managing purge tasks:**

    ```markdown
    @PurgeBot removerole Admin
    ```

8. **Get a list of all registered users and roles:**

    ```markdown
    @PurgeBot listpermissions
    ```

9. **Get help:**

    ```markdown
    @PurgeBot help
    ```

## 🙏 Acknowledgements

**PurgeBot** was inspired by the original [KMS Bot](https://github.com/internetisgone/kms-bot) project. The original bot, written in Python, provided the foundational concept for this Go implementation. A special thanks to the creator of that project!
