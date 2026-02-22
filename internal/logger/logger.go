package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "?"
	}
}

// Logger provides leveled, optionally structured logging.
type Logger interface {
	Debug(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
	Warn(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
}

// Config configures the logger.
type Config struct {
	Level  Level
	Format string // "text" or "json"
	Output io.Writer
}

type loggerImpl struct {
	cfg   Config
	mu    sync.Mutex
	now   func() time.Time
	write func(level Level, msg string, keyvals []interface{})
}

// New creates a Logger from config. Output defaults to os.Stderr if nil.
func New(cfg Config) Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stderr
	}
	if cfg.Format != "json" {
		cfg.Format = "text"
	}
	impl := &loggerImpl{cfg: cfg, now: time.Now}
	if cfg.Format == "json" {
		impl.write = impl.writeJSON
	} else {
		impl.write = impl.writeText
	}
	return impl
}

func (l *loggerImpl) Debug(msg string, keyvals ...interface{}) {
	if l.cfg.Level > LevelDebug {
		return
	}
	l.log(LevelDebug, msg, keyvals)
}

func (l *loggerImpl) Info(msg string, keyvals ...interface{}) {
	if l.cfg.Level > LevelInfo {
		return
	}
	l.log(LevelInfo, msg, keyvals)
}

func (l *loggerImpl) Warn(msg string, keyvals ...interface{}) {
	if l.cfg.Level > LevelWarn {
		return
	}
	l.log(LevelWarn, msg, keyvals)
}

func (l *loggerImpl) Error(msg string, keyvals ...interface{}) {
	if l.cfg.Level > LevelError {
		return
	}
	l.log(LevelError, msg, keyvals)
}

func (l *loggerImpl) log(level Level, msg string, keyvals []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.write(level, msg, keyvals)
}

func (l *loggerImpl) writeText(level Level, msg string, keyvals []interface{}) {
	buf := fmt.Sprintf("%s %s %s", l.now().Format(time.RFC3339), level.String(), msg)
	for i := 0; i+1 < len(keyvals); i += 2 {
		buf += fmt.Sprintf(" %v=%v", keyvals[i], keyvals[i+1])
	}
	buf += "\n"
	_, _ = l.cfg.Output.Write([]byte(buf))
}

func (l *loggerImpl) writeJSON(level Level, msg string, keyvals []interface{}) {
	m := map[string]interface{}{
		"time":  l.now().Format(time.RFC3339),
		"level": level.String(),
		"msg":   msg,
	}
	for i := 0; i+1 < len(keyvals); i += 2 {
		if k, ok := keyvals[i].(string); ok {
			m[k] = keyvals[i+1]
		}
	}
	enc := json.NewEncoder(l.cfg.Output)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m)
}

// ParseLevel returns Level from string (debug, info, warn, error). Defaults to info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info", "":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// StdLogger returns a standard log.Logger that writes at the given level (for compatibility).
func StdLogger(l Logger, level Level) *log.Logger {
	return log.New(&stdAdapter{l: l, level: level}, "", 0)
}

type stdAdapter struct {
	l     Logger
	level Level
}

func (a *stdAdapter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	switch a.level {
	case LevelDebug:
		a.l.Debug(msg)
	case LevelInfo:
		a.l.Info(msg)
	case LevelWarn:
		a.l.Warn(msg)
	case LevelError:
		a.l.Error(msg)
	default:
		a.l.Info(msg)
	}
	return len(p), nil
}
