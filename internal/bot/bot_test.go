package bot

import (
	"errors"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// mockMessageFetcherDeleter is a mock implementation of MessageFetcherDeleter for testing.
type mockMessageFetcherDeleter struct {
	messages      []*discordgo.Message
	deleteCalls   []string
	fetchError    error
	deleteError   error
	shouldLoop    bool
	loopCount     int
	maxLoopCount  int
}

func (m *mockMessageFetcherDeleter) ChannelMessages(channelID string, limit int, beforeID, afterID, aroundID string) ([]*discordgo.Message, error) {
	if m.fetchError != nil {
		return nil, m.fetchError
	}
	if m.shouldLoop && m.loopCount < m.maxLoopCount {
		m.loopCount++
		return m.messages, nil
	}
	return m.messages, nil
}

func (m *mockMessageFetcherDeleter) ChannelMessageDelete(channelID, msgID string) error {
	m.deleteCalls = append(m.deleteCalls, msgID)
	if m.deleteError != nil {
		return m.deleteError
	}
	return nil
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      time.Duration
		wantError bool
	}{
		{
			name:      "30 seconds",
			input:     "30s",
			want:      30 * time.Second,
			wantError: false,
		},
		{
			name:      "5 minutes",
			input:     "5m",
			want:      5 * time.Minute,
			wantError: false,
		},
		{
			name:      "24 hours",
			input:     "24h",
			want:      24 * time.Hour,
			wantError: false,
		},
		{
			name:      "2 days",
			input:     "2d",
			want:      2 * 24 * time.Hour,
			wantError: false,
		},
		{
			name:      "1 day",
			input:     "1d",
			want:      24 * time.Hour,
			wantError: false,
		},
		{
			name:      "invalid format - no unit",
			input:     "30",
			want:      0,
			wantError: true,
		},
		{
			name:      "invalid format - no number",
			input:     "s",
			want:      0,
			wantError: true,
		},
		{
			name:      "invalid format - wrong unit",
			input:     "30x",
			want:      0,
			wantError: true,
		},
		{
			name:      "invalid format - empty string",
			input:     "",
			want:      0,
			wantError: true,
		},
		{
			name:      "large number",
			input:     "1000s",
			want:      1000 * time.Second,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseDuration() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if got != tt.want {
				t.Errorf("ParseDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{
			name:     "1 second",
			duration: 1 * time.Second,
			want:     "1 second",
		},
		{
			name:     "2 seconds",
			duration: 2 * time.Second,
			want:     "2 seconds",
		},
		{
			name:     "1 minute",
			duration: 1 * time.Minute,
			want:     "1 minute",
		},
		{
			name:     "5 minutes",
			duration: 5 * time.Minute,
			want:     "5 minutes",
		},
		{
			name:     "1 hour",
			duration: 1 * time.Hour,
			want:     "1 hour",
		},
		{
			name:     "24 hours",
			duration: 24 * time.Hour,
			want:     "1 day",
		},
		{
			name:     "2 days",
			duration: 2 * 24 * time.Hour,
			want:     "2 days",
		},
		{
			name:     "30 seconds",
			duration: 30 * time.Second,
			want:     "30 seconds",
		},
		{
			name:     "90 seconds",
			duration: 90 * time.Second,
			want:     "90 seconds",
		},
		{
			name:     "90 minutes",
			duration: 90 * time.Minute,
			want:     "90 minutes",
		},
		{
			name:     "25 hours",
			duration: 25 * time.Hour,
			want:     "25 hours",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDuration(tt.duration)
			if got != tt.want {
				t.Errorf("FormatDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPurgeChannel(t *testing.T) {
	// Setup in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Skipf("Skipping: database requires CGO/sqlite: %v", err)
	}

	// Create mock that returns messages older than threshold
	oldTime := time.Now().Add(-2 * time.Hour)
	newTime := time.Now().Add(-10 * time.Minute)

	mockAPI := &mockMessageFetcherDeleter{
		messages: []*discordgo.Message{
			{
				ID:        "msg1",
				Timestamp: oldTime,
			},
			{
				ID:        "msg2",
				Timestamp: oldTime,
			},
			{
				ID:        "msg3",
				Timestamp: newTime, // This should not be deleted
			},
		},
		shouldLoop:   false,
		maxLoopCount: 1,
	}

	bot := NewBot(db, mockAPI)
	bot.purgeChannel("test-channel", 1*time.Hour)

	// Verify that old messages were deleted
	if len(mockAPI.deleteCalls) != 2 {
		t.Errorf("Expected 2 delete calls, got %d", len(mockAPI.deleteCalls))
	}

	// Verify correct messages were deleted
	expectedDeletes := map[string]bool{
		"msg1": true,
		"msg2": true,
	}
	for _, msgID := range mockAPI.deleteCalls {
		if !expectedDeletes[msgID] {
			t.Errorf("Unexpected message deleted: %s", msgID)
		}
	}
}

func TestPurgeChannelWithFetchError(t *testing.T) {
	// Setup in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Skipf("Skipping: database requires CGO/sqlite: %v", err)
	}

	mockAPI := &mockMessageFetcherDeleter{
		fetchError: errors.New("fetch error"),
	}

	bot := NewBot(db, mockAPI)
	bot.purgeChannel("test-channel", 1*time.Hour)

	// Should not delete anything if fetch fails
	if len(mockAPI.deleteCalls) != 0 {
		t.Errorf("Expected 0 delete calls on fetch error, got %d", len(mockAPI.deleteCalls))
	}
}

func TestPurgeChannelWithDeleteError(t *testing.T) {
	// Setup in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Skipf("Skipping: database requires CGO/sqlite: %v", err)
	}

	oldTime := time.Now().Add(-2 * time.Hour)
	mockAPI := &mockMessageFetcherDeleter{
		messages: []*discordgo.Message{
			{
				ID:        "msg1",
				Timestamp: oldTime,
			},
		},
		deleteError: errors.New("delete error"),
		shouldLoop:  false,
	}

	bot := NewBot(db, mockAPI)
	bot.purgeChannel("test-channel", 1*time.Hour)

	// Should still attempt to delete (error is logged but doesn't stop processing)
	if len(mockAPI.deleteCalls) != 1 {
		t.Errorf("Expected 1 delete call even with error, got %d", len(mockAPI.deleteCalls))
	}
}
