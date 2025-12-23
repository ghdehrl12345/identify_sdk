package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event represents an audit log entry.
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	EventType  string            `json:"event_type"`
	UserID     string            `json:"user_id,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	Success    bool              `json:"success"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Logger defines the interface for audit logging.
type Logger interface {
	// LogAuthAttempt logs an authentication attempt.
	LogAuthAttempt(userID string, success bool, metadata map[string]string)
	// LogDecryption logs a decryption event.
	LogDecryption(userID string, resourceID string)
	// LogEvent logs a generic audit event.
	LogEvent(event Event)
}

// JSONLogger writes audit events as JSON lines.
type JSONLogger struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewJSONLogger creates a new JSON audit logger.
func NewJSONLogger(w io.Writer) *JSONLogger {
	return &JSONLogger{writer: w}
}

// NewJSONLoggerToFile creates a JSON logger that writes to a file.
func NewJSONLoggerToFile(path string) (*JSONLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return NewJSONLogger(f), nil
}

// LogAuthAttempt logs an authentication attempt.
func (l *JSONLogger) LogAuthAttempt(userID string, success bool, metadata map[string]string) {
	l.LogEvent(Event{
		Timestamp: time.Now().UTC(),
		EventType: "auth_attempt",
		UserID:    userID,
		Success:   success,
		Metadata:  metadata,
	})
}

// LogDecryption logs a decryption event.
func (l *JSONLogger) LogDecryption(userID string, resourceID string) {
	l.LogEvent(Event{
		Timestamp:  time.Now().UTC(),
		EventType:  "decryption",
		UserID:     userID,
		ResourceID: resourceID,
		Success:    true,
	})
}

// LogEvent logs a generic audit event.
func (l *JSONLogger) LogEvent(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	l.writer.Write(append(data, '\n'))
}

// NoOpLogger is a logger that does nothing (for testing/disabled logging).
type NoOpLogger struct{}

// NewNoOpLogger creates a no-op logger.
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

// LogAuthAttempt does nothing.
func (l *NoOpLogger) LogAuthAttempt(userID string, success bool, metadata map[string]string) {}

// LogDecryption does nothing.
func (l *NoOpLogger) LogDecryption(userID string, resourceID string) {}

// LogEvent does nothing.
func (l *NoOpLogger) LogEvent(event Event) {}
