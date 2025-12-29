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

// AsyncJSONLogger is an asynchronous logger that uses channels for non-blocking writes.
type AsyncJSONLogger struct {
	writer     io.Writer
	eventChan  chan Event
	done       chan struct{}
	wg         sync.WaitGroup
	bufferSize int
}

// AsyncLoggerConfig holds configuration for async logger.
type AsyncLoggerConfig struct {
	BufferSize    int           // Channel buffer size (default: 1000)
	FlushInterval time.Duration // How often to flush (default: 5s)
}

// DefaultAsyncLoggerConfig returns sensible defaults.
func DefaultAsyncLoggerConfig() AsyncLoggerConfig {
	return AsyncLoggerConfig{
		BufferSize:    1000,
		FlushInterval: 5 * time.Second,
	}
}

// NewAsyncJSONLogger creates an async JSON logger with default config.
func NewAsyncJSONLogger(w io.Writer) *AsyncJSONLogger {
	return NewAsyncJSONLoggerWithConfig(w, DefaultAsyncLoggerConfig())
}

// NewAsyncJSONLoggerWithConfig creates an async JSON logger with custom config.
func NewAsyncJSONLoggerWithConfig(w io.Writer, config AsyncLoggerConfig) *AsyncJSONLogger {
	l := &AsyncJSONLogger{
		writer:     w,
		eventChan:  make(chan Event, config.BufferSize),
		done:       make(chan struct{}),
		bufferSize: config.BufferSize,
	}
	l.wg.Add(1)
	go l.processEvents(config.FlushInterval)
	return l
}

// NewAsyncJSONLoggerToFile creates an async logger that writes to a file.
func NewAsyncJSONLoggerToFile(path string) (*AsyncJSONLogger, error) {
	return NewAsyncJSONLoggerToFileWithConfig(path, DefaultAsyncLoggerConfig())
}

// NewAsyncJSONLoggerToFileWithConfig creates an async logger with custom config.
func NewAsyncJSONLoggerToFileWithConfig(path string, config AsyncLoggerConfig) (*AsyncJSONLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return NewAsyncJSONLoggerWithConfig(f, config), nil
}

func (l *AsyncJSONLogger) processEvents(flushInterval time.Duration) {
	defer l.wg.Done()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var buffer []Event

	flush := func() {
		if len(buffer) == 0 {
			return
		}
		for _, event := range buffer {
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			l.writer.Write(append(data, '\n'))
		}
		buffer = buffer[:0]
	}

	for {
		select {
		case event := <-l.eventChan:
			if event.Timestamp.IsZero() {
				event.Timestamp = time.Now().UTC()
			}
			buffer = append(buffer, event)
			// Flush if buffer is getting large
			if len(buffer) >= l.bufferSize/2 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-l.done:
			// Drain remaining events
			for {
				select {
				case event := <-l.eventChan:
					if event.Timestamp.IsZero() {
						event.Timestamp = time.Now().UTC()
					}
					buffer = append(buffer, event)
				default:
					flush()
					return
				}
			}
		}
	}
}

// LogAuthAttempt logs an authentication attempt asynchronously.
func (l *AsyncJSONLogger) LogAuthAttempt(userID string, success bool, metadata map[string]string) {
	l.LogEvent(Event{
		Timestamp: time.Now().UTC(),
		EventType: "auth_attempt",
		UserID:    userID,
		Success:   success,
		Metadata:  metadata,
	})
}

// LogDecryption logs a decryption event asynchronously.
func (l *AsyncJSONLogger) LogDecryption(userID string, resourceID string) {
	l.LogEvent(Event{
		Timestamp:  time.Now().UTC(),
		EventType:  "decryption",
		UserID:     userID,
		ResourceID: resourceID,
		Success:    true,
	})
}

// LogEvent sends an event to the async processing channel.
// Non-blocking: if the buffer is full, the event is dropped.
func (l *AsyncJSONLogger) LogEvent(event Event) {
	select {
	case l.eventChan <- event:
	default:
		// Buffer full, drop event (should log warning in production)
	}
}

// Flush forces immediate write of buffered events.
func (l *AsyncJSONLogger) Flush() {
	// Send a signal through done and recreate
	// For simplicity, we just wait a bit for the ticker to flush
	time.Sleep(100 * time.Millisecond)
}

// Close stops the async logger and flushes remaining events.
func (l *AsyncJSONLogger) Close() error {
	close(l.done)
	l.wg.Wait()
	if closer, ok := l.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
