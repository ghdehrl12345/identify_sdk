package log

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestConsoleLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := &ConsoleLogger{
		level:  LevelDebug,
		writer: &buf,
	}

	logger.Info("test message", String("key", "value"), Int("count", 42))

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("expected [INFO] in output, got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("expected 'test message' in output, got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("expected 'key=value' in output, got: %s", output)
	}
}

func TestLogLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := &ConsoleLogger{
		level:  LevelWarn,
		writer: &buf,
	}

	logger.Debug("should not appear")
	logger.Info("should not appear")
	logger.Warn("should appear")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Error("debug/info should be filtered out")
	}
	if !strings.Contains(output, "should appear") {
		t.Error("warn should appear")
	}
}

func TestMeasureFunc(t *testing.T) {
	elapsed := MeasureFunc("test", func() {
		time.Sleep(10 * time.Millisecond)
	})

	if elapsed < 10*time.Millisecond {
		t.Errorf("expected at least 10ms, got %v", elapsed)
	}
}
