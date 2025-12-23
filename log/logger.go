// Package log provides logging utilities for identify_sdk.
package log

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Level represents log level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelOff
)

// Field represents a log field.
type Field struct {
	Key   string
	Value interface{}
}

// String creates a string field.
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int creates an integer field.
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Duration creates a duration field.
func Duration(key string, value time.Duration) Field {
	return Field{Key: key, Value: value}
}

// Err creates an error field.
func Err(err error) Field {
	return Field{Key: "error", Value: err}
}

// Logger defines the logging interface.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	SetLevel(level Level)
}

// ConsoleLogger logs to console.
type ConsoleLogger struct {
	level  Level
	writer io.Writer
}

// NewConsoleLogger creates a new console logger.
func NewConsoleLogger() *ConsoleLogger {
	return &ConsoleLogger{
		level:  LevelInfo,
		writer: os.Stdout,
	}
}

// SetLevel sets the minimum log level.
func (l *ConsoleLogger) SetLevel(level Level) {
	l.level = level
}

func (l *ConsoleLogger) log(level Level, levelStr, msg string, fields ...Field) {
	if level < l.level {
		return
	}

	timestamp := time.Now().Format("15:04:05.000")
	fmt.Fprintf(l.writer, "%s [%s] %s", timestamp, levelStr, msg)

	for _, f := range fields {
		fmt.Fprintf(l.writer, " %s=%v", f.Key, f.Value)
	}
	fmt.Fprintln(l.writer)
}

func (l *ConsoleLogger) Debug(msg string, fields ...Field) {
	l.log(LevelDebug, "DEBUG", msg, fields...)
}

func (l *ConsoleLogger) Info(msg string, fields ...Field) {
	l.log(LevelInfo, "INFO", msg, fields...)
}

func (l *ConsoleLogger) Warn(msg string, fields ...Field) {
	l.log(LevelWarn, "WARN", msg, fields...)
}

func (l *ConsoleLogger) Error(msg string, fields ...Field) {
	l.log(LevelError, "ERROR", msg, fields...)
}

// NoOpLogger does nothing (default).
type NoOpLogger struct{}

func (l *NoOpLogger) Debug(msg string, fields ...Field) {}
func (l *NoOpLogger) Info(msg string, fields ...Field)  {}
func (l *NoOpLogger) Warn(msg string, fields ...Field)  {}
func (l *NoOpLogger) Error(msg string, fields ...Field) {}
func (l *NoOpLogger) SetLevel(level Level)              {}

// DefaultLogger is the global logger instance.
var DefaultLogger Logger = &NoOpLogger{}

// SetDefaultLogger sets the global logger.
func SetDefaultLogger(l Logger) {
	DefaultLogger = l
}

// EnableDebug enables debug logging to console.
func EnableDebug() {
	logger := NewConsoleLogger()
	logger.SetLevel(LevelDebug)
	DefaultLogger = logger
}

// Debug logs at debug level using default logger.
func Debug(msg string, fields ...Field) {
	DefaultLogger.Debug(msg, fields...)
}

// Info logs at info level using default logger.
func Info(msg string, fields ...Field) {
	DefaultLogger.Info(msg, fields...)
}

// Warn logs at warn level using default logger.
func Warn(msg string, fields ...Field) {
	DefaultLogger.Warn(msg, fields...)
}

// Error logs at error level using default logger.
func Error(msg string, fields ...Field) {
	DefaultLogger.Error(msg, fields...)
}
