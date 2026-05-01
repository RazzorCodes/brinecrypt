package logger

import (
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	once     sync.Once
	instance *zap.Logger
)

type core struct {
	file *os.File
}

func (c *core) Enabled(l zapcore.Level) bool             { return true }
func (c *core) With(fields []zapcore.Field) zapcore.Core { return c }
func (c *core) Sync() error                              { return c.file.Sync() }

func (c *core) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *core) Write(e zapcore.Entry, _ []zapcore.Field) error {
	caller := e.Caller.TrimmedPath()
	if caller == "" {
		caller = "unknown"
	}
	_, err := fmt.Fprintf(c.file, "[%s][%s][%s] %s\n",
		e.Time.Format("2006-01-02 15:04:05"),
		e.Level.CapitalString(),
		caller,
		e.Message,
	)
	return err
}

func get() *zap.Logger {
	once.Do(func() {
		instance = zap.New(&core{file: os.Stderr}, zap.AddCaller())
	})
	return instance
}

func Error(msg string) {
	get().WithOptions(zap.AddCallerSkip(1)).Error(msg)
}

func Warn(msg string) {
	get().WithOptions(zap.AddCallerSkip(1)).Warn(msg)
}

func Info(msg string) {
	get().WithOptions(zap.AddCallerSkip(1)).Info(msg)
}
