package log

import (
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

type Level int32

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

var currentLevel atomic.Int32

func init() {
	currentLevel.Store(int32(LevelDebug))
}

// ParseLevel converts a level name (case-insensitive) to a Level value.
// Returns an error for unrecognized names.
func ParseLevel(name string) (Level, error) {
	switch strings.ToLower(name) {
	case "error":
		return LevelError, nil
	case "warn":
		return LevelWarn, nil
	case "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	case "trace":
		return LevelTrace, nil
	default:
		return LevelDebug, fmt.Errorf("unknown log level %q, valid values: error, warn, info, debug, trace", name)
	}
}

func SetLevel(l Level) {
	currentLevel.Store(int32(l))
}

func GetLevel() Level {
	return Level(currentLevel.Load())
}

func IsTraceEnabled() bool {
	return GetLevel() >= LevelTrace
}

// Errorln always prints — errors are never suppressed by level.
func Errorln(format string, v ...any) {
	log.Printf("[ERROR] "+format+"\n", v...)
}

func Warnln(format string, v ...any) {
	if GetLevel() >= LevelWarn {
		log.Printf("[WARN] "+format+"\n", v...)
	}
}

func Infoln(format string, v ...any) {
	if GetLevel() >= LevelInfo {
		log.Printf("[INFO] "+format+"\n", v...)
	}
}

func Debugln(format string, v ...any) {
	if GetLevel() >= LevelDebug {
		log.Printf("[DEBUG] "+format+"\n", v...)
	}
}

func Traceln(format string, v ...any) {
	if GetLevel() >= LevelTrace {
		log.Printf("[TRACE] "+format+"\n", v...)
	}
}
