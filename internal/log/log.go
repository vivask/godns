package log

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/op/go-logging"
)

const LOGGING_FILE_DIR = "/var/log/godns"

var (
	logFile     *os.File
	moduleName  string
	logFileName string
	logLevel    string
)

// Example format string. Everything except the message has a custom color
// which is dependent on the log level. Many fields have a custom output
// formatting too, eg. the time returns the hour down to the milli second.
var formatScreen = logging.MustStringFormatter(
	`%{color}[%{time:15:04:05.000}] %{longfile} %{longfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var formatFile = logging.MustStringFormatter(
	`[%{time:2006-01-02T15:04:05.000}] %{longfile} %{longfunc} %{level:.4s} %{id:03x} %{message}`,
)

// GetLogger new logger
func GetLogger(name string) *logging.Logger {
	if name == "" {
		name = "server"
	}
	stdoutBE := logging.NewLogBackend(os.Stdout, "", 0)
	beFormat := logging.NewBackendFormatter(stdoutBE, formatScreen)
	logging.SetBackend(beFormat)
	var log1 = logging.MustGetLogger(name)
	return log1
}

// Default logger
var Default = GetLogger("server")

// Forward logging to file name
func SetLogger(name, level string) error {
	if name == "" {
		name = "unknown"
	}

	path := LOGGING_FILE_DIR
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.Mkdir(path, 0744)
		if err != nil {
			return fmt.Errorf("can't create dir %s, error: %w", path, err)
		}
	}

	moduleName = strings.ToLower(name)
	logLevel = strings.ToUpper(level)
	logFileName = fmt.Sprintf("%s/%s.log", path, strings.ToLower(moduleName))

	err := CreateLogger()
	if err != nil {
		return err
	}

	return nil
}

// Create logger
func CreateLogger() error {
	logFile, err := os.OpenFile(logFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("can't open log file %s, error: %w", logFileName, err)
	}

	writer := io.MultiWriter(os.Stdout, logFile)
	fileBE := logging.NewLogBackend(writer, "", 0)
	beFileFormat := logging.NewBackendFormatter(fileBE, formatFile)
	logging.SetBackend(beFileFormat)
	lvl, err := logging.LogLevel(logLevel)
	if err != nil {
		Errorf("Can't set log level %s, error: %v", logLevel, err)
	} else {
		logging.SetLevel(lvl, "")
	}
	Default = logging.MustGetLogger(moduleName)

	Debugf("Log Level: %v", lvl)
	return nil
}

// Get logging context
func GetLogging() ([]string, error) {
	const Limit = 500
	file, err := os.Open(logFileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) > Limit {
		lines = lines[len(lines)-Limit:]
	}

	return lines, scanner.Err()
}

func ClearLogging() error {
	return os.Truncate(logFileName, 0)
}

func IsEmptyLog() bool {
	fi, err := os.Stat(logFileName)
	if err != nil {
		return true
	}
	return fi.Size() == 0
}

// Error logs a message using ERROR as log level.
var Error = Default.Error

// Errorf logs a message using ERROR as log level.
var Errorf = Default.Errorf

// Info logs a message using INFO as log level.
var Info = Default.Info

// Infof logs a message using INFO as log level.
var Infof = Default.Infof

// Debug logs a message using DEBUG as log level.
var Debug = Default.Debug

// Debugf logs a message using DEBUG as log level.
var Debugf = Default.Debugf

// Critical logs a message using CRITICAL as log level.
var Critical = Default.Critical

// Criticalf logs a message using CRITICAL as log level.
var Criticalf = Default.Criticalf

// Warning logs a message using WARNING as log level.
var Warn = Default.Warning

// Warningf logs a message using WARNING as log level.
var Warnf = Default.Warningf

// Notice logs a message using NOTICE as log level.
var Notice = Default.Notice

// Noticef logs a message using NOTICE as log level.
var Noticef = Default.Noticef

// Panic is equivalent to l.Critical(fmt.Sprint()) followed by a call to panic().
var Panic = Default.Panic

// Panicf is equivalent to l.Critical followed by a call to panic().
var Panicf = Default.Panicf

// Fatal is equivalent to l.Critical(fmt.Sprint()) followed by a call to os.Exit(1).
var Fatal = Default.Fatal

// Fatalf is equivalent to l.Critical followed by a call to os.Exit(1).
var Fatalf = Default.Fatalf
