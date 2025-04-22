package main

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logLevelMap = map[string]zapcore.Level{
	"Debug": zapcore.DebugLevel,
	// InfoLevel is the default logging priority.
	"Info": zapcore.InfoLevel,
	// WarnLevel logs are more important than Info, but don't need individual
	// human review.
	"Warn": zapcore.WarnLevel,
	// ErrorLevel logs are high-priority. If an application is running smoothly,
	// it shouldn't generate any error-level logs.
	"Error": zapcore.ErrorLevel,
	// DPanicLevel logs are particularly important errors. In development the
	// logger panics after writing the message.
	"DPanic": zapcore.DPanicLevel,
	// PanicLevel logs a message, then panics.
	"Panic": zapcore.PanicLevel,
	// FatalLevel logs a message, then calls os.Exit(1).
	"Fatal": zapcore.FatalLevel,
}

var defaultLevel = zapcore.InfoLevel

func parseLogLevel(logLevel *string) zapcore.Level {
	if logLevel == nil {
		return defaultLevel
	}
	logLevelStr := *logLevel

	if level, ok := logLevelMap[logLevelStr]; ok {
		return level
	}
	return defaultLevel
}

type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
	Sync()
}

func NewLogger(config LogConfig) *zap.Logger {
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	zc := zap.Config{
		Level:            zap.NewAtomicLevelAt(parseLogLevel(config.Level)),
		OutputPaths:      config.OutputPaths,
		ErrorOutputPaths: config.ErrorOutputPaths,
		EncoderConfig:    encoderCfg,
		Encoding:         config.Encoding,
		InitialFields: map[string]interface{}{
			"pid": os.Getpid(),
		},
	}
	log := zap.Must(zc.Build())
	return log
}
