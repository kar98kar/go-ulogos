// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package logger

import (
	"io"
	"log"
	"sync/atomic"
	"time"

	"github.com/kar98kar/go-ulogos/logger/glog"
)

// LogSystem is implemented by log output devices.
// All methods can be called concurrently from multiple goroutines.
type LogSystem interface {
	LogPrint(LogMsg)
	GetLogger() *log.Logger
}

// NewStdLogSystem creates a LogSystem that prints to the given writer.
// The flag values are defined package log.
func NewStdLogSystem(writer io.Writer, flags int, level LogLevel) *StdLogSystem {
	logger := log.New(writer, "", flags)
	return &StdLogSystem{logger, uint32(level)}
}

func NewMLogSystem(writer io.Writer, flags int, level LogLevel, withTimestamp bool) *MLogSystem {
	logger := log.New(writer, "", flags)
	return &MLogSystem{logger, uint32(level), withTimestamp}
}

type MLogSystem struct {
	logger        *log.Logger
	level         uint32
	withTimestamp bool
}

func (m *MLogSystem) GetLogger() *log.Logger {
	return m.logger
}

func (m *MLogSystem) NewFile() io.Writer {
	f, _, err := CreateMLogFile(time.Now())
	if err != nil {
		glog.Fatal(err)
	}
	return f
}

type StdLogSystem struct {
	logger *log.Logger
	level  uint32
}

// GetLogger is unused, fulfills interface
func (t *StdLogSystem) GetLogger() *log.Logger {
	return t.logger
}

func (m *MLogSystem) LogPrint(msg LogMsg) {
	stdmsg, ok := msg.(stdMsg)
	if ok {
		if m.GetLogLevel() >= stdmsg.Level() {
			if m.withTimestamp {
				m.logger.Print(time.Now().UTC().Format(time.RFC3339), " ", stdmsg.String())
			} else {
				m.logger.Print(stdmsg.String())
			}
		}
	}
}

func (t *StdLogSystem) LogPrint(msg LogMsg) {
	stdmsg, ok := msg.(stdMsg)
	if ok {
		if t.GetLogLevel() >= stdmsg.Level() {
			t.logger.Print(stdmsg.String())
		}
	}
}

func (t *StdLogSystem) SetLogLevel(i LogLevel) {
	atomic.StoreUint32(&t.level, uint32(i))
}

func (t *StdLogSystem) GetLogLevel() LogLevel {
	return LogLevel(atomic.LoadUint32(&t.level))
}

func (m *MLogSystem) GetLogLevel() LogLevel {
	return LogLevel(atomic.LoadUint32(&m.level))
}

// NewJSONLogSystem creates a LogSystem that prints to the given writer without
// adding extra information irrespective of loglevel only if message is JSON type
func NewJsonLogSystem(writer io.Writer) LogSystem {
	logger := log.New(writer, "", 0)
	return &jsonLogSystem{logger}
}

type jsonLogSystem struct {
	logger *log.Logger
}

// GetLogger is unused, fulfills interface
func (t *jsonLogSystem) GetLogger() *log.Logger {
	return t.logger
}

func (t *jsonLogSystem) LogPrint(msg LogMsg) {
	jsonmsg, ok := msg.(jsonMsg)
	if ok {
		t.logger.Print(jsonmsg.String())
	}
}
