// Copyright 2017 Elasticsearch Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

// audit is an example that receives audit messages from the kernel and outputs
// them to stdout. The output format is configurable using CLI flags.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"

	"github.com/elastic/go-libaudit"
	"github.com/elastic/go-libaudit/aucoalesce"
	"github.com/elastic/go-libaudit/auparse"
)

var (
	fs      = flag.NewFlagSet("audit", flag.ExitOnError)
	debug   = fs.Bool("d", false, "enable debug output to stderr")
	rate    = fs.Uint("rate", 0, "rate limit")
	backlog = fs.Uint("backlog", 8192, "backlog limit")
	diag    = fs.String("diag", "", "dump raw information from kernel to file")
	format  = fs.String("format", "", "output format, possible values - json, coalesce")
)

func enableLogger() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
	})
}

func main() {
	fs.Parse(os.Args[1:])

	if *debug {
		enableLogger()
	}

	if err := read(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func read() error {
	if os.Geteuid() != 0 {
		return errors.New("you must be root to receive audit data")
	}

	// Write netlink response to a file for further analysis or for writing
	// tests cases.
	var diagWriter io.Writer
	if *diag != "" {
		f, err := os.OpenFile(*diag, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		diagWriter = f
	}

	log.Debugln("starting netlink client")
	client, err := libaudit.NewAuditClient(diagWriter)
	if err != nil {
		return err
	}

	status, err := client.GetStatus()
	if err != nil {
		return errors.Wrap(err, "failed to get audit status")
	}
	log.Infof("received audit status=%+v", status)

	if status.Enabled == 0 {
		log.Debugln("enabling auditing in the kernel")
		if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
			return errors.Wrap(err, "failed to set enabled=true")
		}
	}

	if status.RateLimit != uint32(*rate) {
		log.Debugf("setting rate limit in kernel to %v", *rate)
		if err = client.SetRateLimit(uint32(*rate), libaudit.NoWait); err != nil {
			return errors.Wrap(err, "failed to set rate limit to unlimited")
		}
	}

	if status.BacklogLimit != uint32(*backlog) {
		log.Debugf("setting backlog limit in kernel to %v", *backlog)
		if err = client.SetBacklogLimit(uint32(*backlog), libaudit.NoWait); err != nil {
			return errors.Wrap(err, "failed to set backlog limit")
		}
	}

	log.Debugf("sending message to kernel registering our PID (%v) as the audit daemon", os.Getpid())
	if err = client.SetPID(libaudit.NoWait); err != nil {
		return errors.Wrap(err, "failed to set audit PID")
	}

	reassembler, err := libaudit.NewReassembler(5, 2*time.Second, &streamHandler{})
	if err != nil {
		return errors.Wrap(err, "failed to create reassmbler")
	}
	defer reassembler.Close()

	for {
		rawEvent, err := client.Receive(false)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		typ := auparse.AuditMessageType(rawEvent.MessageType)

		// Messages from 1300-2099 are kernel --> user space communication.
		if typ < auparse.AUDIT_USER_AUTH ||
			typ >= auparse.AUDIT_ANOM_LOGIN_FAILURES {
			continue
		}

		if err := reassembler.Push(rawEvent.MessageType, rawEvent.RawData); err != nil {
			log.WithError(err).
				WithField("type", typ).
				WithField("raw_data", string(rawEvent.RawData)).
				Warn("failed to push event to reassembler")
		}
	}
}

type streamHandler struct{}

func (s *streamHandler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	switch *format {
	default:
		for _, m := range msgs {
			fmt.Printf("type=%v msg=%v\n", m.RecordType.String(), m.RawData)
		}
	case "json":
		for _, m := range msgs {
			if err := printJSON(m.ToMapStr()); err != nil {
				log.WithError(err).Error("failed to marshal message to JSON")
			}
		}
	case "coalesce", "c":
		event, err := aucoalesce.CoalesceMessages(msgs)
		if err != nil {
			log.WithError(err).Warn("failed to coalesce messages")
			return
		}

		if err := printJSON(event); err != nil {
			log.WithError(err).Error("failed to marshal event to JSON")
		}
	}
}

func (s *streamHandler) EventsLost(count int) {
	log.Infof("Detected the loss of %v sequences.", count)
}

func printJSON(v interface{}) error {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}
