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
	"github.com/elastic/go-libaudit/auparse"
)

var (
	fs     = flag.NewFlagSet("audit", flag.ExitOnError)
	debug  = fs.Bool("d", false, "enable debug output to stderr")
	diag   = fs.String("diag", "", "dump raw information from kernel to file")
	format = fs.String("format", "", "output format, possible values - json")
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
	log.WithField("status", status).Info("received audit status")

	log.Debugln("enabling auditing in the kernel")
	if err = client.SetEnabled(true); err != nil {
		return errors.Wrap(err, "failed to set enabled=true")
	}

	log.Debugln("sending message to kernel registering our PID as the audit daemon")
	if err = client.SetPID(libaudit.WaitForReply); err != nil {
		return errors.Wrap(err, "failed to set audit PID")
	}

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

		// Ignore AUDIT_EOE.
		if typ == auparse.AUDIT_EOE {
			continue
		}

		if err := outputEvent(rawEvent); err != nil {
			log.WithError(err).Warn("failed to output")
		}
	}

	return nil
}

func outputEvent(raw *libaudit.RawAuditMessage) error {
	typ := auparse.AuditMessageType(raw.MessageType)
	msg := string(raw.RawData)

	switch *format {
	default:
		fmt.Printf("type=%v msg=%v\n", typ.String(), msg)
	case "json":
		auditMsg, _ := auparse.Parse(typ, msg)
		jsonBytes, err := json.Marshal(auditMsg.ToMapStr())
		if err != nil {
			return err
		}
		fmt.Println(string(jsonBytes))
	}

	return nil
}
