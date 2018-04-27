// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build linux

// audit is an example that receives audit messages from the kernel and outputs
// them to stdout. The output can be piped to the auparse example to format
// and interpret the output.
package main

import (
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
	fs          = flag.NewFlagSet("audit", flag.ExitOnError)
	debug       = fs.Bool("d", false, "enable debug output to stderr")
	diag        = fs.String("diag", "", "dump raw information from kernel to file")
	rate        = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog     = fs.Uint("backlog", 8192, "backlog limit")
	receiveOnly = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
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

	var err error
	var client *libaudit.AuditClient
	if *receiveOnly {
		client, err = libaudit.NewMulticastAuditClient(diagWriter)
		if err != nil {
			return errors.Wrap(err, "failed to create receive-only audit client")
		}
		defer client.Close()
	} else {
		client, err = libaudit.NewAuditClient(diagWriter)
		if err != nil {
			return errors.Wrap(err, "failed to create audit client")
		}
		defer client.Close()

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
	}

	return receive(client)
}

func receive(r *libaudit.AuditClient) error {
	for {
		rawEvent, err := r.Receive(false)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		fmt.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))
	}
}
