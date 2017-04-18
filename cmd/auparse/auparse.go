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

// auparse is an example that parses audit log files from the Linux auditd
// process.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/elastic/go-libaudit/auparse"
)

var (
	fs    = flag.NewFlagSet("auparse", flag.ExitOnError)
	debug = fs.Bool("d", false, "enable debug output to stderr")
	in    = fs.String("in", "-", "input file (defaults to stdin)")
	out   = fs.String("out", "-", "output file (defaults to stdout)")
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

	if err := parse(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func input() (io.ReadCloser, error) {
	if *in == "-" {
		return os.Stdin, nil
	}

	return os.Open(*in)
}

func output() (io.WriteCloser, error) {
	if *out == "-" {
		return os.Stdout, nil
	}

	return os.OpenFile(*out, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
}

func parse() error {
	input, err := input()
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := output()
	if err != nil {
		return err
	}
	defer output.Close()

	s := bufio.NewScanner(input)
	for s.Scan() {
		line := s.Text()

		auditMsg, err := auparse.ParseLogLine(line)
		if err != nil {
			log.WithError(err).Warn("failed to parse line")
		}

		if err := outputEvent(auditMsg); err != nil {
			log.WithError(err).Warn("failed to output line")
		}
	}
	return nil
}

func outputEvent(auditMsg *auparse.AuditMessage) error {
	jsonBytes, err := json.Marshal(auditMsg.ToMapStr())
	if err != nil {
		return err
	}

	fmt.Println(string(jsonBytes))
	return nil
}
