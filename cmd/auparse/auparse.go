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
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/elastic/go-libaudit"
	"github.com/elastic/go-libaudit/aucoalesce"
	"github.com/elastic/go-libaudit/auparse"
)

var (
	fs        = flag.NewFlagSet("auparse", flag.ExitOnError)
	debug     = fs.Bool("d", false, "enable debug output to stderr")
	in        = fs.String("in", "-", "input file (defaults to stdin)")
	out       = fs.String("out", "-", "output file (defaults to stdout)")
	interpret = fs.Bool("i", false, "interpret and normalize messages")
	idLookup  = fs.Bool("id", true, "lookup uid and gid values in messages (requires -i)")
	format    = fs.String("format", "", "output format, possible values - json, yaml, text (default)")
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

	if err := processLogs(); err != nil {
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

func processLogs() error {
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

	reassembler, err := libaudit.NewReassembler(5, 2*time.Second, &streamHandler{})
	if err != nil {
		return errors.Wrap(err, "failed to create reassmbler")
	}
	defer reassembler.Close()

	// Start goroutine to periodically purge timed-out events.
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if reassembler.Maintain() != nil {
					return
				}
			}
		}
	}()

	// Process lines from the input.
	s := bufio.NewScanner(input)
	for s.Scan() {
		line := s.Text()

		auditMsg, err := auparse.ParseLogLine(line)
		if err != nil {
			log.WithError(err).Warn("failed to parse message header")
		}

		reassembler.PushMessage(auditMsg)
	}

	return nil
}

type streamHandler struct{}

func (s *streamHandler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	outputMultipleMessages(msgs)
}

func (s *streamHandler) EventsLost(count int) {
	log.Infof("Detected the loss of %v sequences.", count)
}

func outputMultipleMessages(msgs []*auparse.AuditMessage) {
	if !*interpret {
		fmt.Println("---")
		for _, m := range msgs {
			outputSingleMessage(m)
		}
		return
	}

	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		log.WithError(err).Warn("failed to coalesce messages")
		return
	}

	if *idLookup {
		aucoalesce.ResolveIDs(event)
	}

	switch *format {
	case "json":
		if err := printJSON(event); err != nil {
			log.WithError(err).Error("failed to marshal event to JSON")
		}
	case "yaml":
		fmt.Println("---")
		if err := printYAML(event); err != nil {
			log.WithError(err).Error("failed to marshal message to YAML")
		}
	default:
		sm := event.Summary
		fmt.Println("---")
		fmt.Printf(`time="%v" sequence=%v category=%v type=%v actor=%v/%v action=%v thing=%v/%v how=%v tags=%v`+"\n",
			event.Timestamp, event.Sequence, event.Category, event.Type, sm.Actor.Primary, sm.Actor.Secondary,
			sm.Action, sm.Object.Primary, sm.Object.Secondary, sm.How, event.Tags)
	}
}

func outputSingleMessage(m *auparse.AuditMessage) {
	switch *format {
	case "json":
		if err := printJSON(m.ToMapStr()); err != nil {
			log.WithError(err).Error("failed to marshal message to JSON")
		}
	case "yaml":
		if err := printYAML(m.ToMapStr()); err != nil {
			log.WithError(err).Error("failed to marshal message to YAML")
		}
	default:
		fmt.Printf("type=%v msg=%v\n", m.RecordType, m.RawData)
	}
}

func printJSON(v interface{}) error {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func printYAML(v interface{}) error {
	yamlBytes, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Println(string(yamlBytes))
	return nil
}
