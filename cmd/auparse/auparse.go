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
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
)

var (
	fs        = flag.NewFlagSet("auparse", flag.ExitOnError)
	in        = fs.String("in", "-", "input file (defaults to stdin)")
	out       = fs.String("out", "-", "output file (defaults to stdout)")
	interpret = fs.Bool("i", false, "interpret and normalize messages")
	idLookup  = fs.Bool("id", true, "lookup uid and gid values in messages (requires -i)")
	format    = fs.String("format", "", "output format, possible values - json, yaml, text (default)")
)

func main() {
	fs.Parse(os.Args[1:]) //nolint:errcheck

	if err := processLogs(); err != nil {
		log.Fatalf("error: %v", err)
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

	return os.OpenFile(*out, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
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

	reassembler, err := libaudit.NewReassembler(5, 2*time.Second, &streamHandler{output})
	if err != nil {
		return fmt.Errorf("failed to create reassmbler: %w", err)
	}
	defer reassembler.Close()

	// Start goroutine to periodically purge timed-out events.
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			if reassembler.Maintain() != nil {
				return
			}
		}
	}()

	// Process lines from the input.
	s := bufio.NewScanner(input)
	for s.Scan() {
		line := s.Text()

		auditMsg, err := auparse.ParseLogLine(line)
		if err != nil {
			log.Printf("failed to parse message header: %v", err)
		}

		reassembler.PushMessage(auditMsg)
	}

	return nil
}

type streamHandler struct {
	output io.Writer
}

func (s *streamHandler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	if err := s.outputMultipleMessages(msgs); err != nil {
		log.Printf("[WARN] Failed writing message to output: %v", err)
	}
}

func (*streamHandler) EventsLost(count int) {
	log.Printf("Detected the loss of %v sequences.", count)
}

func (s *streamHandler) outputMultipleMessages(msgs []*auparse.AuditMessage) error {
	var err error
	if !*interpret {
		if _, err = s.output.Write([]byte("---\n")); err != nil {
			return err
		}
		for _, m := range msgs {
			if err = s.outputSingleMessage(m); err != nil {
				return err
			}
		}
		return nil
	}

	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		log.Printf("Failed to coalesce messages: %v", err)
		return nil
	}

	if *idLookup {
		aucoalesce.ResolveIDs(event)
	}

	switch *format {
	case "json":
		if err := s.printJSON(event); err != nil {
			log.Printf("Failed to marshal event to JSON: %v", err)
		}
	case "yaml":
		if _, err := s.output.Write([]byte("---\n")); err != nil {
			return err
		}
		if err := s.printYAML(event); err != nil {
			log.Printf("Failed to marshal message to YAML: %v", err)
		}
	default:
		sm := event.Summary
		if _, err := s.output.Write([]byte("---\n")); err != nil {
			return err
		}

		_, err := fmt.Fprintf(
			s.output,
			`time="%v" sequence=%v category=%v type=%v actor=%v/%v action=%v thing=%v/%v how=%v tags=%v`+"\n",
			event.Timestamp, event.Sequence, event.Category, event.Type, sm.Actor.Primary, sm.Actor.Secondary,
			sm.Action, sm.Object.Primary, sm.Object.Secondary, sm.How, event.Tags,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *streamHandler) outputSingleMessage(m *auparse.AuditMessage) error {
	switch *format {
	case "json":
		if err := s.printJSON(m.ToMapStr()); err != nil {
			log.Printf("Failed to marshal message to JSON: %v", err)
		}
	case "yaml":
		if err := s.printYAML(m.ToMapStr()); err != nil {
			log.Printf("Failed to marshal message to YAML: %v", err)
		}
	default:
		if _, err := fmt.Fprintf(
			s.output,
			"type=%v msg=%v\n",
			m.RecordType, m.RawData,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *streamHandler) printJSON(v interface{}) error {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err = s.output.Write(jsonBytes); err != nil {
		return err
	}
	if _, err = s.output.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func (s *streamHandler) printYAML(v interface{}) error {
	yamlBytes, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	if _, err = s.output.Write(yamlBytes); err != nil {
		return err
	}
	if _, err = s.output.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}
