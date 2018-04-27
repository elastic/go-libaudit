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

package aucoalesce

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"github.com/elastic/go-libaudit/auparse"
)

var update = flag.Bool("update", false, "update .golden files")

func TestCoalesceMessages(t *testing.T) {
	testFiles, err := filepath.Glob("testdata/*.yaml")
	if err != nil {
		t.Fatal("glob", err)
	}

	for _, file := range testFiles {
		t.Run(file, func(t *testing.T) {
			testCoalesceEvent(t, file)
		})
	}
}

type testEvent struct {
	name     string
	messages []*auparse.AuditMessage
}

type testEventOutput struct {
	TestName string   `json:"test_name"`
	Event    *Event   `json:"event"`
	Warnings []string `json:"warnings,omitempty"`
}

func newTestEventOutput(testName string, event *Event) testEventOutput {
	var errs []string
	for _, err := range event.Warnings {
		errs = append(errs, err.Error())
	}
	sort.Strings(errs)
	return testEventOutput{testName, event, errs}
}

func testCoalesceEvent(t *testing.T, file string) {
	testEvents := readEventsFromYAML(t, file)

	var events []testEventOutput
	for _, te := range testEvents {
		event, err := CoalesceMessages(te.messages)
		if err != nil {
			t.Fatal(err)
		}

		events = append(events, newTestEventOutput(te.name, event))
	}

	// Update golden files on -update.
	if *update {
		if err := writeGoldenFile(file, events); err != nil {
			t.Fatal(err)
		}
	}

	goldenEvents, err := readGoldenFile(file)
	if err != nil {
		t.Fatal(err)
	}

	// Compare events to golden events.
	for i, observed := range events {
		if i >= len(goldenEvents) {
			t.Errorf("golden file has fewer events that there are test cases (run with -update): file=%v", file)
			continue
		}
		expected := goldenEvents[i]

		t.Run(testEvents[i].name, func(t *testing.T) {
			assert.EqualValues(t, expected, normalizeEvent(t, observed), "file=%v test_case=%v", file, testEvents[i].name)
		})
	}
}

func readEventsFromYAML(t testing.TB, name string) []testEvent {
	file, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	var data map[string]interface{}
	if err := yaml.Unmarshal(file, &data); err != nil {
		t.Fatal(err)
	}

	tests, ok := data["tests"]
	if !ok {
		t.Fatal("failed to find 'tests' in yaml")
	}

	cases, ok := tests.(map[interface{}]interface{})
	if !ok {
		t.Fatalf("unexpected type %T for 'tests'", tests)
	}

	// Create test cases from YAML file.
	var testEvents []testEvent
	for name, messages := range cases {
		var msgs []*auparse.AuditMessage

		s := bufio.NewScanner(strings.NewReader(messages.(string)))
		for s.Scan() {
			line := s.Text()
			msg, err := auparse.ParseLogLine(line)
			if err != nil {
				t.Fatal("invalid message:", line)
			}

			msgs = append(msgs, msg)
		}

		testEvents = append(testEvents, testEvent{
			name:     name.(string),
			messages: msgs,
		})
	}

	// Sort the test cases by their key to ensure ordering.
	sort.Slice(testEvents, func(i, j int) bool {
		return testEvents[i].name < testEvents[j].name
	})

	return testEvents
}

func writeGoldenFile(name string, events []testEventOutput) error {
	if strings.HasSuffix(name, ".yaml") {
		name = name[:len(name)-len(".yaml")]
	}

	f, err := os.Create(name + ".json.golden")
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}

	_, err = f.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	return nil
}

func readGoldenFile(name string) ([]map[string]interface{}, error) {
	if strings.HasSuffix(name, ".yaml") {
		name = name[:len(name)-len(".yaml")]
	}

	data, err := ioutil.ReadFile(name + ".json.golden")
	if err != nil {
		return nil, err
	}

	var out []map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func normalizeEvent(t testing.TB, event testEventOutput) map[string]interface{} {
	b, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
