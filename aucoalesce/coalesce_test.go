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

package aucoalesce

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/go-libaudit/auparse"
	"github.com/stretchr/testify/assert"
)

var update = flag.Bool("update", false, "update .golden files")

func TestCoalesceMessages(t *testing.T) {
	files, err := filepath.Glob("testdata/*.log")
	if err != nil {
		t.Fatal("glob failed", err)
	}

	for _, name := range files {
		testCoalesce(t, name)
	}
}

func testCoalesce(t testing.TB, file string) {
	msgs := readMessages(t, file)

	event, err := CoalesceMessages(msgs)
	if err != nil {
		t.Fatal(err)
	}

	// Update golden files on -update.
	if *update {
		if err = writeGoldenFile(file, event); err != nil {
			t.Fatal(err)
		}
	}

	// Compare events to golden events.
	goldenEvent, err := readGoldenFile(file + ".golden")
	if err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, goldenEvent, normalizeEvent(t, event), "file: %v", file)
}

func readMessages(t testing.TB, name string) []*auparse.AuditMessage {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var msgs []*auparse.AuditMessage

	// Read logs and parse events.
	s := bufio.NewScanner(bufio.NewReader(f))
	for s.Scan() {
		line := s.Text()
		msg, err := auparse.ParseLogLine(line)
		if err != nil {
			t.Fatal("invalid message:", line)
		}

		msgs = append(msgs, msg)
	}

	return msgs
}

func writeGoldenFile(sourceName string, event map[string]interface{}) error {
	f, err := os.Create(sourceName + ".golden")
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return err
	}

	_, err = f.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	return nil
}

func readGoldenFile(name string) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func normalizeEvent(t testing.TB, event map[string]interface{}) map[string]interface{} {
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
