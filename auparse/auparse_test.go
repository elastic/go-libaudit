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

package auparse

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var update = flag.Bool("update", false, "update .golden files")

const (
	syscallMsg = `audit(1490137971.011:50406): arch=c000003e syscall=42 ` +
		`success=yes exit=0 a0=15 a1=7ffd83722200 a2=6e a3=ea60 items=1 ppid=1 ` +
		`pid=1229 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 ` +
		`fsgid=0 tty=(none) ses=4294967295 comm="master" ` +
		`exe="/usr/libexec/postfix/master" ` +
		`subj=system_u:system_r:postfix_master_t:s0 key=(null)`

	syscallLogLine = `type=SYSCALL msg=` + syscallMsg
)

func TestNormalizeAuditMessage(t *testing.T) {
	tests := []struct {
		typ AuditMessageType
		in  string
		out string
	}{
		{
			AUDIT_AVC,
			`avc:  denied  { read } for  pid=1494`,
			`seresult=denied seperms=read pid=1494`,
		},
		{
			AUDIT_LOGIN,
			`login pid=26125 uid=0 old auid=4294967295 new auid=0 old ses=4294967295 new ses=1172`,
			`login pid=26125 uid=0 old_auid=4294967295 new_auid=0 old_ses=4294967295 new_ses=1172`,
		},
	}

	for _, tc := range tests {
		msg, err := normalizeAuditMessage(tc.typ, tc.in)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, tc.out, msg)
	}
}

func TestParseAuditHeader(t *testing.T) {
	ts, seq, err := parseAuditHeader([]byte(syscallMsg))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, time.Unix(1490137971, 11*int64(time.Millisecond)).UnixNano(), ts.UnixNano())
	assert.EqualValues(t, 50406, seq)
}

func TestGetAuditMessageType(t *testing.T) {
	typ, err := GetAuditMessageType("UNKNOWN[1329]")
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, 1329, typ)

	typ, err = GetAuditMessageType("CWD")
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, 1307, typ)

	_, err = GetAuditMessageType("[]")
	assert.Equal(t, errInvalidAuditMessageTypName, err)

	_, err = GetAuditMessageType("")
	assert.Equal(t, errInvalidAuditMessageTypName, err)
}

func TestParseLogLineFromFiles(t *testing.T) {
	files, err := filepath.Glob("testdata/*.log")
	if err != nil {
		t.Fatal("glob failed", err)
	}

	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		// Read logs and parse events.
		var events []*AuditMessage
		s := bufio.NewScanner(bufio.NewReader(f))
		var lineNum int
		for s.Scan() {
			line := s.Text()
			lineNum++

			event, err := ParseLogLine(line)
			if err != nil {
				t.Logf("parsing failed at %v:%d on '%v' with error: %v",
					name, lineNum, line, err)
			}

			events = append(events, event)
		}

		// Update golden files on -update.
		if *update {
			if err := writeGoldenFile(name, events); err != nil {
				t.Fatal(err)
			}
			continue
		}

		// Compare events to golden events.
		goldenEvents, err := readGoldenFile(name + ".golden")
		if err != nil {
			t.Fatal(err)
		}

		for i, gold := range goldenEvents {
			assert.Equal(t, gold, events[i].ToMapStr(), "file: %v:%d", name, i+1)
		}
	}
}

func writeGoldenFile(sourceName string, events []*AuditMessage) error {
	f, err := os.Create(sourceName + ".golden")
	if err != nil {
		return err
	}
	defer f.Close()

	jsonEvents := []map[string]string{}
	for _, event := range events {
		jsonEvents = append(jsonEvents, event.ToMapStr())

	}

	b, err := json.MarshalIndent(jsonEvents, "", "  ")
	if err != nil {
		return err
	}

	_, err = f.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	return nil
}

func readGoldenFile(name string) ([]map[string]string, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	var out []map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func BenchmarkParseAuditHeader(b *testing.B) {
	msg := []byte(syscallMsg)
	for i := 0; i < b.N; i++ {
		_, _, err := parseAuditHeader(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAuditHeaderRegex(b *testing.B) {
	var auditMessageRegex = regexp.MustCompile(`^audit\((\d+).(\d+):(\d+)\):`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matches := auditMessageRegex.FindStringSubmatch(syscallMsg)
		if len(matches) != 4 {
			b.Fatal(errInvalidAuditHeader)
		}

		sec, _ := strconv.ParseInt(matches[1], 10, 64)
		msec, _ := strconv.ParseInt(matches[2], 10, 64)
		_ = time.Unix(sec, msec*int64(time.Millisecond))
		_, _ = strconv.Atoi(matches[3])
	}
}

// ExampleParseLogLine demonstrates parsing a log line from auditd and shows
// what the parsed data looks like.
func ExampleParseLogLine() {
	msg, err := ParseLogLine(syscallLogLine)
	if err != nil {
		return
	}

	evt, err := json.MarshalIndent(msg.ToMapStr(), "", "  ")
	if err != nil {
		return
	}

	fmt.Println(string(evt))
	// Output:
	//{
	//   "@timestamp": "2017-03-21 23:12:51.011 +0000 UTC",
	//   "a0": "15",
	//   "a1": "7ffd83722200",
	//   "a2": "6e",
	//   "a3": "ea60",
	//   "arch": "x86_64",
	//   "auid": "4294967295",
	//   "comm": "master",
	//   "egid": "0",
	//   "euid": "0",
	//   "exe": "/usr/libexec/postfix/master",
	//   "exit": "0",
	//   "fsgid": "0",
	//   "fsuid": "0",
	//   "gid": "0",
	//   "items": "1",
	//   "pid": "1229",
	//   "ppid": "1",
	//   "raw_msg": "audit(1490137971.011:50406): arch=c000003e syscall=42 success=yes exit=0 a0=15 a1=7ffd83722200 a2=6e a3=ea60 items=1 ppid=1 pid=1229 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"master\" exe=\"/usr/libexec/postfix/master\" subj=system_u:system_r:postfix_master_t:s0 key=(null)",
	//   "record_type": "SYSCALL",
	//   "sequence": "50406",
	//   "ses": "4294967295",
	//   "sgid": "0",
	//   "subj": "system_u:system_r:postfix_master_t:s0",
	//   "success": "yes",
	//   "suid": "0",
	//   "syscall": "connect",
	//   "tty": "(none)",
	//   "uid": "0"
	//}
}
