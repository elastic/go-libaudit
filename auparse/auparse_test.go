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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFieldMap(t *testing.T) {
	m := &fieldMap{}
	mm := *m
	mm["test"] = field{`'test'`, "test"}

	f, err := m.find("test")
	require.Nil(t, err)
	assert.Equal(t, "test", f.value)

	m.setFieldValue("test", "newVal")
	assert.Equal(t, "newVal", mm["test"].value)

	m.add("second", field{`'test'`, "test"})
	f2, err := m.find("second")
	require.Nil(t, err)
	assert.Equal(t, "test", f2.value)
	assert.Equal(t, "test", mm["second"].value)
}

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
	ts, seq, end, err := parseAuditHeader(syscallMsg)
	if err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, ')', syscallMsg[end])
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

func TestExtractKeyValuePairs(t *testing.T) {
	tests := []struct {
		in  string
		out fieldMap
	}{
		{
			`argc=4 a0="cat" a1="btest=test" a2="-f" a3="regex=8"'`,
			fieldMap{
				"argc": newField("4"),
				"a0":   {`"cat"`, `cat`},
				"a1":   {`"btest=test"`, `btest=test`},
				"a2":   {`"-f"`, `-f`},
				"a3":   {`"regex=8"`, `regex=8`},
			},
		},
		{
			`x='grep "test" file' y=z`,
			fieldMap{
				"x": {`'grep "test" file'`, `grep "test" file`},
				"y": newField("z"),
			},
		},
		{
			`x="grep 'test' file" y=z`,
			fieldMap{
				"x": {`"grep 'test' file"`, `grep 'test' file`},
				"y": newField("z"),
			},
		},
		{
			`x="grep \"test\" file" y=z`,
			fieldMap{
				"x": {`"grep \"test\" file"`, `grep \"test\" file`},
				"y": newField("z"),
			},
		},
		{
			`x='grep \'test\' file' y=z`,
			fieldMap{
				"x": {`'grep \'test\' file'`, `grep \'test\' file`},
				"y": newField("z"),
			},
		},
	}

	for _, tc := range tests {
		out := extractKeyValuePairs(tc.in)
		assert.Equal(t, tc.out, out, "failed on: %v", tc.in)
	}
}

func BenchmarkExtractKeyValuePairs(b *testing.B) {
	tests := []struct {
		name string
		in   string
		out  fieldMap
	}{
		{
			"bpf message",
			`arch=c000003e syscall=321 success=yes exit=0 a0=2 a1=c0059cd6e8 comm="pf-host-agent" exe="/optimyze.cloud/prodfiler/pf-host-agent/pf-host-agent" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="bpf" ARCH=x86_64 SYSCALL=bpf`,
			fieldMap{
				"arch":    newField("c000003e"),
				"syscall": newField("321"),
				"success": {`yes`, `yes`},
				"exit":    newField("0"),
				"a0":      newField("2"),
				"a1":      {"c0059cd6e8", "c0059cd6e8"},
				"comm":    {`"pf-host-agent"`, `pf-host-agent`},
				"exe":     {`"/optimyze.cloud/prodfiler/pf-host-agent/pf-host-agent"`, `/optimyze.cloud/prodfiler/pf-host-agent/pf-host-agent`},
				"subj":    newField("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"),
				"key":     {`"bpf"`, "bpf"},
			},
		},
		{
			"short message",
			`x='grep "test" file' y=z`,
			fieldMap{
				"x": {`'grep "test" file'`, `grep "test" file`},
				"y": newField("z"),
			},
		},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				extractKeyValuePairs(tc.in)
			}
		})
	}
}

var dataTests = []struct {
	name   string
	text   string
	output map[string]string
}{
	{
		name: "syscall",
		text: "type=SYSCALL msg=audit(1481076984.827:17): arch=c000003e syscall=313 success=yes exit=0 a0=0 a1=41a15c a2=0 a3=0 items=0 ppid=390 pid=391 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"modprobe\" exe=\"/usr/bin/kmod\" subj=system_u:system_r:insmod_t:s0 key=(null)",
		output: map[string]string{
			"a0":          "0",
			"a1":          "41a15c",
			"a2":          "0",
			"a3":          "0",
			"arch":        "x86_64",
			"auid":        "unset",
			"comm":        "modprobe",
			"egid":        "0",
			"euid":        "0",
			"exe":         "/usr/bin/kmod",
			"exit":        "0",
			"fsgid":       "0",
			"fsuid":       "0",
			"gid":         "0",
			"items":       "0",
			"pid":         "391",
			"ppid":        "390",
			"result":      "success",
			"ses":         "unset",
			"sgid":        "0",
			"subj_domain": "insmod_t",
			"subj_level":  "s0",
			"subj_role":   "system_r",
			"subj_user":   "system_u",
			"suid":        "0",
			"syscall":     "finit_module",
			"tty":         "(none)",
			"uid":         "0",
		},
	},
	{
		"user_cmd",
		`type=USER_CMD msg=audit(1488862769.030:19469538): user pid=3027 uid=497 auid=700 ses=11988 msg='cwd="/" cmd=2F7573722F6C696236342F6E6167696F732F706C7567696E732F636865636B5F617374657269736B5F7369705F7065657273202D7020313037 terminal=? res=success'`,
		map[string]string{
			"auid":   "700",
			"cmd":    "/usr/lib64/nagios/plugins/check_asterisk_sip_peers -p 107",
			"cwd":    "/",
			"pid":    "3027",
			"result": "success",
			"ses":    "11988",
			"uid":    "497",
		},
	},
}

func TestExtractAndEnrichData(t *testing.T) {
	for _, tc := range dataTests {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := ParseLogLine(tc.text)
			if err != nil {
				t.Fatalf("parsing message: %v", err)
			}
			data, err := msg.Data()
			require.Nil(t, err)
			assert.Equal(t, tc.output, data)
		})
	}
}

func BenchmarkAuditMessageData(b *testing.B) {
	for _, tc := range dataTests {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				msg, errP := ParseLogLine(tc.text)
				if errP != nil {
					b.Fatalf("parsing message: %v", errP)
				}
				b.StartTimer()
				data, err := msg.Data()
				b.StopTimer()
				require.Nil(b, err)
				assert.Equal(b, tc.output, data)
			}
		})
	}
}

func TestParseLogLineFromFiles(t *testing.T) {
	files, err := filepath.Glob("testdata/*.log")
	if err != nil {
		t.Fatal("glob failed", err)
	}
	if len(files) == 0 {
		t.Fatal("no files found")
	}

	for _, filePath := range files {
		testGoldenFile(t, filePath)
	}
}

type StoredAuditMessage struct {
	Timestamp  time.Time         `json:"@timestamp"`
	RecordType AuditMessageType  `json:"record_type"`
	Sequence   uint32            `json:"sequence"`
	RawMessage string            `json:"raw_msg"`
	Tags       []string          `json:"keys,omitempty"`
	Data       map[string]string `json:"data"`
	Error      string            `json:"error,omitempty"`
}

func NewStoredAuditMessage(msg *AuditMessage) *StoredAuditMessage {
	if msg == nil {
		return nil
	}

	// Ensure raw message has been parsed.
	var errorMsg string
	if _, err := msg.Data(); err != nil {
		errorMsg = err.Error()
	}

	return &StoredAuditMessage{
		Timestamp:  msg.Timestamp,
		RecordType: msg.RecordType,
		Sequence:   msg.Sequence,
		RawMessage: msg.RawData,
		Tags:       msg.tags,
		Data:       msg.data,
		Error:      errorMsg,
	}
}

func testGoldenFile(t *testing.T, filePath string) {
	t.Helper()

	events := loadAuditMessages(t, filePath)

	// Update golden files on -update.
	if *update {
		if err := writeGoldenFile(filePath, events); err != nil {
			t.Fatal(err)
		}
		return
	}

	// Compare events to golden events.
	goldenEvents, err := readGoldenFile(filePath + ".golden")
	if err != nil {
		t.Fatal(err)
	}

	for i, gold := range goldenEvents {
		if events[i] != nil {
			assert.Equal(t, gold, NewStoredAuditMessage(events[i]), "file: %v:%d", filePath, i+1)
		} else {
			assert.Nil(t, gold, "file: %v:%d", filePath, i+1)
		}
	}
}

func loadAuditMessages(tb testing.TB, name string) []*AuditMessage {
	f, err := os.Open(name)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()

	// Read logs and parse events.
	var messages []*AuditMessage
	s := bufio.NewScanner(bufio.NewReader(f))
	var lineNum int
	for s.Scan() {
		line := s.Text()
		lineNum++

		msg, err := ParseLogLine(line)
		if err != nil && *update {
			tb.Logf("parsing failed at %v:%d on '%v' with error: %v",
				name, lineNum, line, err)
		}

		messages = append(messages, msg)
	}
	if err := s.Err(); err != nil {
		tb.Fatalf("incomplete file loading: %v", err)
	}
	return messages
}

func writeGoldenFile(sourceName string, events []*AuditMessage) error {
	f, err := os.Create(sourceName + ".golden")
	if err != nil {
		return err
	}
	defer f.Close()

	var jsonEvents []*StoredAuditMessage
	for _, event := range events {
		if event != nil {
			jsonEvents = append(jsonEvents, NewStoredAuditMessage(event))
		} else {
			jsonEvents = append(jsonEvents, nil)
		}
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

func readGoldenFile(name string) ([]*StoredAuditMessage, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	var out []*StoredAuditMessage
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func BenchmarkParseAuditHeader(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, err := parseAuditHeader(syscallMsg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAuditHeaderRegex(b *testing.B) {
	auditMessageRegex := regexp.MustCompile(`^audit\((\d+).(\d+):(\d+)\):`)
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

func BenchmarkParseLogLine(b *testing.B) {
	// Build corpus of valid messages from the test data.
	files, err := filepath.Glob("testdata/*.log")
	require.NoError(b, err)
	var msgs []string
	for _, f := range files {
		data, err := ioutil.ReadFile(f)
		require.NoError(b, err)
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if _, err = ParseLogLine(line); err == nil {
				msgs = append(msgs, line)
			}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := msgs[i%len(msgs)]
		if _, err = ParseLogLine(msg); err != nil {
			b.Fatal(err)
		}
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
	//   "auid": "unset",
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
	//   "result": "success",
	//   "sequence": "50406",
	//   "ses": "unset",
	//   "sgid": "0",
	//   "subj_domain": "postfix_master_t",
	//   "subj_level": "s0",
	//   "subj_role": "system_r",
	//   "subj_user": "system_u",
	//   "suid": "0",
	//   "syscall": "connect",
	//   "tty": "(none)",
	//   "uid": "0"
	//}
}
