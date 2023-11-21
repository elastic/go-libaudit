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
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

//go:generate sh -c "go run mk_audit_msg_types.go && gofmt -s -w zaudit_msg_types.go"
//go:generate sh -c "perl mk_audit_syscalls.pl > zaudit_syscalls.go && gofmt -s -w zaudit_syscalls.go"
//go:generate perl mk_audit_arches.pl
//go:generate go run mk_audit_exit_codes.go
//go:generate go run github.com/elastic/go-licenser

const (
	typeToken = "type="
	msgToken  = "msg="
)

var (
	// errInvalidAuditHeader means some part of the audit header was invalid.
	errInvalidAuditHeader = errors.New("invalid audit message header")
	// errParseFailure indicates a generic failure to parse.
	errParseFailure = errors.New("failed to parse audit message")
	// errInvalidResult indicates a that neither "success" and "res" keys are not found
	errInvalidResult = errors.New("success and res key not found")
)

// AuditMessage represents a single audit message.
type AuditMessage struct {
	RecordType AuditMessageType // Record type from netlink header.
	Timestamp  time.Time        // Timestamp parsed from payload in netlink message.
	Sequence   uint32           // Sequence parsed from payload.
	RawData    string           // Raw message as a string.

	offset int               // offset is the index into RawData where the header ends and message begins.
	data   map[string]string // The key value pairs parsed from the message.
	tags   []string          // The keys associated with the event (e.g. the values set in rules with -F key=exec).
	error  error             // Error that occurred while parsing.
}

type field struct {
	orig  string // Original field value parse from message (including quotes).
	value string // Parsed and enriched value.
}

func newField(orig string) field { return field{orig: orig, value: orig} }

type fieldMap map[string]field

func (fm fieldMap) add(key string, f field) {
	fm[key] = f
}

func (fm fieldMap) setFieldValue(key, value string) {
	if f, ok := fm[key]; ok {
		fm[key] = field{orig: f.orig, value: value}
	}
}

func (fm fieldMap) find(key string) (field, error) {
	if f, ok := fm[key]; ok {
		return f, nil
	}
	return field{}, fmt.Errorf("%s key not found", key)
}

func (fm fieldMap) delete(key string) {
	delete(fm, key)
}

// Data returns the key-value pairs that are contained in the audit message.
// This information is parsed from the raw message text the first time this
// method is called, all future invocations return the stored result. A nil
// map may be returned error is non-nil. A non-nil error is returned if there
// was a failure parsing or enriching the data.
func (m *AuditMessage) Data() (map[string]string, error) {
	if m.data != nil || m.error != nil {
		return m.data, m.error
	}

	if m.offset < 0 {
		m.error = errors.New("message has no data content")
		return nil, m.error
	}

	message, err := normalizeAuditMessage(m.RecordType, m.RawData[m.offset:])
	if err != nil {
		m.error = err
		return nil, m.error
	}

	extractedKv := extractKeyValuePairs(message)
	if err = m.enrichData(extractedKv); err != nil {
		m.error = err
		return nil, m.error
	}

	m.data = make(map[string]string, len(extractedKv))
	for k, f := range extractedKv {
		m.data[k] = f.value
	}

	return m.data, m.error
}

func (m *AuditMessage) Tags() ([]string, error) {
	_, err := m.Data()
	return m.tags, err
}

// ToMapStr returns a new map containing the parsed key value pairs, the
// record_type, @timestamp, and sequence. The parsed key value pairs have
// a lower precedence than the well-known keys and will not override them.
// If an error occurred while parsing the message then an error key will be
// present.
func (m *AuditMessage) ToMapStr() map[string]interface{} {
	// Ensure event has been parsed.
	data, err := m.Data()

	out := make(map[string]interface{}, len(data)+5)
	for k, v := range data {
		out[k] = v
	}

	out["record_type"] = m.RecordType.String()
	out["@timestamp"] = m.Timestamp.UTC().String()
	out["sequence"] = strconv.FormatUint(uint64(m.Sequence), 10)
	out["raw_msg"] = m.RawData
	if len(m.tags) > 0 {
		out["tags"] = m.tags
	}
	if err != nil {
		out["error"] = err.Error()
	}
	return out
}

// ParseLogLine parses an audit message as logged by the Linux audit daemon.
// It expects logs line that begin with the message type. For example,
// "type=SYSCALL msg=audit(1488862769.030:19469538)". A non-nil error is
// returned if it fails to parse the message header (type, timestamp, sequence).
func ParseLogLine(line string) (*AuditMessage, error) {
	msgIndex := strings.Index(line, msgToken)
	if msgIndex == -1 {
		return nil, errInvalidAuditHeader
	}

	// Verify type=XXX is before msg=
	if msgIndex < len(typeToken)+1 {
		return nil, errInvalidAuditHeader
	}

	// Convert the type to a number (i.e. type=SYSCALL -> 1300).
	typName := line[len(typeToken) : msgIndex-1]
	typ, err := GetAuditMessageType(typName)
	if err != nil {
		return nil, err
	}

	msg := line[msgIndex+len(msgToken):]
	return Parse(typ, msg)
}

// Parse parses an audit message in the format it was received from the kernel.
// It expects a message type, which is the message type value from the netlink
// header, and a message, which is raw data from the netlink message. The
// message should begin the the audit header that contains the timestamp and
// sequence number -- "audit(1488862769.030:19469538)".
//
// A non-nil error is returned if it fails to parse the message header
// (timestamp, sequence).
func Parse(typ AuditMessageType, message string) (*AuditMessage, error) {
	message = strings.TrimSpace(message)

	timestamp, seq, end, err := parseAuditHeader(message)
	if err != nil {
		return nil, err
	}

	msg := &AuditMessage{
		RecordType: typ,
		Timestamp:  timestamp,
		Sequence:   seq,
		offset:     indexOfMessage(message[end:]),
		RawData:    message,
	}
	return msg, nil
}

// parseAuditHeader parses the timestamp and sequence number from the audit
// message header that has the form of "audit(1490137971.011:50406):".
func parseAuditHeader(line string) (time.Time, uint32, int, error) {
	// Find tokens.
	start := strings.IndexRune(line, '(')
	if start == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	dot := strings.IndexRune(line[start:], '.')
	if dot == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	dot += start
	sep := strings.IndexRune(line[dot:], ':')
	if sep == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	sep += dot
	end := strings.IndexRune(line[sep:], ')')
	if end == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	end += sep

	// Parse timestamp.
	sec, err := strconv.ParseInt(line[start+1:dot], 10, 64)
	if err != nil {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	msec, err := strconv.ParseInt(line[dot+1:sep], 10, 64)
	if err != nil {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	tm := time.Unix(sec, msec*int64(time.Millisecond)).UTC()

	// Parse sequence.
	sequence, err := strconv.ParseUint(line[sep+1:end], 10, 32)
	if err != nil {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}

	return tm, uint32(sequence), end, nil
}

func indexOfMessage(msg string) int {
	return strings.IndexFunc(msg, func(r rune) bool {
		switch r {
		case ':', ' ':
			return true
		default:
			return false
		}
	})
}

// Key/Value Parsing Helpers

var (
	// kvRegex is the regular expression used to match quoted and unquoted key
	// value pairs.
	kvRegex = regexp.MustCompile(`([a-z0-9_-]+)=((?:[^"'\s]+)|'(?:\\'|[^'])*'|"(?:\\"|[^"])*")`)

	// avcMessageRegex matches the beginning of SELinux AVC messages to parse
	// the seresult and seperms parameters.
	// Example: "avc:  denied  { read } for  "
	selinuxAVCMessageRegex = regexp.MustCompile(`avc:\s+(\w+)\s+\{\s*(.*)\s*\}\s+for\s+`)
)

// normalizeAuditMessage fixes some of the peculiarities of certain audit
// messages in order to make them parsable as key-value pairs.
func normalizeAuditMessage(typ AuditMessageType, msg string) (string, error) {
	switch typ {
	case AUDIT_AVC:
		i := selinuxAVCMessageRegex.FindStringSubmatchIndex(msg)
		if i == nil {
			// It's a different type of AVC (e.g. AppArmor) and doesn't require
			// normalization to make it parsable.
			return msg, nil
		}

		// This selinux AVC regex match should return three pairs.
		if len(i) != 3*2 {
			return "", errParseFailure
		}
		perms := strings.Fields(msg[i[4]:i[5]])
		msg = fmt.Sprintf("seresult=%v seperms=%v %v", msg[i[2]:i[3]], strings.Join(perms, ","), msg[i[1]:])
	case AUDIT_LOGIN:
		msg = strings.Replace(msg, "old ", "old_", 2)
		msg = strings.Replace(msg, "new ", "new_", 2)
	case AUDIT_CRED_DISP, AUDIT_USER_START, AUDIT_USER_END:
		msg = strings.Replace(msg, " (hostname=", " hostname=", 2)
		msg = strings.TrimRight(msg, ")'")
	}

	return msg, nil
}

func extractKeyValuePairs(msg string) fieldMap {
	data := make(fieldMap, 0)
	matches := kvRegex.FindAllStringSubmatch(msg, -1)
	for _, m := range matches {
		key, orig := m[1], m[2]
		value := trimQuotesAndSpace(orig)

		// Drop fields with useless values.
		switch value {
		case "", "?", "?,", "(null)":
			continue
		}

		if key == "msg" {
			for mk, mv := range extractKeyValuePairs(value) {
				data.add(mk, mv)
			}
			continue
		}
		data.add(key, field{orig: orig, value: value})
	}
	return data
}

func trimQuotesAndSpace(v string) string { return strings.Trim(v, `'" `) }

// Enrichment after KV parsing.
//
//nolint:errcheck // Continue enriching even if some fields do not exist.
func (m *AuditMessage) enrichData(data fieldMap) error {
	data.normalizeUnsetID("auid")
	data.normalizeUnsetID("old-auid")
	data.normalizeUnsetID("ses")

	// Many message types can have subj field so check them all.
	data.parseSELinuxContext("subj")

	// Normalize success/res to result.
	data.result()

	// Convert exit codes to named POSIX exit codes.
	data.exit()

	// Normalize keys that are of the form key="key=user_command".
	m.auditRuleKeyNew(data)

	data.hexDecode("cwd")

	switch m.RecordType {
	case AUDIT_SECCOMP:
		if err := data.setSignalName(); err != nil {
			return err
		}
		fallthrough
	case AUDIT_SYSCALL:
		if err := data.arch(); err != nil {
			return err
		}
		if err := data.setSyscallName(); err != nil {
			return err
		}
		if err := data.hexDecode("exe"); err != nil {
			return err
		}
	case AUDIT_SOCKADDR:
		if err := data.saddr(); err != nil {
			return err
		}
	case AUDIT_PROCTITLE:
		if err := data.hexDecode("proctitle"); err != nil {
			return err
		}
	case AUDIT_USER_CMD:
		if err := data.hexDecode("cmd"); err != nil {
			return err
		}
	case AUDIT_TTY, AUDIT_USER_TTY:
		if err := data.hexDecode("data"); err != nil {
			return err
		}
	case AUDIT_EXECVE:
		if err := data.execveArgs(); err != nil {
			return err
		}
	case AUDIT_PATH:
		data.parseSELinuxContext("obj")
		data.hexDecode("name")
	case AUDIT_USER_LOGIN:
		// acct only exists in failed logins.
		data.hexDecode("acct")
	}

	return nil
}

func (fm fieldMap) arch() error {
	const key = "arch"
	field, err := fm.find(key)
	if err != nil {
		return err
	}

	arch, err := strconv.ParseInt(field.value, 16, 64)
	if err != nil {
		return fmt.Errorf("failed to parse arch: %w", err)
	}

	fm.setFieldValue(key, AuditArch(arch).String())
	return nil
}

func (fm fieldMap) setSyscallName() error {
	field, err := fm.find("syscall")
	if err != nil {
		return err
	}

	syscall, err := strconv.Atoi(field.value)
	if err != nil {
		return fmt.Errorf("failed to parse syscall: %w", err)
	}

	arch, err := fm.find("arch")
	if err != nil {
		return errors.New("arch key not found so syscall cannot be translated to a name")
	}

	if name, found := AuditSyscalls[arch.value][syscall]; found {
		fm.setFieldValue("syscall", name)
	}
	return nil
}

func (fm fieldMap) setSignalName() error {
	field, err := fm.find("sig")
	if err != nil {
		return err
	}

	signalNum, err := strconv.Atoi(field.value)
	if err != nil {
		return fmt.Errorf("failed to parse sig: %w", err)
	}

	if signalName := unix.SignalName(syscall.Signal(signalNum)); signalName != "" {
		fm.setFieldValue("sig", signalName)
	}
	return nil
}

func (fm fieldMap) saddr() error {
	field, err := fm.find("saddr")
	if err != nil {
		return err
	}

	saddrData, err := parseSockaddr(field.value)
	if err != nil {
		return fmt.Errorf("failed to parse saddr: %w", err)
	}

	fm.delete("saddr")
	for k, v := range saddrData {
		fm.add(k, newField(v))
	}
	return nil
}

func (fm fieldMap) normalizeUnsetID(key string) {
	f, err := fm.find(key)
	if err != nil {
		return
	}

	switch f.value {
	case "4294967295", "-1":
		fm.setFieldValue(key, "unset")
	}
}

func (fm fieldMap) hexDecode(key string) error {
	field, err := fm.find(key)
	if err != nil {
		return err
	}

	// Use the original value that may or may not contain a leading quote.
	decodedStrings, err := hexToStrings(field.orig)
	if err != nil {
		// Field is not in hex. Ignore.
		return nil
	}

	if len(decodedStrings) > 0 {
		fm.setFieldValue(key, strings.Join(decodedStrings, " "))
	}
	return nil
}

func (fm fieldMap) execveArgs() error {
	argc, err := fm.find("argc")
	if err != nil {
		return err
	}

	count, err := strconv.ParseUint(argc.value, 10, 32)
	if err != nil {
		return fmt.Errorf("failed to convert argc='%v' to number: %w", argc, err)
	}

	for i := 0; i < int(count); i++ {
		key := "a" + strconv.Itoa(i)

		arg, err := fm.find(key)
		if err != nil {
			return fmt.Errorf("failed to find arg %v", key)
		}

		if ascii, err := hexToString(arg.orig); err == nil {
			fm.setFieldValue(key, ascii)
		}
	}

	return nil
}

// parseSELinuxContext parses a SELinux security context of the form
// 'user:role:domain:level:category'.
func (fm fieldMap) parseSELinuxContext(key string) error {
	f, err := fm.find(key)
	if err != nil {
		return err
	}

	keys := []string{"_user", "_role", "_domain", "_level", "_category"}
	contextParts := strings.SplitN(f.value, ":", len(keys))
	if len(contextParts) == 0 {
		return fmt.Errorf("failed to split SELinux context field %v", key)
	}
	fm.delete(key)

	for i, part := range contextParts {
		fm.add(key+keys[i], newField(part))
	}
	return nil
}

func (fm fieldMap) result() error {
	// Syscall messages use "success". Other messages use "res".
	field, err := fm.find("success")
	if err != nil {
		field, err = fm.find("res")
		if err != nil {
			return errInvalidResult
		}
		fm.delete("res")
	} else {
		fm.delete("success")
	}

	switch v := strings.ToLower(field.value); {
	case v == "yes", v == "1", strings.HasPrefix(v, "suc"):
		fm.add("result", newField("success"))
	default:
		fm.add("result", newField("fail"))
	}
	return nil
}

func (m *AuditMessage) auditRuleKeyNew(data fieldMap) {
	field, err := data.find("key")
	if err != nil {
		return
	}
	data.delete("key")

	// Handle hex encoded data (e.g. key=28696E7).
	if decodedData, err := decodeUppercaseHexString(field.orig); err == nil {
		keys := strings.Split(string(decodedData), string([]byte{0x01}))
		m.tags = keys
		return
	}

	parts := strings.SplitN(field.value, "=", 2)
	if len(parts) == 1 {
		// Handle key="net".
		m.tags = parts
	} else if len(parts) == 2 {
		// Handle key="key=net".
		m.tags = parts[1:]
	}
}

func (fm fieldMap) exit() error {
	field, err := fm.find("exit")
	if err != nil {
		return err
	}

	exitCode, err := strconv.Atoi(field.value)
	if err != nil {
		return fmt.Errorf("failed to parse exit: %w", err)
	}

	if exitCode >= 0 {
		return nil
	}

	name, found := AuditErrnoToName[-1*exitCode]
	if !found {
		return nil
	}

	fm.setFieldValue("exit", name)
	return nil
}
