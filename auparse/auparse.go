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
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

//go:generate sh -c "go run mk_audit_msg_types.go && gofmt -s -w zaudit_msg_types.go"
//go:generate sh -c "perl mk_audit_syscalls.pl > zaudit_syscalls.go && gofmt -s -w zaudit_syscalls.go"
//go:generate perl mk_audit_arches.pl

const (
	typeToken            = "type="
	msgToken             = "msg="
	auditHeaderSeparator = ")"
)

var (
	// errInvalidAuditHeader means some part of the audit header was invalid.
	errInvalidAuditHeader = errors.New("invalid audit message header")
	// errParseFailure indicates a generic failure to parse.
	errParseFailure = errors.New("failed to parse audit message")
)

// AuditMessage represents a single audit message.
type AuditMessage struct {
	RecordType AuditMessageType  // Record type from netlink header.
	Timestamp  time.Time         // Timestamp parsed from payload in netlink message.
	Sequence   int               // Sequence parsed from payload.
	RawData    string            // Raw message as a string.
	Data       map[string]string // The key value pairs parsed from the message.
	Error      error             // Error that occurred while parsing.
}

// ToMapStr returns a new map containing the parsed key value pairs, the
// record_type, @timestamp, and sequence. The parsed key value pairs have
// a lower precedence than the well-known keys and will not override them.
// If an error occurred while parsing the message then an error key will be
// present.
func (m *AuditMessage) ToMapStr() map[string]string {
	out := make(map[string]string, len(m.Data)+4)
	for k, v := range m.Data {
		out[k] = v
	}

	out["record_type"] = m.RecordType.String()
	out["@timestamp"] = m.Timestamp.UTC().String()
	out["sequence"] = strconv.Itoa(m.Sequence)
	out["raw_msg"] = m.RawData
	if m.Error != nil {
		out["error"] = m.Error.Error()
	}
	return out
}

// ParseLogLine parses an audit message as logged by the Linux audit daemon.
// It expects logs line that begin with the message type. For example,
// "type=SYSCALL msg=audit(1488862769.030:19469538)".
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
// If an error occurs an AuditMessage may or may not be returned depending on
// how much parsing occurred prior to the error. But if an error does occur you
// can be sure that parsing is not complete.
func Parse(typ AuditMessageType, message string) (*AuditMessage, error) {
	msg := &AuditMessage{
		RecordType: typ,
		RawData:    strings.TrimSpace(message),
	}

	timestamp, seq, err := parseAuditHeader([]byte(message))
	if err != nil {
		msg.Error = err
		return msg, err
	}

	msg.Timestamp = timestamp
	msg.Sequence = seq

	msg.Data, err = extractKeyValuePairs(msg.RecordType, msg.RawData)
	if err != nil {
		msg.Error = err
		return msg, err
	}

	if err = enrichData(msg); err != nil {
		msg.Error = err
		return msg, err
	}

	return msg, nil
}

// parseAuditHeader parses the timestamp and sequence number from the audit
// message header that has the form of "audit(1490137971.011:50406):".
func parseAuditHeader(line []byte) (time.Time, int, error) {
	// Find tokens.
	start := bytes.IndexRune(line, '(')
	if start == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	dot := bytes.IndexRune(line[start:], '.')
	if dot == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	dot += start
	sep := bytes.IndexRune(line[dot:], ':')
	if sep == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	sep += dot
	end := bytes.IndexRune(line[sep:], ')')
	if end == -1 {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	end += sep

	// Parse timestamp.
	sec, err := strconv.ParseInt(string(line[start+1:dot]), 10, 64)
	if err != nil {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	msec, err := strconv.ParseInt(string(line[dot+1:sep]), 10, 64)
	if err != nil {
		return time.Time{}, 0, errInvalidAuditHeader
	}
	tm := time.Unix(sec, msec*int64(time.Millisecond)).UTC()

	// Parse sequence.
	sequence, err := strconv.Atoi(string(line[sep+1 : end]))
	if err != nil {
		return time.Time{}, 0, errInvalidAuditHeader
	}

	return tm, sequence, nil
}

func removeAuditHeader(msg string) (string, error) {
	start := strings.Index(msg, auditHeaderSeparator)
	if start == -1 {
		return "", errParseFailure
	}

	return strings.TrimLeft(msg[start:], ": "), nil
}

// Key/Value Parsing Helpers

var (
	// keyValueRegex is the regular expression used to match keys.
	keyValueRegex = regexp.MustCompile(`[a-z0-9_-]+=`)

	// avcMessageRegex matches the beginning of AVC messages to parse the
	// seresult and seperms parameters. Example: "avc:  denied  { read } for  "
	avcMessageRegex = regexp.MustCompile(`avc:\s+(\w+)\s+\{\s*(.*)\s*\}\s+for\s+`)
)

// normalizeAuditMessage fixes some of the peculiarities of certain audit
// messages in order to make them parsable as key-value pairs.
func normalizeAuditMessage(typ AuditMessageType, msg string) (string, error) {
	switch typ {
	case AUDIT_AVC:
		i := avcMessageRegex.FindStringSubmatchIndex(msg)
		if len(i) != 3*2 {
			return "", errParseFailure
		}
		perms := strings.Fields(msg[i[4]:i[5]])
		msg = fmt.Sprintf("seresult=%v seperms=%v %v", msg[i[2]:i[3]], strings.Join(perms, ","), msg[i[1]:])
	case AUDIT_LOGIN:
		msg = strings.Replace(msg, "old ", "old_", 2)
		msg = strings.Replace(msg, "new ", "new_", 2)
	case AUDIT_CRED_DISP, AUDIT_USER_START, AUDIT_USER_END:
		msg = strings.Replace(msg, "msg='PAM: ", "msg='op=PAM:", 2)
		msg = strings.Replace(msg, " (hostname=", " hostname=", 2)
		msg = strings.TrimRight(msg, ")'")
	}

	return msg, nil
}

func extractKeyValuePairs(typ AuditMessageType, msg string) (map[string]string, error) {
	msg, err := removeAuditHeader(msg)
	if err != nil {
		return nil, err
	}

	msg, err = normalizeAuditMessage(typ, msg)
	if err != nil {
		return nil, err
	}

	data := map[string]string{}

	keyIndexes := keyValueRegex.FindAllStringSubmatchIndex(msg, -1)
	for i, keyIndex := range keyIndexes {
		key := msg[keyIndex[0] : keyIndex[1]-1]
		var value string

		if i < len(keyIndexes)-1 {
			nextKeyIndex := keyIndexes[i+1]
			value = trimQuotesAndSpace(msg[keyIndex[1]:nextKeyIndex[0]])
		} else {
			value = trimQuotesAndSpace(msg[keyIndex[1]:])
		}

		// Drop fields with useless values.
		switch value {
		case "", "?", "?,", "(null)":
			continue
		}

		data[key] = value
	}

	return data, nil
}

func trimQuotesAndSpace(v string) string {
	return strings.Trim(v, `'" `)
}

// Enrichment after KV parsing

func enrichData(msg *AuditMessage) error {
	switch msg.RecordType {
	case AUDIT_SYSCALL:
		if err := arch(msg.Data); err != nil {
			return err
		}
		if err := syscall(msg.Data); err != nil {
			return err
		}
		if err := hexDecode("exe", msg.Data); err != nil {
			return err
		}
	case AUDIT_SOCKADDR:
		if err := saddr(msg.Data); err != nil {
			return err
		}
	case AUDIT_PROCTITLE:
		if err := hexDecode("proctitle", msg.Data); err != nil {
			return err
		}
	case AUDIT_USER_CMD:
		if err := hexDecode("cmd", msg.Data); err != nil {
			return err
		}
	}

	return nil
}

func arch(data map[string]string) error {
	hex, found := data["arch"]
	if !found {
		return errors.New("arch key not found")
	}

	arch, err := strconv.ParseInt(hex, 16, 64)
	if err != nil {
		return errors.Wrap(err, "failed to parse arch")
	}

	data["arch"] = auditArch(arch).String()
	return nil
}

func syscall(data map[string]string) error {
	num, found := data["syscall"]
	if !found {
		return errors.New("syscall key not found")
	}

	syscall, err := strconv.Atoi(num)
	if err != nil {
		return errors.Wrap(err, "failed to parse syscall")
	}

	arch := data["arch"]
	data["syscall"] = auditSyscalls[arch][syscall]
	return nil
}

func saddr(data map[string]string) error {
	saddr, found := data["saddr"]
	if !found {
		return errors.New("saddr key not found")
	}

	saddrData, err := parseSockaddr(saddr)
	if err != nil {
		return errors.Wrap(err, "failed to parse saddr")
	}

	delete(data, "saddr")
	for k, v := range saddrData {
		data[k] = v
	}
	return nil
}

func hexDecode(key string, data map[string]string) error {
	hexValue, found := data[key]
	if !found {
		return errors.Errorf("%v key not found", key)
	}

	ascii, err := hexToASCII(hexValue)
	if err != nil {
		// Field is not in hex. Ignore.
		return nil
	}

	data[key] = ascii
	return nil
}
