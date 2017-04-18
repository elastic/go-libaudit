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

// Package aucoalesce provides functions to coalesce related audit messages into
// a single event.
package aucoalesce

import (
	"strings"

	"github.com/pkg/errors"

	"github.com/elastic/go-libaudit/auparse"
)

// CoalesceMessages combines the given messages into a single event. It assumes
// that all the messages in the slice have the same timestamp and sequence
// number. An error is returned is msgs is empty or nil.
func CoalesceMessages(msgs []*auparse.AuditMessage) (map[string]interface{}, error) {
	if len(msgs) == 0 {
		return nil, errors.New("messages is empty")
	}

	event := map[string]interface{}{
		"@timestamp": msgs[0].Timestamp,
		"sequence":   msgs[0].Sequence,
	}

	for _, msg := range msgs {
		data, _ := msg.Data()
		if len(data) == 0 {
			continue
		}

		switch msg.RecordType {
		default:
			addRecord(msg, event)
		case auparse.AUDIT_PATH:
			addPathRecord(msg, event)
		case auparse.AUDIT_CWD:
			addCWDRecord(msg, event)
		case auparse.AUDIT_SYSCALL:
			rename("syscall", "name", data)
			delete(data, "items")
			addRecord(msg, event)
		case auparse.AUDIT_EOE:
			// EOE (end-of-event) is just an empty sentinel message.
		}
	}

	return event, nil
}

func addRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	recordType := strings.ToLower(msg.RecordType.String())
	data, _ := msg.Data()
	event[recordType] = data
}

func addPathRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	paths, ok := event["path"].([]map[string]string)
	if !ok {
		paths = make([]map[string]string, 0, 1)
	}

	data, _ := msg.Data()
	paths = append(paths, data)
	event["path"] = paths
}

func addCWDRecord(msg *auparse.AuditMessage, event map[string]interface{}) {
	data, _ := msg.Data()
	cwd, found := data["cwd"]
	if !found {
		return
	}

	event["cwd"] = cwd
}

func rename(old, new string, event map[string]string) {
	value, found := event[old]
	if found {
		delete(event, old)
		event[new] = value
	}
}
