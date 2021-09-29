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

package rule

import (
	"io"
	"unsafe"
)

const (
	syscallBitmaskSize = 64 // AUDIT_BITMASK_SIZE
	maxFields          = 64 // AUDIT_MAX_FIELDS
)

// WireFormat is the binary representation of a rule as used to exchange rules
// (commands) with the kernel.
type WireFormat []byte

// auditRuleData supports filter rules with both integer and string
// fields.  It corresponds with AUDIT_ADD_RULE, AUDIT_DEL_RULE and
// AUDIT_LIST_RULES requests.
// https://github.com/linux-audit/audit-kernel/blob/v3.15/include/uapi/linux/audit.h#L423-L437
type auditRuleData struct {
	Flags      filter
	Action     action
	FieldCount uint32
	Mask       [syscallBitmaskSize]uint32 // Syscalls affected.
	Fields     [maxFields]field
	Values     [maxFields]uint32
	FieldFlags [maxFields]operator
	BufLen     uint32 // Total length of buffer used for string fields.
	Buf        []byte // String fields.
}

const ruleHeaderSize = int(unsafe.Sizeof(auditRuleData{}) - unsafe.Sizeof([]byte(nil)))

func (r auditRuleData) toWireFormat() WireFormat {
	n := ruleHeaderSize + len(r.Buf)
	n += (4 - n%4) % 4 // Adding padding.
	buf := make([]byte, n)
	copy(buf, (*[ruleHeaderSize]byte)(unsafe.Pointer(&r))[:])
	copy(buf[ruleHeaderSize:], r.Buf)
	return buf
}

func fromWireFormat(data WireFormat) (*auditRuleData, error) {
	if len(data) < ruleHeaderSize {
		return nil, io.ErrUnexpectedEOF
	}
	var r auditRuleData
	copy((*[ruleHeaderSize]byte)(unsafe.Pointer(&r))[:], data)
	if uint32(len(data[ruleHeaderSize:])) < r.BufLen {
		return nil, io.ErrUnexpectedEOF
	}
	data = data[ruleHeaderSize:]
	r.Buf = append(r.Buf, data[:r.BufLen]...)
	return &r, nil
}
