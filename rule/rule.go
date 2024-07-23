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
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/elastic/go-libaudit/v2/auparse"
)

//go:generate sh -c "go tool cgo -godefs defs_kernel_types.go > zkernel_types.go && gofmt -w zkernel_types.go"
//go:generate go run github.com/elastic/go-licenser

const (
	maxKeyLength = 256  // AUDIT_MAX_KEY_LEN
	pathMax      = 4096 // PATH_MAX
	keySeparator = 0x01 // AUDIT_KEY_SEPARATOR
)

// Build builds an audit rule.
func Build(rule Rule) (WireFormat, error) {
	data := &ruleData{}
	var err error

	switch v := rule.(type) {
	case *SyscallRule:
		if err = data.setList(v.List); err != nil {
			return nil, err
		}

		// While it's possible to set syscalls on lists other than the 'exit' list
		// they don't actually do anything since the syscall information isn't
		// available at that time.  Don't assume that all syscalls are enabled.
		if data.flags == exitFilter {
			data.allSyscalls = true
		}

		if err = data.setAction(v.Action); err != nil {
			return nil, err
		}

		for _, filter := range v.Filters {
			switch filter.Type {
			case ValueFilterType:
				if err = addFilter(data, filter.LHS, filter.Comparator, filter.RHS); err != nil {
					return nil, fmt.Errorf("failed to add filter '%v': %w", filter, err)
				}
			case InterFieldFilterType:
				if err = addInterFieldComparator(data, filter.LHS, filter.Comparator, filter.RHS); err != nil {
					return nil, fmt.Errorf("failed to add interfield comparison '%v': %w", filter, err)
				}
			}
		}

		for _, syscall := range v.Syscalls {
			if err = addSyscall(data, syscall); err != nil {
				return nil, fmt.Errorf("failed to add syscall '%v': %w", syscall, err)
			}
		}

		if err = addKeys(data, v.Keys); err != nil {
			return nil, err
		}

	case *FileWatchRule:
		if err = addFileWatch(data, v); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown rule type: %T", v)
	}

	ard, err := data.toAuditRuleData()
	if err != nil {
		return nil, err
	}

	return ard.toWireFormat(), nil
}

// ToCommandLine decodes a WireFormat into a command-line rule.
// When resolveIds is set, it tries to resolve the argument to UIDs, GIDs,
// file_type fields.
// `auditctl -l` always prints the numeric (non-resolved) representation of
// this fields, so when the flag is set to false, the output is the same as
// auditctl.
// There is an exception to this rule when parsing the `arch` field:
// auditctl always prints "b64" or "b32" even for architectures other than
// the current machine. This is misleading, so this code will print the actual
// architecture.
func ToCommandLine(wf WireFormat, resolveIds bool) (rule string, err error) {
	return ToCommandLineAddRemove(wf, resolveIds, true)
}

// ToCommandLineAddRemove decodes a WireFormat into a command-line rule.
// When resolveIds is set, it tries to resolve the argument to UIDs, GIDs,
// file_type fields.
// When addRule is set, it indicates the rule is being added to the system.
// When addRule is unset, it indicates the rule is being removed from the system.
// `auditctl -l` always prints the numeric (non-resolved) representation of
// this fields, so when the flag is set to false, the output is the same as
// auditctl.
// There is an exception to this rule when parsing the `arch` field:
// auditctl always prints "b64" or "b32" even for architectures other than
// the current machine. This is misleading, so this code will print the actual
// architecture.
func ToCommandLineAddRemove(wf WireFormat, resolveIds, addRule bool) (rule string, err error) {
	ar, err := fromWireFormat(wf)
	if err != nil {
		return "", fmt.Errorf("failed to parse wire format: %w", err)
	}

	r := ruleData{}
	if err = r.fromAuditRuleData(ar); err != nil {
		return "", fmt.Errorf("failed to parse audit rule: %w", err)
	}

	list, err := r.getList()
	if err != nil {
		return "", err
	}

	act, err := r.getAction()
	if err != nil {
		return "", err
	}

	existingFields := make(map[field]int)
	for idx, fieldID := range r.fields {
		existingFields[fieldID] = idx
	}

	// Detect if rule is a watch.
	// Must have all syscalls and perm field. Only other valid fields are
	// dir, path and key, according to auditctl source
	if permIdx, ok := existingFields[permField]; r.allSyscalls && ok {
		extraFields, pos := false, 0
		var path, key string
	loop:
		for _, fieldID := range r.fields {
			switch fieldID {
			case keyField, pathField, dirField:
				if pos >= len(r.strings) {
					return "", fmt.Errorf("no buffer data for path field %d", fieldID)
				}
				if fieldID == keyField {
					key = r.strings[pos]
				} else {
					path = r.strings[pos]
				}
				pos++
			case permField:
			default:
				extraFields = true
				break loop
			}
		}
		if !extraFields {
			addRemove := "-w"
			if !addRule {
				addRemove = "-W"
			}

			arguments := []string{
				addRemove, path, "-p",
				permission(r.values[permIdx]).String(),
			}
			if len(key) > 0 {
				arguments = append(arguments, "-k", key)
			}
			return strings.Join(arguments, " "), nil
		}
	}

	// Parse rule as syscall type
	addRemove := "-a"
	if !addRule {
		addRemove = "-d"
	}

	arguments := []string{addRemove, fmt.Sprintf("%s,%s", act, list)}

	// Parse arch field first, if present
	// Here there is a significant difference to what auditctl does.
	// Auditctl will allow to install a rule for a different platform
	// (i.e. "aarch64" when the actual platform is "x86_64"). A rule like this
	// will never trigger any events in the kernel.
	// When such a rule is printed with `auditctl -l`, it will show as
	// "-F arch=b64", which is wrong.
	// This code will print the real value, "aarch64".
	if fieldIdx, found := existingFields[archField]; found {
		r.arch, err = getDisplayArch(r.values[fieldIdx])
		if err != nil {
			return "", err
		}
		arguments = append(arguments, "-F", fmt.Sprintf("arch=%s", r.arch))
	}

	// Parse syscalls
	if r.allSyscalls {
		if r.flags == exitFilter || r.flags == entryFilter {
			arguments = append(arguments, "-S", "all")
		}
	} else if len(r.syscalls) > 0 {
		arch, err := getRuntimeArch()
		if err != nil {
			return "", err
		}
		if r.arch == "b32" {
			switch arch {
			case "i386", "arm", "ppc":
			case "aarch64":
				arch = "arm"
			case "x86_64":
				arch = "i386"
			case "ppc64", "ppc64le":
				arch = "ppc"
			default:
				return "", fmt.Errorf("invalid arch for b32: '%s'", arch)
			}
		} else if len(r.arch) > 0 && r.arch != "b64" {
			arch = r.arch
		}
		syscallTable, ok := auparse.AuditSyscalls[arch]
		if !ok {
			return "", fmt.Errorf("no syscall table for arch %s", arch)
		}
		list := make([]string, len(r.syscalls))
		for idx, syscallID := range r.syscalls {
			list[idx], ok = syscallTable[int(syscallID)]
			if !ok {
				return "", fmt.Errorf("syscall %d not found for arch %s", syscallID, arch)
			}
		}

		arguments = append(arguments, "-S", strings.Join(list, ","))
	}

	// Parse fields
	stringIndex := 0
	for idx, fieldID := range r.fields {
		op, found := reverseOperatorsTable[r.fieldFlags[idx]]
		if !found {
			return "", fmt.Errorf("field operator %x not found", r.fieldFlags[idx])
		}
		switch fieldID {
		case archField:
			// arch already handled
		case fieldCompare:
			fieldIds, found := reverseComparisonsTable[comparison(r.values[idx])]
			if !found {
				return "", errors.New("comparison code not valid")
			}
			if fieldIds[1] < fieldIds[0] {
				fieldIds[0], fieldIds[1] = fieldIds[1], fieldIds[0]
			}
			var fields [2]string
			for idx, id := range fieldIds {
				if fields[idx], found = reverseFieldsTable[id]; !found {
					return "", fmt.Errorf("unknown field %d", id)
				}
			}
			arguments = append(arguments, fmt.Sprintf("-C %s%s%s",
				fields[0], op, fields[1]))

		default:
			lhs, found := reverseFieldsTable[fieldID]
			if !found {
				return "", fmt.Errorf("field %x not found", fieldID)
			}
			value := r.values[idx]
			var rhs string
			switch fieldID {
			// Fields that take a string
			case objectUserField, objectRoleField, objectTypeField, objectLevelLowField,
				objectLevelHighField, pathField, dirField, subjectUserField,
				subjectRoleField, subjectTypeField, subjectSensitivityField,
				subjectClearanceField, keyField, exeField:
				if stringIndex >= len(r.strings) {
					return "", errors.New("string buffer overflow")
				}
				rhs = r.strings[stringIndex]
				stringIndex++
			case exitField:
				exitCode := int(int32(value))
				if errnoValue, ok := auparse.AuditErrnoToName[-exitCode]; ok {
					rhs = fmt.Sprintf("-%s", errnoValue)
				} else {
					rhs = strconv.Itoa(exitCode)
				}
			case uidField, euidField, suidField, fsuidField, auidField, objectUIDField:
				rhs = strconv.Itoa(int(int32(value)))
				if resolveIds {
					if user, err := user.LookupId(rhs); err == nil {
						rhs = user.Username
					}
				}
			case gidField, egidField, sgidField, fsgidField, objectGIDField:
				rhs = strconv.Itoa(int(int32(value)))
				if resolveIds {
					if group, err := user.LookupGroupId(rhs); err == nil {
						rhs = group.Name
					}
				}
			case msgTypeField:
				if value <= math.MaxUint16 {
					rhs = auparse.AuditMessageType(value).String()
				} else {
					rhs = fmt.Sprintf("UNKNOWN[%d]", value)
				}
			case permField:
				rhs = permission(value).String()
			case filetypeField:
				if resolveIds {
					rhs = filetype(value).String()
				} else {
					rhs = strconv.Itoa(int(value))
				}
			default:
				rhs = strconv.Itoa(int(value))
			}
			arguments = append(arguments, fmt.Sprintf("-F %s%s%s", lhs, op, rhs))
		}
	}

	return strings.Join(arguments, " "), nil
}

func addFileWatch(data *ruleData, rule *FileWatchRule) error {
	path := filepath.Clean(rule.Path)

	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute: %v", path)
	}

	watchType := "path"
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		watchType = "dir"
	}

	var perms string
	if len(rule.Permissions) == 0 {
		perms = "rwxa"
	} else {
		perms = ""
		for _, p := range rule.Permissions {
			switch p {
			case ReadAccessType:
				perms += "r"
			case WriteAccessType:
				perms += "w"
			case ExecuteAccessType:
				perms += "x"
			case AttributeChangeAccessType:
				perms += "a"
			}
		}
	}

	// Build rule.
	data.flags = exitFilter
	data.action = alwaysAction
	data.allSyscalls = true
	if err := addFilter(data, watchType, "=", path); err != nil {
		return err
	}
	if err := addFilter(data, "perm", "=", perms); err != nil {
		return err
	}
	if err := addKeys(data, rule.Keys); err != nil {
		return err
	}
	return nil
}

func addKeys(data *ruleData, keys []string) error {
	if len(keys) > 0 {
		key := strings.Join(keys, string(rune(keySeparator)))
		if err := addFilter(data, "key", "=", key); err != nil {
			return fmt.Errorf("failed to add keys [%v]: %w", strings.Join(keys, ","), err)
		}
	}
	return nil
}

type ruleData struct {
	flags  filter
	action action

	allSyscalls bool
	syscalls    []uint32

	fields     []field
	values     []uint32
	fieldFlags []operator

	strings []string

	arch string
}

func (r ruleData) toAuditRuleData() (*auditRuleData, error) {
	data := &auditRuleData{auditRuleHeader: auditRuleHeader{
		Flags:      r.flags,
		Action:     r.action,
		FieldCount: uint32(len(r.fields)),
	}}

	if r.allSyscalls {
		for i := range data.Mask {
			data.Mask[i] = 0xFFFFFFFF
		}
		// NOTE: This was added to match the binary output when listing rules
		// from the kernel. See https://github.com/elastic/go-libaudit/pull/97.
		data.Mask[len(data.Mask)-1] = 0x0000FFFF
	} else {
		for _, syscallNum := range r.syscalls {
			word := syscallNum / 32
			bit := 1 << (syscallNum - (word * 32))
			if int(word) > len(data.Mask) {
				return nil, fmt.Errorf("invalid syscall number %v", syscallNum)
			}
			data.Mask[word] |= uint32(bit)
		}
	}

	if len(r.fields) > len(data.Fields) {
		return nil, fmt.Errorf("too many filters and keys, only %v total are supported", len(data.Fields))
	}
	for i := range r.fields {
		data.Fields[i] = r.fields[i]
		data.FieldFlags[i] = r.fieldFlags[i]
		data.Values[i] = r.values[i]
	}

	for _, s := range r.strings {
		data.Buf = append(data.Buf, []byte(s)...)
	}
	data.BufLen = uint32(len(data.Buf))

	return data, nil
}

func (r *ruleData) fromAuditRuleData(in *auditRuleData) error {
	r.flags = in.Flags
	r.action = in.Action
	r.fields = make([]field, in.FieldCount)
	r.allSyscalls = true
	for i := 0; r.allSyscalls && i < len(in.Mask)-1; i++ {
		r.allSyscalls = in.Mask[i] == 0xFFFFFFFF
	}
	if !r.allSyscalls {
		for word, bits := range in.Mask {
			for bit := uint32(0); bit < 32; bit++ {
				if bits&(1<<bit) != 0 {
					r.syscalls = append(r.syscalls, uint32(word)*32+bit)
				}
			}
		}
	}
	r.fields = make([]field, in.FieldCount)
	r.fieldFlags = make([]operator, in.FieldCount)
	r.values = make([]uint32, in.FieldCount)

	offset := uint32(0)
	for i := uint32(0); i < in.FieldCount; i++ {
		r.fields[i] = in.Fields[i]
		r.fieldFlags[i] = in.FieldFlags[i]
		r.values[i] = in.Values[i]
		switch r.fields[i] {
		case objectUserField, objectRoleField, objectTypeField, objectLevelLowField,
			objectLevelHighField, pathField, dirField, subjectUserField,
			subjectRoleField, subjectTypeField, subjectSensitivityField,
			subjectClearanceField, keyField, exeField:
			end := in.Values[i] + offset
			if end > in.BufLen {
				return fmt.Errorf("field %d overflows buffer", i)
			}
			r.strings = append(r.strings, string(in.Buf[offset:end]))
			offset = end
		}
	}

	return nil
}

func (r *ruleData) setList(list string) error {
	switch list {
	case "exit":
		r.flags = exitFilter
	case "task":
		r.flags = taskFilter
	case "user":
		r.flags = userFilter
	case "exclude":
		r.flags = excludeFilter
	default:
		return fmt.Errorf("invalid list '%v'", list)
	}

	return nil
}

func (r *ruleData) getList() (string, error) {
	switch r.flags {
	case exitFilter:
		return "exit", nil
	case taskFilter:
		return "task", nil
	case userFilter:
		return "user", nil
	case excludeFilter:
		return "exclude", nil
	default:
		return "", fmt.Errorf("invalid list flag '%v'", r.flags)
	}
}

func (r *ruleData) setAction(action string) error {
	switch action {
	case "always":
		r.action = alwaysAction
	case "never":
		r.action = neverAction
	default:
		return fmt.Errorf("invalid action '%v'", action)
	}

	return nil
}

func (r *ruleData) getAction() (string, error) {
	switch r.action {
	case alwaysAction:
		return "always", nil
	case neverAction:
		return "never", nil
	default:
		return "", fmt.Errorf("invalid action '%v'", r.action)
	}
}

// Convert name to number.
// Look for conditions when arch needs to be specified.
// Add syscall bit to mask.
func addSyscall(rule *ruleData, syscall string) error {
	if syscall == "all" {
		rule.allSyscalls = true
		return nil
	}
	rule.allSyscalls = false

	syscallNum, err := strconv.Atoi(syscall)
	if err != nil {
		if !errors.Is(err, strconv.ErrSyntax) {
			return fmt.Errorf("failed to parse syscall number '%v': %w", syscall, err)
		}

		arch := rule.arch
		if arch == "" {
			arch, err = getRuntimeArch()
			if err != nil {
				return fmt.Errorf("failed to add syscall: %w", err)
			}
		}

		// Convert name to number.
		table, found := reverseSyscall[arch]
		if !found {
			return fmt.Errorf("syscall table not found for arch %v", arch)
		}

		syscallNum, found = table[syscall]
		if !found {
			return fmt.Errorf("unknown syscall '%v' for arch %v", syscall, arch)
		}
	}

	rule.syscalls = append(rule.syscalls, uint32(syscallNum))
	return nil
}

func addInterFieldComparator(rule *ruleData, lhs, comparator, rhs string) error {
	op, found := operatorsTable[comparator]
	if !found {
		return fmt.Errorf("invalid operator '%v'", comparator)
	}

	switch op {
	case equalOperator, notEqualOperator:
	default:
		return fmt.Errorf("invalid operator '%v', only '=' or '!=' can be used", comparator)
	}

	leftField, found := fieldsTable[lhs]
	if !found {
		return fmt.Errorf("invalid field '%v' on left", lhs)
	}

	rightField, found := fieldsTable[rhs]
	if !found {
		return fmt.Errorf("invalid field '%v' on right", lhs)
	}

	table, found := comparisonsTable[leftField]
	if !found {
		return fmt.Errorf("field '%v' cannot be used in an interfield comparison", lhs)
	}

	comparison, found := table[rightField]
	if !found {
		return fmt.Errorf("field '%v' cannot be used in an interfield comparison", rhs)
	}

	rule.fields = append(rule.fields, fieldCompare)
	rule.fieldFlags = append(rule.fieldFlags, op)
	rule.values = append(rule.values, uint32(comparison))

	return nil
}

func addFilter(rule *ruleData, lhs, comparator, rhs string) error {
	op, found := operatorsTable[comparator]
	if !found {
		return fmt.Errorf("invalid operator '%v'", comparator)
	}

	field, found := fieldsTable[lhs]
	if !found {
		return fmt.Errorf("invalid field '%v' on left", lhs)
	}

	// Only newer kernel versions support exclude for credential types. Older
	// kernels only support exclude on the msgtype field.
	// https://github.com/torvalds/linux/blob/v5.16/kernel/auditfilter.c#L1343
	if rule.flags == excludeFilter {
		switch field {
		case pidField, uidField, gidField, auidField, msgTypeField,
			subjectUserField, subjectRoleField, subjectTypeField,
			subjectSensitivityField, subjectClearanceField,
			exeField:
		default:
			return fmt.Errorf("field '%v' cannot be used the exclude flag", lhs)
		}
	}

	switch field {
	case uidField, euidField, suidField, fsuidField, auidField, objectUIDField:
		// Convert RHS to number.
		// Or attempt to lookup the name to get the number.
		uid, err := getUID(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, uid)
	case gidField, egidField, sgidField, fsgidField, objectGIDField:
		gid, err := getGID(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, gid)
	case exitField:
		// Flag must be FilterExit.
		if rule.flags != exitFilter {
			return errors.New("exit filter can only be applied to syscall exit")
		}
		exitCode, err := getExitCode(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, uint32(exitCode))
	case msgTypeField:
		// Flag must be exclude or user.
		if rule.flags != userFilter && rule.flags != excludeFilter {
			return errors.New("msgtype filter can only be applied to the user or exclude lists")
		}
		msgType, err := getAuditMsgType(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, msgType)
	case objectUserField, objectRoleField, objectTypeField, objectLevelLowField,
		objectLevelHighField, pathField, dirField:
		// Flag must be FilterExit.
		if rule.flags != exitFilter {
			return fmt.Errorf("%v filter can only be applied to the syscall exit", lhs)
		}
		fallthrough
	case subjectUserField, subjectRoleField, subjectTypeField,
		subjectSensitivityField, subjectClearanceField, keyField, exeField:
		// Add string to strings.
		if field == keyField && len(rhs) > maxKeyLength {
			return fmt.Errorf("%v cannot be longer than %v", lhs, maxKeyLength)
		} else if len(rhs) > pathMax {
			return fmt.Errorf("%v cannot be longer than %v", lhs, pathMax)
		}
		rule.values = append(rule.values, uint32(len(rhs)))
		rule.strings = append(rule.strings, rhs)
	case archField:
		// Arch should come before syscall.
		// Arch only supports = and !=.
		if op != equalOperator && op != notEqualOperator {
			return fmt.Errorf("arch only supports the = and != operators")
		}
		// Or convert name to arch or validate given arch.
		archName, arch, err := getArch(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, arch)
		rule.arch = archName
	case permField:
		// Perm is only valid for exit.
		if rule.flags != exitFilter {
			return fmt.Errorf("perm filter can only be applied to the syscall exit")
		}
		// Perm is only valid for =.
		if op != equalOperator {
			return fmt.Errorf("perm only support the = operator")
		}
		perm, err := getPerm(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, perm)
	case filetypeField:
		// Filetype is only valid for exit.
		if rule.flags != exitFilter {
			return fmt.Errorf("filetype filter can only be applied to the syscall exit")
		}
		filetype, err := getFiletype(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, uint32(filetype))
	case arg0Field, arg1Field, arg2Field, arg3Field:
		// Convert RHS to a number.
		arg, err := parseNum(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, arg)
	// case SessionIDField:
	case inodeField:
		// Flag must be FilterExit.
		if rule.flags != exitFilter {
			return fmt.Errorf("inode filter can only be applied to the syscall exit")
		}
		// Comparator must be = or !=.
		if op != equalOperator && op != notEqualOperator {
			return fmt.Errorf("inode only supports the = and != operators")
		}
		// Convert RHS to number.
		inode, err := parseNum(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, inode)
	case saddrFamField:
		// Convert RHS to number.
		num, err := parseNum(rhs)
		if err != nil {
			return err
		}
		const (
			// include/linux/socket.h
			afInet  = 2
			afInet6 = 10
		)
		switch num {
		case afInet, afInet6:
		default:
			return fmt.Errorf("saddr_fam must be 2 or 10: have %d", num)
		}
		rule.values = append(rule.values, num)
	case devMajorField, devMinorField, successField, ppidField:
		// Flag must be FilterExit.
		if rule.flags != exitFilter {
			return fmt.Errorf("%v filter can only be applied to the syscall exit", lhs)
		}
		fallthrough
	default:
		// Convert RHS to number.
		num, err := parseNum(rhs)
		if err != nil {
			return err
		}
		rule.values = append(rule.values, num)
	}

	rule.fields = append(rule.fields, field)
	rule.fieldFlags = append(rule.fieldFlags, op)
	return nil
}

func getUID(uid string) (uint32, error) {
	if uid == "unset" || uid == "-1" {
		return 4294967295, nil
	}

	v, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		if !errors.Is(err, strconv.ErrSyntax) {
			return 0, fmt.Errorf("failed to parse uid '%v': %w", uid, err)
		}

		u, err := user.Lookup(uid)
		if err != nil {
			return 0, fmt.Errorf("failed to convert user '%v' to a numeric ID: %w", uid, err)
		}

		v, err = strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("failed to parse uid '%v' belonging to user '%v': %w", u.Uid, u.Username, err)
		}
	}

	return uint32(v), nil
}

func getGID(gid string) (uint32, error) {
	v, err := strconv.ParseUint(gid, 10, 32)
	if err != nil {
		if !errors.Is(err, strconv.ErrSyntax) {
			return 0, fmt.Errorf("failed to parse gid '%v': %w", gid, err)
		}

		g, err := user.LookupGroup(gid)
		if err != nil {
			return 0, fmt.Errorf("failed to convert group '%v' to a numeric ID: %w", gid, err)
		}

		v, err = strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("failed to parse gid '%v' belonging to group '%v': %w", g.Gid, g.Name, err)
		}
	}

	return uint32(v), nil
}

func getExitCode(exit string) (int32, error) {
	v, err := strconv.ParseInt(exit, 0, 32)
	if err != nil {
		if !errors.Is(err, strconv.ErrSyntax) {
			return 0, fmt.Errorf("failed to parse exit code '%v': %w", exit, err)
		}

		sign := 1
		code := exit
		if strings.HasPrefix(exit, "-") {
			sign = -1
			code = exit[1:]
		}

		num, found := auparse.AuditErrnoToNum[code]
		if !found {
			return 0, fmt.Errorf("failed to convert error to exit code '%v'", exit)
		}
		v = int64(sign * num)
	}

	return int32(v), nil
}

func getArch(arch string) (string, uint32, error) {
	realArch := arch
	switch strings.ToLower(arch) {
	case "b64":
		runtimeArch, err := getRuntimeArch()
		if err != nil {
			return "", 0, err
		}

		switch runtimeArch {
		case "aarch64", "x86_64", "ppc64":
			realArch = runtimeArch
		default:
			return "", 0, fmt.Errorf("cannot use b64 on %v", runtimeArch)
		}
	case "b32":
		runtimeArch, err := getRuntimeArch()
		if err != nil {
			return "", 0, err
		}

		switch runtimeArch {
		case "arm", "i386":
			realArch = runtimeArch
		case "aarch64":
			realArch = "arm"
		case "x86_64":
			realArch = "i386"
		case "ppc64":
			realArch = "ppc"
		default:
			return "", 0, fmt.Errorf("cannot use b32 on %v", runtimeArch)
		}
	}

	archValue, found := reverseArch[realArch]
	if !found {
		return "", 0, fmt.Errorf("unknown arch '%v'", arch)
	}
	return realArch, archValue, nil
}

// from a rule arch returned by kernel, decide what arch name to display
func getDisplayArch(archID uint32) (string, error) {
	runtimeArchStr, err := getRuntimeArch()
	if err != nil {
		return "", err
	}
	runtimeArchU32, ok := reverseArch[runtimeArchStr]
	if !ok {
		return "", errors.New("current architecture not supported")
	}
	runtimeArch := auparse.AuditArch(runtimeArchU32)
	requestedArch := auparse.AuditArch(archID)
	if requestedArch == runtimeArch {
		switch requestedArch {
		case auparse.AUDIT_ARCH_AARCH64, auparse.AUDIT_ARCH_X86_64, auparse.AUDIT_ARCH_PPC64:
			return "b64", nil
		case auparse.AUDIT_ARCH_ARM, auparse.AUDIT_ARCH_I386, auparse.AUDIT_ARCH_PPC:
			return "b32", nil
		}
	} else {
		switch {
		case runtimeArch == auparse.AUDIT_ARCH_AARCH64 && requestedArch == auparse.AUDIT_ARCH_ARM,
			runtimeArch == auparse.AUDIT_ARCH_X86_64 && requestedArch == auparse.AUDIT_ARCH_I386,
			runtimeArch == auparse.AUDIT_ARCH_PPC64 && requestedArch == auparse.AUDIT_ARCH_PPC:
			return "b32", nil
		}
	}
	name, ok := auparse.AuditArchNames[requestedArch]
	if !ok {
		return "", fmt.Errorf("unsupported arch=%x in rule", requestedArch)
	}
	return name, nil
}

// getRuntimeArch returns the program's arch (not the machine's arch).
func getRuntimeArch() (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "arm":
		arch = "arm"
	case "arm64":
		arch = "aarch64"
	case "386":
		arch = "i386"
	case "amd64":
		arch = "x86_64"
	case "ppc64", "ppc64le", "ppc":
		arch = runtime.GOARCH
	case "s390":
		arch = "s390"
	case "s390x":
		arch = "s390x"
	case "mips", "mipsle", "mips64", "mips64le":
		fallthrough
	default:
		return "", fmt.Errorf("unsupported arch: %v", runtime.GOARCH)
	}

	return arch, nil
}

func getAuditMsgType(msgType string) (uint32, error) {
	v, err := strconv.ParseUint(msgType, 0, 32)
	if err != nil {
		if !errors.Is(err, strconv.ErrSyntax) {
			return 0, fmt.Errorf("failed to parse msgtype '%v': %w", msgType, err)
		}

		typ, err := auparse.GetAuditMessageType(msgType)
		if err != nil {
			return 0, fmt.Errorf("failed to convert msgtype '%v' to numeric value: %w", msgType, err)
		}
		v = uint64(typ)
	}

	return uint32(v), nil
}

func getPerm(perm string) (uint32, error) {
	var permBits permission
	for _, p := range perm {
		switch p {
		case 'r':
			permBits |= readPerm
		case 'w':
			permBits |= writePerm
		case 'x':
			permBits |= execPerm
		case 'a':
			permBits |= attrPerm
		default:
			return 0, fmt.Errorf("invalid permission access type '%v'", p)
		}
	}

	return uint32(permBits), nil
}

// String returns the string representation of the permission bits.
func (bits permission) String() string {
	perms := make([]byte, 0, 4)
	if bits&readPerm != 0 {
		perms = append(perms, 'r')
	}
	if bits&writePerm != 0 {
		perms = append(perms, 'w')
	}
	if bits&execPerm != 0 {
		perms = append(perms, 'x')
	}
	if bits&attrPerm != 0 {
		perms = append(perms, 'a')
	}
	return string(perms)
}

func getFiletype(filetype string) (filetype, error) {
	switch strings.ToLower(filetype) {
	case "file":
		return fileFiletype, nil
	case "dir":
		return dirFiletype, nil
	case "socket":
		return socketFiletype, nil
	case "symlink":
		return linkFiletype, nil
	case "char":
		return characterFiletype, nil
	case "block":
		return blockFiletype, nil
	case "fifo":
		return fifoFiletype, nil
	default:
		return 0, fmt.Errorf("invalid filetype '%v'", filetype)
	}
}

// String returns the string representation of a filetype
func (ft filetype) String() string {
	switch ft {
	case fileFiletype:
		return "file"
	case dirFiletype:
		return "dir"
	case socketFiletype:
		return "socket"
	case linkFiletype:
		return "symlink"
	case characterFiletype:
		return "char"
	case blockFiletype:
		return "block"
	case fifoFiletype:
		return "fifo"
	default:
		return fmt.Sprintf("UNKNOWN:%x", uint32(ft))
	}
}

func parseNum(num string) (uint32, error) {
	if strings.HasPrefix(num, "-") {
		v, err := strconv.ParseInt(num, 0, 32)
		return uint32(v), err
	}
	v, err := strconv.ParseUint(num, 0, 32)
	return uint32(v), err
}
