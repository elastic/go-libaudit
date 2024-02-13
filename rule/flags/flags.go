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

// Package flags provides parsing of audit rules as specified using CLI flags
// in accordance to the man page for auditctl (from the auditd userspace tools).
package flags

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/kballard/go-shellquote"

	"github.com/elastic/go-libaudit/v2/rule"
)

// Parse parses an audit rule specified using flags. It can parse delete all
// commands (-D), file watch rules (-w), and syscall rules (-a or -A).
func Parse(s string) (rule.Rule, error) {
	args, err := shellquote.Split(s)
	if err != nil {
		return nil, err
	}

	// Parse the flags.
	ruleFlagSet := newRuleFlagSet()
	if err := ruleFlagSet.flagSet.Parse(args); err != nil {
		return nil, err
	}
	if err := ruleFlagSet.validate(); err != nil {
		return nil, err
	}

	// Build a struct that is specific to the command type.
	var r rule.Rule
	switch ruleFlagSet.Type {
	case rule.DeleteAllRuleType:
		r = &rule.DeleteAllRule{
			Type: rule.DeleteAllRuleType,
			Keys: ruleFlagSet.Key,
		}
	case rule.FileWatchRuleType, rule.DeleteFileWatchRuleType:
		fileWatchRule := &rule.FileWatchRule{
			Type:        ruleFlagSet.Type,
			Path:        ruleFlagSet.Path,
			Permissions: ruleFlagSet.Permissions,
			Keys:        ruleFlagSet.Key,
		}
		r = fileWatchRule

		if ruleFlagSet.Type == rule.DeleteFileWatchRuleType {
			fileWatchRule.Path = ruleFlagSet.DeletePath
		}
	case rule.AppendSyscallRuleType, rule.PrependSyscallRuleType, rule.DeleteSyscallRuleType:
		syscallRule := &rule.SyscallRule{
			Type:     ruleFlagSet.Type,
			Filters:  ruleFlagSet.Filters,
			Syscalls: ruleFlagSet.Syscalls,
			Keys:     ruleFlagSet.Key,
		}
		r = syscallRule

		switch ruleFlagSet.Type {
		case rule.AppendSyscallRuleType:
			syscallRule.List = ruleFlagSet.Append.List
			syscallRule.Action = ruleFlagSet.Append.Action
		case rule.PrependSyscallRuleType:
			syscallRule.List = ruleFlagSet.Prepend.List
			syscallRule.Action = ruleFlagSet.Prepend.Action
		case rule.DeleteSyscallRuleType:
			syscallRule.List = ruleFlagSet.Delete.List
			syscallRule.Action = ruleFlagSet.Delete.Action
		}
	default:
		return nil, fmt.Errorf("unknown rule type: %v", ruleFlagSet.Type)
	}

	return r, nil
}

// --- ruleFlagSet ---

// ruleFlagSet is a used to parse the flags used in an audit rule.
type ruleFlagSet struct {
	Type rule.Type

	DeleteAll bool // [-D] Delete all rules.

	// Audit Rule
	Prepend  addFlag    // -A Prepend rule (list,action) or (action,list).
	Append   addFlag    // -a Append rule (list,action) or (action,list).
	Delete   addFlag    // [-d] delete single rule
	Filters  filterList // -F [n=v | n!=v | n<v | n>v | n<=v | n>=v | n&v | n&=v] OR -C [n=v | n!=v]
	Syscalls stringList // -S Syscall name or number or "all". Value can be comma-separated.

	// Filepath watch (can be done more expressively using syscalls)
	Path        string              // -w Path for filesystem watch (no wildcards).
	DeletePath  string              // -W Path for filesystem watch to remove (no wildcards).
	Permissions fileAccessTypeFlags // -p [r|w|x|a] Permission filter.

	Key stringList // -k Key(s) to associate with the rule.

	flagSet *flag.FlagSet
}

func newRuleFlagSet() *ruleFlagSet {
	rule := &ruleFlagSet{
		flagSet: flag.NewFlagSet("rule", flag.ContinueOnError),
	}
	rule.flagSet.SetOutput(ioutil.Discard)

	rule.flagSet.BoolVar(&rule.DeleteAll, "D", false, "delete all")
	rule.flagSet.Var(&rule.Append, "a", "append rule")
	rule.flagSet.Var(&rule.Prepend, "A", "prepend rule")
	rule.flagSet.Var(&rule.Delete, "d", "delete rule")
	rule.flagSet.Var((*interFieldFilterList)(&rule.Filters), "C", "comparison filter")
	rule.flagSet.Var((*valueFilterList)(&rule.Filters), "F", "filter")
	rule.flagSet.Var(&rule.Syscalls, "S", "syscall name, number, or 'all'")
	rule.flagSet.Var(&rule.Permissions, "p", "access type - r=read, w=write, x=execute, a=attribute change")
	rule.flagSet.StringVar(&rule.Path, "w", "", "path to watch, no wildcards")
	rule.flagSet.StringVar(&rule.DeletePath, "W", "", "path to unwatch, no wildcards")
	rule.flagSet.Var(&rule.Key, "k", "key")

	return rule
}

func (r *ruleFlagSet) Usage() string {
	buf := new(bytes.Buffer)
	r.flagSet.SetOutput(buf)
	r.flagSet.Usage()
	r.flagSet.SetOutput(ioutil.Discard)
	return buf.String()
}

func (r *ruleFlagSet) validate() error {
	var (
		deleteAll       uint8
		fileWatchFlags  uint8
		addFileWatch    uint8
		deleteFileWatch uint8
		syscallFlags    uint8
		addSyscall      uint8
		deleteSyscall   uint8
	)

	r.flagSet.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "D":
			deleteAll = 1
		case "p":
			fileWatchFlags = 1
		case "w":
			addFileWatch = 1
		case "W":
			deleteFileWatch = 1
		case "S", "F", "C":
			syscallFlags = 1
		case "a", "A":
			addSyscall = 1
		case "d":
			deleteSyscall = 1
		}
	})

	// Test for mutual exclusivity.
	switch deleteAll + addFileWatch + deleteFileWatch + addSyscall + deleteSyscall {
	case 0:
		return errors.New("missing an operation flag (add or delete rule)")
	case 1:
		switch {
		case deleteAll > 0:
			r.Type = rule.DeleteAllRuleType
		case addFileWatch > 0:
			r.Type = rule.FileWatchRuleType
		case deleteFileWatch > 0:
			r.Type = rule.DeleteFileWatchRuleType
		case addSyscall > 0:
			r.Type = rule.AppendSyscallRuleType
		case deleteSyscall > 0:
			r.Type = rule.DeleteSyscallRuleType
		default:
			return fmt.Errorf("unknown state")
		}
	default:
		ops := make([]string, 0, 3)
		if deleteAll > 0 {
			ops = append(ops, "delete all [-D]")
		}
		if addFileWatch > 0 {
			ops = append(ops, "file watch [-w]")
		}
		if deleteFileWatch > 0 {
			ops = append(ops, "delete file watch [-W]")
		}
		if addSyscall > 0 {
			ops = append(ops, "audit rule [-a|-A]")
		}
		if deleteSyscall > 0 {
			ops = append(ops, "delete audit rule [-d]")
		}

		return fmt.Errorf("mutually exclusive flags uses together (%v)",
			strings.Join(ops, " and "))
	}

	if (addFileWatch+deleteFileWatch) > 0 && syscallFlags > 0 {
		return fmt.Errorf("audit rule [-F|-S|-C] flags cannot be used with file watches")
	}

	if (addSyscall+deleteSyscall) > 0 && fileWatchFlags > 0 {
		return fmt.Errorf("file watch [-p] flags cannot be used with syscall rules")
	}

	if deleteAll > 0 && syscallFlags > 0 {
		return fmt.Errorf("audit rule [-F|-S|-C] flags cannot be used when deleting all rules")
	}

	if deleteAll > 0 && fileWatchFlags > 0 {
		return fmt.Errorf("file watch permission [-p] flags cannot be used when deleting all rules")
	}

	if addSyscall > 0 {
		var zero addFlag
		if r.Prepend == zero && r.Append == zero {
			return errors.New("audit rules must specify either [-A] or [-a]")
		}
		if r.Prepend != zero && r.Append != zero {
			return fmt.Errorf("audit rules cannot specify both [-A] and [-a]")
		}
		if r.Prepend != zero {
			r.Type = rule.PrependSyscallRuleType
		}
	}

	return nil
}

// --- Specialized flag.Value types for parsing the audit rules.

// --- filterList ----

type filterList []rule.FilterSpec

func (l filterList) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("[")
	for i, v := range l {
		buf.WriteString(v.String())
		if i > len(l)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString("]")
	return buf.String()
}

// --- interFieldFilter ---

type interFieldFilter rule.FilterSpec

var comparisonRegexp = regexp.MustCompile(`(\w+)\s*(!?=)(\w+)`)

func (f *interFieldFilter) Set(value string) error {
	values := comparisonRegexp.FindStringSubmatch(value)
	if len(values) != 4 {
		return fmt.Errorf("invalid comparison: '%v'", value)
	}

	f.Type = rule.InterFieldFilterType
	f.LHS = values[1]
	f.Comparator = values[2]
	f.RHS = values[3]
	return nil
}

// --- valueFilterFlag ---

type valueFilter rule.FilterSpec

var filterRegexp = regexp.MustCompile(`(\w+)\s*(<=|>=|&=|=|!=|<|>|&)(\S+)`)

func (f *valueFilter) Set(value string) error {
	values := filterRegexp.FindStringSubmatch(value)
	if len(values) != 4 {
		return fmt.Errorf("invalid filter: '%v'", value)
	}

	f.Type = rule.ValueFilterType
	f.LHS = values[1]
	f.Comparator = values[2]
	f.RHS = values[3]
	return nil
}

// --- interFieldFilterList ----

type interFieldFilterList filterList

func (l interFieldFilterList) String() string { return filterList(l).String() }

func (l *interFieldFilterList) Set(value string) error {
	comparisonFlag := &interFieldFilter{}
	if err := comparisonFlag.Set(value); err != nil {
		return err
	}
	*l = append(*l, rule.FilterSpec(*comparisonFlag))
	return nil
}

// --- valueFilterList ----

type valueFilterList filterList

func (l valueFilterList) String() string { return filterList(l).String() }

func (l *valueFilterList) Set(value string) error {
	filterFlag := &valueFilter{}
	if err := filterFlag.Set(value); err != nil {
		return err
	}
	*l = append(*l, rule.FilterSpec(*filterFlag))
	return nil
}

// --- stringList ---

// StringList is a flag type for usage when the parameter has an arity > 1.
type stringList []string

func (l *stringList) String() string {
	return "[" + strings.Join(*l, ", ") + "]"
}

func (l *stringList) Set(value string) error {
	words := strings.Split(value, ",")
	for _, w := range words {
		*l = append(*l, strings.TrimSpace(w))
	}
	return nil
}

// --- addFlag ---

// addFlag is a flag type for appending or prepending a rule.
type addFlag struct {
	List   string
	Action string
}

func (f *addFlag) Set(value string) error {
	parts := strings.Split(value, ",")
	if len(parts) > 2 {
		return fmt.Errorf("expected a list type and action but got '%v'", value)
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "task", "exit", "user", "exclude":
			f.List = part
		case "never", "always":
			f.Action = part
		default:
			return fmt.Errorf("invalid list type or action: '%v'", part)
		}
	}

	if f.List == "" {
		return errors.New("missing list type")
	}
	if f.Action == "" {
		return errors.New("missing action")
	}
	return nil
}

func (f *addFlag) String() string {
	return fmt.Sprintf("%v,%v", f.List, f.Action)
}

// --- fileAccessTypeFlags ---

type fileAccessTypeFlags []rule.AccessType

func (f *fileAccessTypeFlags) Set(value string) error {
	for _, v := range []byte(value) {
		switch v {
		case 'r':
			*f = append(*f, rule.ReadAccessType)
		case 'w':
			*f = append(*f, rule.WriteAccessType)
		case 'x':
			*f = append(*f, rule.ExecuteAccessType)
		case 'a':
			*f = append(*f, rule.AttributeChangeAccessType)
		default:
			return fmt.Errorf("invalid file access type: '%v'", string(v))
		}
	}
	return nil
}

func (f fileAccessTypeFlags) String() string {
	flags := make([]string, 0, len(f))
	for _, accessType := range f {
		flags = append(flags, accessType.String())
	}
	return "[" + strings.Join(flags, "|") + "]"
}
