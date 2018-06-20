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
	"math"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/go-libaudit/auparse"
)

func TestBuild(t *testing.T) {
	r := &SyscallRule{
		Type:     AppendSyscallRuleType,
		List:     "exit",
		Action:   "always",
		Syscalls: []string{"connect"},
		Filters: []FilterSpec{
			{
				Type:       ValueFilterType,
				LHS:        "auid",
				Comparator: "!=",
				RHS:        "0",
			},
		},
	}

	wireFormat, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, wireFormat)
}

func TestAddFlag(t *testing.T) {
	t.Run("exit", func(t *testing.T) {
		rule := &ruleData{}
		assert.NoError(t, rule.setList("exit"))
		assert.EqualValues(t, exitFilter, rule.flags)
	})

	t.Run("task", func(t *testing.T) {
		rule := &ruleData{}
		assert.NoError(t, rule.setList("task"))
		assert.EqualValues(t, taskFilter, rule.flags)
	})

	t.Run("user", func(t *testing.T) {
		rule := &ruleData{}
		assert.NoError(t, rule.setList("user"))
		assert.EqualValues(t, userFilter, rule.flags)
	})

	t.Run("exclude", func(t *testing.T) {
		rule := &ruleData{}
		assert.NoError(t, rule.setList("exclude"))
		assert.EqualValues(t, excludeFilter, rule.flags)
	})

	t.Run("invalid", func(t *testing.T) {
		rule := &ruleData{}
		assert.Error(t, rule.setList("invalid"))
	})
}

func TestAddAction(t *testing.T) {
	t.Run("always", func(t *testing.T) {
		rule := &ruleData{}
		assert.NoError(t, rule.setAction("always"))
		assert.EqualValues(t, alwaysAction, rule.action)
	})

	t.Run("never", func(t *testing.T) {
		rule := &ruleData{}
		assert.NoError(t, rule.setAction("never"))
		assert.EqualValues(t, neverAction, rule.action)
	})

	t.Run("invalid", func(t *testing.T) {
		rule := &ruleData{}
		assert.Error(t, rule.setAction("invalid"))
	})
}

func TestAddSyscall(t *testing.T) {
	t.Run("all", func(t *testing.T) {
		rule := &ruleData{}
		if err := addSyscall(rule, "all"); err != nil {
			t.Fatal(err)
		}
		assert.True(t, rule.allSyscalls)
	})

	t.Run("unknown", func(t *testing.T) {
		rule := &ruleData{}
		err := addSyscall(rule, "unknown")
		assert.Error(t, err)
	})

	t.Run("open", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip("requires amd64")
		}
		const openSyscallNum = 2
		rule := &ruleData{}
		if err := addSyscall(rule, "open"); err != nil {
			t.Fatal(err)
		}
		if assert.Len(t, rule.syscalls, 1) {
			assert.EqualValues(t, openSyscallNum, rule.syscalls[0])
		}
	})
}

func TestAddFilter(t *testing.T) {
	t.Run("invalid operator", func(t *testing.T) {
		err := addFilter(&ruleData{}, "auid", "%", "0")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid operator")
		}
	})

	t.Run("invalid lhs", func(t *testing.T) {
		err := addFilter(&ruleData{}, "foobar", "=", "0")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "invalid field")
		}
	})

	t.Run("disallow_exclude", func(t *testing.T) {
		rule := &ruleData{flags: excludeFilter}
		err := addFilter(rule, "perm", "=", "wa")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "cannot be used")
		}
	})

	t.Run("uid", func(t *testing.T) {
		rule := &ruleData{}
		if err := addFilter(rule, "uid", ">", "1000"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, uidField, rule.fields[0])
		assert.EqualValues(t, greaterThanOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 1000, rule.values[0])
	})
	t.Run("auid_name", func(t *testing.T) {
		rule := &ruleData{}
		if err := addFilter(rule, "auid", "=", "root"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, auidField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 0, rule.values[0])
	})

	t.Run("gid", func(t *testing.T) {
		rule := &ruleData{}
		if err := addFilter(rule, "gid", "<=", "500"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, gidField, rule.fields[0])
		assert.EqualValues(t, lessThanOrEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 500, rule.values[0])
	})
	t.Run("egid", func(t *testing.T) {
		group, err := user.LookupGroupId("0")
		if err != nil {
			t.Fatal(err)
		}

		rule := &ruleData{}
		if err := addFilter(rule, "egid", "=", group.Name); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, egidField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 0, rule.values[0])
	})

	t.Run("exit", func(t *testing.T) {
		rule := &ruleData{flags: exitFilter}
		if err := addFilter(rule, "exit", "!=", "2"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, exitField, rule.fields[0])
		assert.EqualValues(t, notEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, 2, rule.values[0])
	})

	t.Run("exit_negative", func(t *testing.T) {
		rule := &ruleData{flags: exitFilter}
		if err := addFilter(rule, "exit", "!=", "-1"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, exitField, rule.fields[0])
		assert.EqualValues(t, notEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, -1, rule.values[0])
	})

	t.Run("exit_named", func(t *testing.T) {
		rule := &ruleData{flags: exitFilter}
		if err := addFilter(rule, "exit", "!=", "EPERM"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, exitField, rule.fields[0])
		assert.EqualValues(t, notEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, int(syscall.EPERM), rule.values[0])
	})

	t.Run("exit_named_negative", func(t *testing.T) {
		rule := &ruleData{flags: exitFilter}
		if err := addFilter(rule, "exit", "!=", "-EPERM"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, exitField, rule.fields[0])
		assert.EqualValues(t, notEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, -1*int(syscall.EPERM), rule.values[0])
	})

	t.Run("msgtype", func(t *testing.T) {
		t.Run("exit", func(t *testing.T) {
			rule := &ruleData{flags: exitFilter}
			if err := addFilter(rule, "msgtype", "=", "EXECVE"); err == nil {
				t.Fatal("expected error")
			}
		})

		t.Run("user", func(t *testing.T) {
			rule := &ruleData{flags: userFilter}
			if err := addFilter(rule, "msgtype", "=", "EXECVE"); err != nil {
				t.Fatal(err)
			}
			assert.EqualValues(t, msgTypeField, rule.fields[0])
			assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
			assert.EqualValues(t, auparse.AUDIT_EXECVE, rule.values[0])
		})

		t.Run("exclude", func(t *testing.T) {
			rule := &ruleData{flags: excludeFilter}
			if err := addFilter(rule, "msgtype", "=", "1309"); err != nil {
				t.Fatal(err)
			}
			assert.EqualValues(t, msgTypeField, rule.fields[0])
			assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
			assert.EqualValues(t, auparse.AUDIT_EXECVE, rule.values[0])
		})

		t.Run("unknown", func(t *testing.T) {
			rule := &ruleData{flags: excludeFilter}
			if err := addFilter(rule, "msgtype", "=", "UNKNOWN"); err == nil {
				t.Fatal("expected error")
			}
		})
	})

	t.Run("path", func(t *testing.T) {
		const etcPasswd = "/etc/passwd"
		rule := &ruleData{flags: exitFilter}
		if err := addFilter(rule, "path", "=", etcPasswd); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, pathField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, etcPasswd, rule.strings[0])
	})

	t.Run("key_too_long", func(t *testing.T) {
		rule := &ruleData{}
		if err := addFilter(rule, "key", "=", strings.Repeat("x", maxKeyLength)); err != nil {
			t.Fatal(err)
		}
		if err := addFilter(rule, "key", "=", strings.Repeat("x", maxKeyLength+1)); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("exe", func(t *testing.T) {
		const sudo = "/usr/bin/sudo"
		rule := &ruleData{}
		if err := addFilter(rule, "exe", "=", sudo); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, exeField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, sudo, rule.strings[0])
	})

	t.Run("arch_b32", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip("arch test expects amd64")
		}
		rule := &ruleData{}
		if err := addFilter(rule, "arch", "=", "b32"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, archField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, auparse.AUDIT_ARCH_I386, rule.values[0])
	})

	t.Run("arch_b64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip("arch test expects amd64")
		}
		rule := &ruleData{}
		if err := addFilter(rule, "arch", "=", "b64"); err != nil {
			t.Fatalf("%+v", err)
		}
		assert.EqualValues(t, archField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, auparse.AUDIT_ARCH_X86_64, rule.values[0])
	})

	t.Run("perm", func(t *testing.T) {
		rule := &ruleData{flags: exitFilter}
		if err := addFilter(rule, "perm", "=", "wa"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, permField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, writePerm|attrPerm, rule.values[0])
	})

	t.Run("filetype", func(t *testing.T) {
		rule := &ruleData{flags: exitFilter}
		if err := addFilter(rule, "filetype", "=", "dir"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, filetypeField, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, dirFiletype, rule.values[0])
	})

	t.Run("arg_max_uint32", func(t *testing.T) {
		rule := &ruleData{}
		if err := addFilter(rule, "a3", "=", strconv.FormatUint(math.MaxUint32, 10)); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, arg3Field, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, uint32(math.MaxUint32), rule.values[0])
	})

	t.Run("arg_min_int32", func(t *testing.T) {
		rule := &ruleData{}
		if err := addFilter(rule, "a3", "=", strconv.FormatInt(math.MinInt32, 10)); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, arg3Field, rule.fields[0])
		assert.EqualValues(t, equalOperator, rule.fieldFlags[0])
		assert.EqualValues(t, math.MinInt32, rule.values[0])
	})
}

func TestAddInterFieldComparator(t *testing.T) {
	t.Run("auid!=obj_uid", func(t *testing.T) {
		rule := &ruleData{}
		if err := addInterFieldComparator(rule, "auid", "!=", "obj_uid"); err != nil {
			t.Fatal(err)
		}
		assert.EqualValues(t, fieldCompare, rule.fields[0])
		assert.EqualValues(t, notEqualOperator, rule.fieldFlags[0])
		assert.EqualValues(t, _AUDIT_COMPARE_AUID_TO_OBJ_UID, rule.values[0])
	})
}
