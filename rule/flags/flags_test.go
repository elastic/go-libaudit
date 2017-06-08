package flags_test

import (
	"testing"

	. "github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"

	"github.com/stretchr/testify/assert"
)

func TestFlagsParse(t *testing.T) {
	tests := []struct {
		flags string
		rule  interface{}
	}{
		{
			"-w /etc/shadow -p wa -k identity",
			&FileWatchRule{
				Type:        FileWatchRuleType,
				Path:        "/etc/shadow",
				Permissions: []AccessType{WriteAccessType, AttributeChangeAccessType},
				Keys:        []string{"identity"},
			},
		},
		{
			"-w /etc/shadow -p cwa", nil,
		},
		{
			"-w /etc/shadow -p wa -k identity -k users",
			&FileWatchRule{
				Type:        FileWatchRuleType,
				Path:        "/etc/shadow",
				Permissions: []AccessType{WriteAccessType, AttributeChangeAccessType},
				Keys:        []string{"identity", "users"},
			},
		},
		{
			"-a always,exit -F path=/etc/shadow -F perm=wa",
			&SyscallRule{
				Type:   AppendSyscallRuleType,
				Action: "always",
				List:   "exit",
				Filters: []FilterSpec{
					{
						Type:       ValueFilterType,
						LHS:        "path",
						Comparator: "=",
						RHS:        "/etc/shadow",
					},
					{
						Type:       ValueFilterType,
						LHS:        "perm",
						Comparator: "=",
						RHS:        "wa",
					},
				},
			},
		},
		{
			"-D",
			&DeleteAllRule{Type: DeleteAllRuleType},
		},
		{
			"-E", nil,
		},
		{
			"-D -a exit,always", nil,
		},
		{
			"-k key", nil,
		},
		{
			"-D -k key",
			&DeleteAllRule{
				Type: DeleteAllRuleType,
				Keys: []string{"key"},
			},
		},
		{
			"-D -D",
			&DeleteAllRule{Type: DeleteAllRuleType},
		},
		{
			"-a exit,always -A task,never", nil,
		},
		{
			"-A always,exit -C auid!=uid",
			&SyscallRule{
				Type:   PrependSyscallRuleType,
				Action: "always",
				List:   "exit",
				Filters: []FilterSpec{
					{
						Type:       InterFieldFilterType,
						LHS:        "auid",
						Comparator: "!=",
						RHS:        "uid",
					},
				},
			},
		},
		{
			"-a exit,always -F auid>=1000",
			&SyscallRule{
				Type:   AppendSyscallRuleType,
				Action: "always",
				List:   "exit",
				Filters: []FilterSpec{
					{
						Type:       ValueFilterType,
						LHS:        "auid",
						Comparator: ">=",
						RHS:        "1000",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		rule, err := flags.Parse(tc.flags)
		if tc.rule == nil {
			if err == nil {
				t.Error("expected error in rule:", tc.flags)
			} else {
				t.Logf("parse error: %v in rule: %v", err, tc.flags)
			}
			continue
		}
		assert.EqualValues(t, tc.rule, rule, "error in %v", tc.flags)
		t.Logf("%+v", tc.flags)
	}
}
