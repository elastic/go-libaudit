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

package aucoalesce

import "github.com/elastic/go-libaudit/v2/auparse"

// AuditEventType is a categorization of a simple or compound audit event.
type AuditEventType uint16

const (
	EventTypeUnknown AuditEventType = iota
	EventTypeUserspace
	EventTypeSystemServices
	EventTypeConfig
	EventTypeTTY
	EventTypeUserAccount
	EventTypeUserLogin
	EventTypeAuditDaemon
	EventTypeMACDecision
	EventTypeAnomaly
	EventTypeIntegrity
	EventTypeAnomalyResponse
	EventTypeMAC
	EventTypeCrypto
	EventTypeVirt
	EventTypeAuditRule
	EventTypeDACDecision
	EventTypeGroupChange
)

var auditEventTypeNames = map[AuditEventType]string{
	EventTypeUnknown:         "unknown",
	EventTypeUserspace:       "user-space",
	EventTypeSystemServices:  "system-services",
	EventTypeConfig:          "configuration",
	EventTypeTTY:             "TTY",
	EventTypeUserAccount:     "user-account",
	EventTypeUserLogin:       "user-login",
	EventTypeAuditDaemon:     "audit-daemon",
	EventTypeMACDecision:     "mac-decision",
	EventTypeAnomaly:         "anomaly",
	EventTypeIntegrity:       "integrity",
	EventTypeAnomalyResponse: "anomaly-response",
	EventTypeMAC:             "mac",
	EventTypeCrypto:          "crypto",
	EventTypeVirt:            "virt",
	EventTypeAuditRule:       "audit-rule",
	EventTypeDACDecision:     "dac-decision",
	EventTypeGroupChange:     "group-change",
}

func (t AuditEventType) String() string {
	name, found := auditEventTypeNames[t]
	if found {
		return name
	}
	return auditEventTypeNames[EventTypeUnknown]
}

func (t AuditEventType) MarshalText() (text []byte, err error) {
	return []byte(t.String()), nil
}

func GetAuditEventType(t auparse.AuditMessageType) AuditEventType {
	// Ported from: https://github.com/linux-audit/audit-userspace/blob/v2.7.5/auparse/normalize.c#L681
	switch {
	case t >= auparse.AUDIT_USER_AUTH && t <= auparse.AUDIT_USER_END,
		t >= auparse.AUDIT_USER_CHAUTHTOK && t <= auparse.AUDIT_CRED_REFR,
		t >= auparse.AUDIT_USER_LOGIN && t <= auparse.AUDIT_USER_LOGOUT,
		t == auparse.AUDIT_GRP_AUTH:
		return EventTypeUserLogin
	case t >= auparse.AUDIT_ADD_USER && t <= auparse.AUDIT_DEL_GROUP,
		t >= auparse.AUDIT_GRP_MGMT && t <= auparse.AUDIT_GRP_CHAUTHTOK,
		t >= auparse.AUDIT_ACCT_LOCK && t <= auparse.AUDIT_ACCT_UNLOCK:
		return EventTypeUserAccount
	case t == auparse.AUDIT_KERNEL,
		t >= auparse.AUDIT_SYSTEM_BOOT && t <= auparse.AUDIT_SERVICE_STOP:
		return EventTypeSystemServices
	case t == auparse.AUDIT_USYS_CONFIG,
		t == auparse.AUDIT_CONFIG_CHANGE,
		t == auparse.AUDIT_NETFILTER_CFG,
		t >= auparse.AUDIT_FEATURE_CHANGE && t <= auparse.AUDIT_REPLACE:
		return EventTypeConfig
	case t == auparse.AUDIT_SECCOMP:
		return EventTypeDACDecision
	case t >= auparse.AUDIT_CHGRP_ID && t <= auparse.AUDIT_TRUSTED_APP,
		t == auparse.AUDIT_USER_CMD,
		t == auparse.AUDIT_CHUSER_ID:
		return EventTypeUserspace
	case t == auparse.AUDIT_USER_TTY, t == auparse.AUDIT_TTY:
		return EventTypeTTY
	case t >= auparse.AUDIT_DAEMON_START && t <= auparse.AUDIT_LAST_DAEMON:
		return EventTypeAuditDaemon
	case t == auparse.AUDIT_USER_SELINUX_ERR,
		t == auparse.AUDIT_USER_AVC,
		t >= auparse.AUDIT_APPARMOR_ALLOWED && t <= auparse.AUDIT_APPARMOR_DENIED,
		t == auparse.AUDIT_APPARMOR_ERROR,
		t >= auparse.AUDIT_AVC && t <= auparse.AUDIT_AVC_PATH:
		return EventTypeMACDecision
	case t >= auparse.AUDIT_INTEGRITY_DATA && t <= auparse.AUDIT_INTEGRITY_LAST_MSG,
		t == auparse.AUDIT_ANOM_RBAC_INTEGRITY_FAIL:
		return EventTypeIntegrity
	case t >= auparse.AUDIT_ANOM_PROMISCUOUS && t <= auparse.AUDIT_LAST_KERN_ANOM_MSG,
		t >= auparse.AUDIT_ANOM_LOGIN_FAILURES && t <= auparse.AUDIT_ANOM_RBAC_FAIL,
		t >= auparse.AUDIT_ANOM_CRYPTO_FAIL && t <= auparse.AUDIT_LAST_ANOM_MSG:
		return EventTypeAnomaly
	case t >= auparse.AUDIT_RESP_ANOMALY && t <= auparse.AUDIT_LAST_ANOM_RESP:
		return EventTypeAnomalyResponse
	case t >= auparse.AUDIT_MAC_POLICY_LOAD && t <= auparse.AUDIT_LAST_SELINUX,
		t >= auparse.AUDIT_AA && t <= auparse.AUDIT_APPARMOR_AUDIT,
		t >= auparse.AUDIT_APPARMOR_HINT && t <= auparse.AUDIT_APPARMOR_STATUS,
		t >= auparse.AUDIT_USER_ROLE_CHANGE && t <= auparse.AUDIT_LAST_USER_LSPP_MSG:
		return EventTypeMAC
	case t >= auparse.AUDIT_FIRST_KERN_CRYPTO_MSG && t <= auparse.AUDIT_LAST_KERN_CRYPTO_MSG,
		t >= auparse.AUDIT_CRYPTO_TEST_USER && t <= auparse.AUDIT_LAST_CRYPTO_MSG:
		return EventTypeCrypto
	case t >= auparse.AUDIT_VIRT_CONTROL && t <= auparse.AUDIT_LAST_VIRT_MSG:
		return EventTypeVirt
	case t >= auparse.AUDIT_SYSCALL && t <= auparse.AUDIT_SOCKETCALL,
		t >= auparse.AUDIT_SOCKADDR && t <= auparse.AUDIT_MQ_GETSETATTR,
		t >= auparse.AUDIT_FD_PAIR && t <= auparse.AUDIT_OBJ_PID,
		t >= auparse.AUDIT_BPRM_FCAPS && t <= auparse.AUDIT_NETFILTER_PKT:
		return EventTypeAuditRule
	default:
		return EventTypeUnknown
	}
}
