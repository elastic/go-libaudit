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

// +build linux

package libaudit

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// This can be run inside of Docker with:
// docker run -it --rm -v `pwd`:/go/src/github.com/elastic/go-libaudit \
//   --pid=host --privileged golang:1.8.3 /bin/bash

var (
	hexdump = flag.Bool("hexdump", false, "dump kernel responses to stdout in hexdump -C format")
	list    = flag.Bool("l", false, "dump rules")
)

// testRule is a base64 representation of the following rule.
// -a always,exit -S open,truncate -F dir=/etc -F success=0
const testRule = `BAAAAAIAAAACAAAABAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGsAAABoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAvZXRj`

func TestAuditClientGetStatus(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to get audit status")
	}

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Status: %+v", status)
}

func TestAuditClientGetStatusPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("must be non-root to test permission failure")
	}

	status, err := getStatus(t)
	assert.Nil(t, status, "status should be nil")

	// ECONNREFUSED means we are in a username space.
	// EPERM means we are not root.
	if err != syscall.ECONNREFUSED && err != syscall.EPERM {
		t.Fatal("unexpected error")
	}
}

func getStatus(t testing.TB) (*AuditStatus, error) {
	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	return c.GetStatus()
}

func TestDeleteRules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to get audit status")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	n, err := c.DeleteRules()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v rules deleted", n)
}

func TestListRules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to list rules")
	}

	if !*list {
		t.SkipNow()
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rules, err := c.GetRules()
	if err != nil {
		t.Fatal(err)
	}

	for i, rule := range rules {
		b64 := base64.StdEncoding.EncodeToString(rule)
		t.Logf("rule %v - (base64):\n%v", i, b64)
		t.Logf("rule %v - (hexdump):\n%v", i, hex.Dump(rule))
	}
}

func TestAddRule(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to get audit status")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer c.DeleteRules()

	rawRule, _ := base64.StdEncoding.DecodeString(testRule)
	if err := c.AddRule(rawRule); err != nil {
		t.Fatal(err)
	}
	t.Log("rule added")
}

func TestAddDuplicateRule(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to get audit status")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer c.DeleteRules()

	// Add first rule.
	rawRule, _ := base64.StdEncoding.DecodeString(testRule)
	if err := c.AddRule(rawRule); err != nil {
		t.Fatal(err)
	}

	// Add duplicate rule.
	err = c.AddRule(rawRule)
	if err == nil {
		t.Fatal("expected error about duplicate rule")
	}
	assert.Contains(t, err.Error(), "rule exists")
}

func TestAuditClientGetRules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to get audit status")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rules, err := c.GetRules()
	if err != nil {
		t.Fatalf("%+v", err)
	}

	for _, r := range rules {
		fmt.Printf("%+v\n", r)
	}
}

func TestAuditClientSetPID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to set audit pid")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.SetPID(WaitForReply)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SetPID complete")
}

func TestAuditClientSetEnabled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to enable audit")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.SetEnabled(true, WaitForReply)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SetEnabled complete")

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, 1, status.Enabled)
}

func TestAuditClientSetFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to enable audit")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.SetFailure(LogOnFailure, WaitForReply)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SetFailure complete")

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, LogOnFailure, status.Failure)

	err = c.SetFailure(SilentOnFailure, WaitForReply)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SetFailure complete")

	status, err = getStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, SilentOnFailure, status.Failure)
}

func TestAuditClientSetRateLimit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to set rate limit")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var limit uint32 = 1233
	err = c.SetRateLimit(limit, WaitForReply)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SetRateLimit complete")

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, limit, status.RateLimit)
}

func TestAuditClientSetBacklogLimit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to set rate limit")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var limit uint32 = 10002
	err = c.SetBacklogLimit(limit, WaitForReply)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SetBacklogLimit complete")

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, limit, status.BacklogLimit)
}

func TestMulticastAuditClient(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to bind to netlink audit socket")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	// Start the testing.
	client, err := NewMulticastAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Receive (likely no messages will be received).
	var msgCount int
	for i := 0; i < 5; i++ {
		msg, err := client.Receive(true)
		if err == syscall.EAGAIN {
			time.Sleep(500 * time.Millisecond)
			continue
		} else if err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Received: type=%v, msg=%v", msg.Type, string(msg.Data))
			msgCount++
		}
	}
	t.Logf("received %d messages", msgCount)
}

func TestAuditClientReceive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to set audit port id")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	// Open two clients from this process to consume the port ID that's
	// equal to the process ID. The next client will have a random port ID
	// and this will test that the client works properly when two sockets are
	// used.
	observer, err := NewAuditClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()

	if err = observer.SetEnabled(false, WaitForReply); err != nil {
		t.Fatal("failed to disable audit", err)
	}

	defer func() {
		status, err := observer.GetStatus()
		t.Logf("get status: status=%+v, err=%v", status, err)
	}()

	// Start the testing.
	client, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	status, err := client.GetStatus()
	if err != nil {
		t.Fatal("get status failed", err)
	}
	t.Logf("status=%+v, process_id=%v", status, os.Getpid())

	err = client.SetEnabled(true, WaitForReply)
	if err != nil {
		t.Fatal("set enabled failed:", err)
	}

	err = client.SetBacklogLimit(1024, WaitForReply)
	if err != nil {
		t.Fatal("set backlog limit failed:", err)
	}

	err = client.SetPID(WaitForReply)
	if err != nil {
		t.Fatal("set pid failed:", err, " (Did you stop auditd?)")
	}

	// Depending on the kernel version, it will reply with an AUDIT_REPLACE (1329)
	// message, followed by an AUDIT_CONFIG_CHANGE (1305) message, followed
	// by an ACK. Older kernels seem to not send the AUDIT_CONFIG_CHANGE message.
	if err = client.SetPID(WaitForReply); err == nil {
		t.Fatal("set pid failed:", err)
	} else if errors.Cause(err) != syscall.EEXIST {
		t.Fatal("expected second SetPID call to result in EEXISTS but got", err)
	}

	// Expect at least 1 message caused by our previous call (CONFIG_CHANGE).
	var msgCount int
	for i := 0; i < 10; i++ {
		msg, err := client.Receive(true)
		if err == syscall.EAGAIN {
			time.Sleep(500 * time.Millisecond)
			continue
		} else if err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Received: type=%v, msg=%v", msg.Type, string(msg.Data))
			msgCount++
		}
	}
	assert.True(t, msgCount >= 1, "expected at least one messages")
}

func TestAuditStatusMask(t *testing.T) {
	assert.EqualValues(t, 0x0001, AuditStatusEnabled)
	assert.EqualValues(t, 0x0002, AuditStatusFailure)
	assert.EqualValues(t, 0x0004, AuditStatusPID)
	assert.EqualValues(t, 0x0008, AuditStatusRateLimit)
	assert.EqualValues(t, 0x00010, AuditStatusBacklogLimit)
	assert.EqualValues(t, 0x00020, AuditStatusBacklogWaitTime)
}

func TestAuditWaitForPendingACKs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to change settings")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	c, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Perform some asynchronous requests

	var limit uint32 = 10002
	if err = c.SetBacklogLimit(limit, NoWait); err != nil {
		t.Fatal(err, "set backlog limit failed:", err)
	}

	failureMode := PanicOnFailure
	if err = c.SetFailure(failureMode, NoWait); err != nil {
		t.Fatal(err, "set failure mode failed:", err)
	}

	// Wait for completion

	if err = c.WaitForPendingACKs(); err != nil {
		t.Fatal(err, "wait for pending ACKs failed:", err)
	}

	// Perform synchronous request

	if err = c.SetPID(WaitForReply); err != nil {
		t.Fatal("set pid failed:", err, " (Did you stop auditd?)")
	}

	t.Log("WaitForPendingACKs complete")

}
