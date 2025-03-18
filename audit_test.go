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

//go:build linux
// +build linux

package libaudit

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/elastic/go-libaudit/v2/sys"
)

// This can be run inside of Docker with:
// docker run -it --rm -v `pwd`:/go/src/github.com/elastic/go-libaudit --pid=host --privileged golang:1.10.2 /bin/bash

var (
	hexdump   = flag.Bool("hexdump", false, "dump kernel responses to stdout in hexdump -C format")
	list      = flag.Bool("l", false, "dump rules")
	immutable = flag.Bool("immutable", false, "test setting kernel as immutable (requires reboot to undo)")
)

// testRule is a base64 representation of the following rule.
// -a always,exit -S open,truncate -F dir=/etc -F success=0
const testRule = `BAAAAAIAAAACAAAABAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGsAAABoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAvZXRj`

// TestNetlinkIface is a mock interface for testing close behavior
type TestNetlinkIface struct {
	recvStack []error
	sendStack []error
}

func (*TestNetlinkIface) Close() error {
	return nil
}

func (tn *TestNetlinkIface) Send(_ syscall.NetlinkMessage) (uint32, error) {
	top := tn.sendStack[0]
	tn.sendStack = slices.Delete(tn.sendStack, 0, 1)
	return 0, top
}

func (tn *TestNetlinkIface) SendNoWait(_ syscall.NetlinkMessage) (uint32, error) {
	top := tn.sendStack[0]
	tn.sendStack = slices.Delete(tn.sendStack, 0, 1)
	return 0, top
}

func (tn *TestNetlinkIface) Receive(_ bool, _ NetlinkParser) ([]syscall.NetlinkMessage, error) {
	top := tn.recvStack[0]
	tn.recvStack = slices.Delete(tn.recvStack, 0, 1)
	return nil, top
}

func TestCloseBehavior(t *testing.T) {
	testCases := []struct {
		name string
		cfg  *TestNetlinkIface
		err  error
	}{
		{
			name: "retry",
			cfg: &TestNetlinkIface{
				// cause the first send to error out
				sendStack: []error{syscall.EWOULDBLOCK, nil, nil},
				// force the close logic to drain
				recvStack: []error{syscall.ENOBUFS, syscall.ENOBUFS, syscall.EAGAIN},
			},
			err: nil,
		},
		{
			name: "repeated-send-fail",
			cfg: &TestNetlinkIface{
				// cause the first send to error out
				sendStack: []error{syscall.EWOULDBLOCK, syscall.EWOULDBLOCK, syscall.EWOULDBLOCK, nil},
				// force the close logic to drain
				recvStack: []error{syscall.EWOULDBLOCK, syscall.EWOULDBLOCK, nil, syscall.EWOULDBLOCK, nil, syscall.EWOULDBLOCK, nil},
			},
			err: nil,
		},
		{
			name: "transient-eintr-send",
			cfg: &TestNetlinkIface{
				// cause the first send to error out
				sendStack: []error{syscall.EINTR, nil, nil},
				// force the close logic to drain
				recvStack: []error{syscall.EAGAIN},
			},
			err: nil,
		},
		{
			name: "fail-recv-error",
			cfg: &TestNetlinkIface{
				// cause the first send to error out
				sendStack: []error{syscall.EWOULDBLOCK, nil, nil},
				// force the close logic to drain
				recvStack: []error{syscall.ENOBUFS, syscall.ENOBUFS, syscall.EBADFD},
			},
			err: syscall.EBADFD,
		},
		{
			name: "fail-send-error",
			cfg: &TestNetlinkIface{
				// cause the first send to error out
				sendStack: []error{syscall.EWOULDBLOCK, syscall.EBADFD, nil},
				// force the close logic to drain
				recvStack: []error{syscall.EAGAIN, syscall.EAGAIN},
			},
			err: syscall.EBADFD,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testClient := AuditClient{
				Netlink:         test.cfg,
				pendingAcks:     []uint32{},
				clearPIDOnClose: true,
				closeOnce:       sync.Once{},
			}

			err := testClient.Close()
			require.True(t, errors.Is(err, test.err), "expected error %s", test.err)
		})
	}
}

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
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.EPERM) {
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
	if sys.GetEndian() != binary.LittleEndian {
		t.Skip("testRule is for little endian, but test machine is big endian")
	}

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
	defer deleteRules(t, c)

	rawRule, _ := base64.StdEncoding.DecodeString(testRule)
	if err := c.AddRule(rawRule); err != nil {
		t.Fatal(err)
	}
	t.Log("rule added")
}

func TestAddDuplicateRule(t *testing.T) {
	if sys.GetEndian() != binary.LittleEndian {
		t.Skip("testRule is for little endian, but test machine is big endian")
	}

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
	defer deleteRules(t, c)

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

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	if status.FeatureBitmap&AuditFeatureBitmapBacklogLimit == 0 {
		t.Skip("backlog limit feature not supported in current kernel")
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

	status, err = getStatus(t)
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
		if errors.Is(err, syscall.EAGAIN) {
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

	kMajor, kMinor, err := kernelVersion()
	if err != nil {
		t.Fatal("get kernel version failed:", err)
	}
	// Setting a new PID when an audit process is already registered only fails
	// in Linux kernel version 4.11 and up.
	if kMajor > 4 || kMajor == 4 && kMinor >= 11 {
		// Depending on the kernel version, it will reply with an AUDIT_REPLACE (1329)
		// message, followed by an AUDIT_CONFIG_CHANGE (1305) message, followed
		// by an ACK. Older kernels seem to not send the AUDIT_CONFIG_CHANGE message.
		if err = client.SetPID(WaitForReply); err == nil {
			t.Fatal("set pid (overwrite) didn't fail as expected.")
		} else if !errors.Is(err, syscall.EEXIST) {
			t.Fatal("expected second SetPID call to result in EEXISTS but got", err)
		}
	}

	// Expect at least 1 message caused by our previous call (CONFIG_CHANGE).
	var msgCount int
	for i := 0; i < 10; i++ {
		msg, err := client.Receive(true)
		if errors.Is(err, syscall.EAGAIN) {
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

func TestAuditClientClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to set audit port id")
	}

	var dumper io.WriteCloser
	if *hexdump {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	// Open a secondary client to verify that audit PID value.
	observer, err := NewAuditClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()

	// Start the testing.
	client, err := NewAuditClient(dumper)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	err = client.SetPID(WaitForReply)
	if err != nil {
		t.Fatal("set pid failed:", err, " (Did you stop auditd?)")
	}

	// Validate the PID.
	status, err := observer.GetStatus()
	if err != nil {
		t.Fatal("failed to get audit status", err)
	}
	assert.NotZero(t, status.PID)

	// Close will clear the PID to 0.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	// Validate the PID is cleared.
	status, err = observer.GetStatus()
	if err != nil {
		t.Fatal("failed to get audit status", err)
	}
	assert.EqualValues(t, 0, status.PID)
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

func TestAuditClientSetBacklogWaitTime(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to set backlog wait time")
	}

	status, err := getStatus(t)
	if err != nil || status == nil {
		t.Skipf("audit status not available: %v", err)
	}
	if status.FeatureBitmap&AuditFeatureBitmapBacklogWaitTime == 0 {
		t.Skip("backlog wait time feature not supported in current kernel")
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

	for _, waitValue := range []int32{0, 500} {
		msg := fmt.Sprintf("[wait time = %d]", waitValue)
		err = c.SetBacklogWaitTime(waitValue, WaitForReply)
		if err != nil {
			t.Fatal(err, msg)
		}
		t.Log("SetBacklogWaitTime complete", msg)

		status, err := getStatus(t)
		if err != nil {
			t.Fatal(err, msg)
		}
		assert.EqualValues(t, waitValue, status.BacklogWaitTime, msg)
	}
}

func TestAuditFeatureBitmap(t *testing.T) {
	assert.EqualValues(t, 0x01, AuditFeatureBitmapBacklogLimit)
	assert.EqualValues(t, 0x02, AuditFeatureBitmapBacklogWaitTime)
	assert.EqualValues(t, 0x04, AuditFeatureBitmapExecutablePath)
	assert.EqualValues(t, 0x08, AuditFeatureBitmapExcludeExtend)
	assert.EqualValues(t, 0x10, AuditFeatureBitmapSessionIDFilter)
	assert.EqualValues(t, 0x20, AuditFeatureBitmapLostReset)
}

func TestAuditClientGetStatusAsync(t *testing.T) {
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

	for _, withACK := range []bool{true, false} {
		seq, err := c.GetStatusAsync(withACK)
		if err != nil {
			t.Fatal(err)
		}

		if withACK {
			// Get the ack message which is a NLMSG_ERROR type whose error code is SUCCESS.
			ack, err := c.getReply(seq)
			if err != nil {
				t.Fatal(err)
			}

			if ack.Header.Type != syscall.NLMSG_ERROR {
				t.Fatalf("unexpected ACK to GET, got type=%d", ack.Header.Type)
			}

			if err = ParseNetlinkError(ack.Data); err != nil {
				t.Fatal(err)
			}
		}

		reply, err := c.getReply(seq)
		if err != nil {
			t.Fatal(err)
		}

		if reply.Header.Type != AuditGet {
			t.Fatalf("unexpected reply to GET, got type=%d", reply.Header.Type)
		}

		replyStatus := &AuditStatus{}
		if err := replyStatus.FromWireFormat(reply.Data); err != nil {
			t.Fatal(err)
		}

		t.Logf("Status: %+v", replyStatus)
	}
}

func TestAuditStatusRoundTrip(t *testing.T) {
	err := quick.Check(func(a AuditStatus) bool {
		buf := a.toWireFormat()
		var new AuditStatus
		err := new.FromWireFormat(buf)
		if err != nil {
			t.Log(err)
			return false
		}
		return a == new
	}, nil)
	assert.NoError(t, err, "audit status failed round-trip")
}

func TestAuditClientSetImmutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must be root to enable audit")
	}
	if !*immutable {
		t.Skip("use -immutable to test SetImmutable")
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

	err = c.SetImmutable(WaitForReply)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SetImmutable complete")

	status, err := getStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	assert.EqualValues(t, 2, status.Enabled)
}

func TestValidRuleParsing(t *testing.T) {
	var rules []string
	switch runtime.GOARCH {
	case "386":
		rules = []string{
			"-a always,exit -F arch=b32 -S execve,execveat -F key=exec",
			"-a never,exit -F arch=b32 -S bind,connect,accept4 -F key=external-access",
			"-w /etc/group -p wa",
			"-w /etc/passwd -p rx",
			"-w /etc/gshadow -p rwxa",
			"-w /tmp/test -p rwa",
			"-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F key=access",
			"-a never,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F key=access",
			"-a always,exit -F arch=b32 -S open -F key=admin -F uid=root -F gid=root -F exit=33 -F path=/tmp -F perm=rwxa",
			"-a always,exit -F arch=b32 -S open -F key=key -F uid=30000 -F gid=333 -F exit=-151111 -F filetype=fifo",
			"-a never,exclude -F msgtype=GRP_CHAUTHTOK",
			"-a always,user -F uid=root",
			"-a always,task -F uid=root",
			"-a always,exit -S mount -F pid=1234",
		}
	case "amd64":
		rules = []string{
			"-a always,exit -F arch=b64 -S execve,execveat -F key=exec",
			"-a never,exit -F arch=b64 -S connect,accept,bind -F key=external-access",
			"-w /etc/group -p wa",
			"-w /etc/passwd -p rx",
			"-w /etc/gshadow -p rwxa",
			"-w /tmp/test -p rwa",
			"-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F key=access",
			"-a never,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F key=access",
			"-a always,exit -F arch=b32 -S open -F key=admin -F uid=root -F gid=root -F exit=33 -F path=/tmp -F perm=rwxa",
			"-a always,exit -F arch=b64 -S open -F key=key -F uid=30000 -F gid=333 -F exit=-151111 -F filetype=fifo",
			"-a never,exclude -F msgtype=GRP_CHAUTHTOK",
			"-a always,user -F uid=root",
			"-a always,task -F uid=root",
			"-a always,exit -S mount -F pid=1234",
			"-d always,exit -F arch=b64 -S execve,execveat -F key=exec",
			"-d never,exit -F arch=b64 -S connect,accept,bind -F key=external-access",
			"-W /etc/group -p wa",
			"-W /etc/passwd -p rx",
			"-W /etc/gshadow -p rwxa",
			"-W /tmp/test -p rwa",
			"-d always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F key=access",
			"-d never,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F key=access",
			"-d always,exit -F arch=b32 -S open -F key=admin -F uid=root -F gid=root -F exit=33 -F path=/tmp -F perm=rwxa",
			"-d always,exit -F arch=b64 -S open -F key=key -F uid=30000 -F gid=333 -F exit=-151111 -F filetype=fifo",
			"-d never,exclude -F msgtype=GRP_CHAUTHTOK",
			"-d always,user -F uid=root",
			"-d always,task -F uid=root",
			"-d always,exit -S mount -F pid=1234",
		}
	default:
		// Can't have multiple syscall testing as ordering of individual syscalls
		// will vary between platforms (sorted by syscall id)
		rules = []string{
			"-a always,exit -S execve -F key=exec",
			"-w /etc/group -p wa",
			"-w /etc/passwd -p rx",
			"-w /etc/gshadow -p rwxa",
			"-w /tmp/test -p rwa",
			"-a always,exit -S all -F exit=-EACCES -F key=access",
			"-a never,exit -S all -F exit=-EPERM -F key=access",
			"-a always,exit -S open -F key=admin -F uid=root -F gid=root -F exit=33 -F path=/tmp -F perm=rwxa",
			"-a always,exit -S open -F key=key -F uid=30000 -F gid=333 -F exit=-151111 -F filetype=fifo",
			"-a never,exclude -F msgtype=GRP_CHAUTHTOK",
			"-a always,user -F uid=root",
			"-a always,task -F uid=root",
			"-a always,exit -S mount -F pid=1234",
			"-d always,exit -S execve -F key=exec",
			"-W /etc/group -p wa",
			"-W /etc/passwd -p rx",
			"-W /etc/gshadow -p rwxa",
			"-W /tmp/test -p rwa",
			"-d always,exit -S all -F exit=-EACCES -F key=access",
			"-d never,exit -S all -F exit=-EPERM -F key=access",
			"-d always,exit -S open -F key=admin -F uid=root -F gid=root -F exit=33 -F path=/tmp -F perm=rwxa",
			"-d always,exit -S open -F key=key -F uid=30000 -F gid=333 -F exit=-151111 -F filetype=fifo",
			"-d never,exclude -F msgtype=GRP_CHAUTHTOK",
			"-d always,user -F uid=root",
			"-d always,task -F uid=root",
			"-d always,exit -S mount -F pid=1234",
		}
	}
	t.Logf("checking %d rules", len(rules))
	for idx, line := range rules {
		msg := fmt.Sprintf("parsing line #%d: `%s`", idx, line)
		r, err := flags.Parse(line)
		if err != nil {
			t.Fatal(err, msg)
		}
		data, err := rule.Build(r)
		if err != nil {
			t.Fatal(err, msg)
		}
		addRule := true
		switch r.TypeOf() {
		case rule.DeleteFileWatchRuleType, rule.DeleteSyscallRuleType:
			addRule = false
		}
		cmdline, err := rule.ToCommandLineAddRemove(data, true, addRule)
		if err != nil {
			t.Fatal(err, msg)
		}
		assert.Equal(t, line, cmdline, msg)
	}
}

func TestInvalidRuleParsing(t *testing.T) {
	rules := []string{
		"-D -a",
		"-D -A",
		"-D -d",

		"-D -a always",
		"-D -A always",
		"-D -d always",

		"-D -a never",
		"-D -A never",
		"-D -d never",

		"-D -a always,task",
		"-D -A always,task",
		"-D -d always,task",

		"-D -a always,task -w /foo/bar -p rw",
		"-D -a always,task -W /foo/bar -p rw",
		"-D -A always,task -w /foo/bar -p rw",
		"-D -A always,task -W /foo/bar -p rw",
		"-D -d always,task -w /foo/bar -p rw",
		"-D -d always,task -W /foo/bar -p rw",

		"-D -a never,task",
		"-D -A never,task",
		"-D -d never,task",

		"-D -w /foo/bar",
		"-D -W /foo/bar",
		"-D -w /foo/bar -p rw",
		"-D -W /foo/bar -p rw",
		"-D -w /foo/bar -p garbage",
		"-D -W /foo/bar -p garbage",

		"-w /foo/bar -W /foo/bar",
		"-w /foo/bar -W /foo/bar -p rw",

		"-w foo/bar",
		"-W foo/bar",
		"-w foo/bar -p rw",
		"-W foo/bar -p rw",

		"-w foo/bar -S 42",
		"-W foo/bar -S 42",

		"-w foo/bar -W foo/bar",
		"-w foo/bar -W foo/bar -p rw",

		"-w foo/bar -W foo/bar -S 42",

		"-w /foo/bar -F uid=100",
		"-W /foo/bar -F uid=100",

		"-w /foo/bar -S 42",
		"-W /foo/bar -S 42",

		"-w /foo/bar -F uid=100",
		"-W /foo/bar -F uid=100",

		"-w /foo/bar -C auid!=uid",
		"-W /foo/bar -C auid!=uid",

		"-a always,exit -w /foo/bar -p rw",
		"-a always,exit -W /foo/bar -p rw",
		"-A always,exit -w /foo/bar -p rw",
		"-A always,exit -W /foo/bar -p rw",

		"-a always,exit -w /foo/bar",
		"-a always,exit -W /foo/bar",
		"-A always,exit -w /foo/bar",
		"-A always,exit -W /foo/bar",
	}

	t.Logf("checking %d rules", len(rules))
	for idx, line := range rules {
		r, err := flags.Parse(line)
		if err != nil {
			t.Log(err)
			continue
		}

		_, err = rule.Build(r)
		if err != nil {
			t.Log(err)
			continue
		}

		t.Errorf("parsing line #%d: `%s' should have failed", idx, line)
	}
}

func extractDecimalNumber(s []int8, pos int) (value, nextPos int) {
	for value = 0; ; pos++ {
		c := s[pos]
		if '0' <= c && c <= '9' {
			value = value*10 + int(c-'0')
			continue
		}
		return value, pos + 1
	}
}

func kernelVersion() (major, minor int, err error) {
	var info syscall.Utsname
	if err = syscall.Uname(&info); err != nil {
		return 0, 0, err
	}
	s := info.Release[:]
	// As all major non-Intel architecture return []uint8 instead of []int8 for Utsname.Release following conversion is required
	temp := make([]int8, len(s))
	for index, num := range s {
		temp[index] = num
	}

	major, pos := extractDecimalNumber(temp, 0)
	minor, _ = extractDecimalNumber(temp, pos)
	return major, minor, nil
}

func deleteRules(t testing.TB, client *AuditClient) {
	t.Helper()

	if _, err := client.DeleteRules(); err != nil {
		t.Errorf("failed to delete rules: %v", err)
	}
}
