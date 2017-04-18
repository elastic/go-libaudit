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
	"encoding/hex"
	"flag"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var hexdump = flag.Bool("hexdump", false, "dump kernel responses to stdout in hexdump -C format")

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
	assert.Equal(t, syscall.EPERM, err)
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
	err = client.SetPID(NoWait)
	if err != nil {
		t.Fatal("set pid failed:", err)
	}

	// Expect at least 2 messages caused by our previous call.
	var msgCount int
	for i := 0; i < 10; i++ {
		msg, err := client.Receive(true)
		if err == syscall.EAGAIN {
			time.Sleep(500 * time.Millisecond)
			continue
		} else if err != nil {
			t.Fatal(err)
		} else {
			t.Logf("Received: type=%v, msg=%v", msg.MessageType, string(msg.RawData))
			msgCount++
		}
	}
	assert.True(t, msgCount >= 2, "expected at least two messages")
}

func TestAuditStatusMask(t *testing.T) {
	assert.EqualValues(t, 0x0001, AuditStatusEnabled)
	assert.EqualValues(t, 0x0002, AuditStatusFailure)
	assert.EqualValues(t, 0x0004, AuditStatusPID)
	assert.EqualValues(t, 0x0008, AuditStatusRateLimit)
	assert.EqualValues(t, 0x00010, AuditStatusBacklogLimit)
	assert.EqualValues(t, 0x00020, AuditStatusBacklogWaitTime)
}
