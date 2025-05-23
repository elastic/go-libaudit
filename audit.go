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
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/elastic/go-libaudit/v2/auparse"
)

const (
	// AuditMessageMaxLength is the maximum length of an audit message (data
	// portion of a NetlinkMessage).
	// https://github.com/linux-audit/audit-userspace/blob/990aa27ccd02f9743c4f4049887ab89678ab362a/lib/libaudit.h#L435
	AuditMessageMaxLength = 8970
)

// Audit command and control message types.
const (
	AuditGet uint16 = iota + 1000
	AuditSet
)

// Netlink groups.
const (
	NetlinkGroupNone    = iota // Group 0 not used
	NetlinkGroupReadLog        // "best effort" read only socket, defined in the kernel as AUDIT_NLGRP_READLOG
)

// WaitMode is a flag to control the behavior of methods that abstract
// asynchronous communication for the caller.
type WaitMode uint8

const (
	// WaitForReply mode causes a call to wait for a reply message.
	WaitForReply WaitMode = iota + 1
	// NoWait mode causes a call to return without waiting for a reply message.
	NoWait
)

// FailureMode defines the kernel's behavior on critical errors.
type FailureMode uint32

const (
	// SilentOnFailure ignores errors.
	SilentOnFailure FailureMode = 0
	// LogOnFailure logs errors using printk.
	LogOnFailure
	// PanicOnFailure causes a kernel panic on error.
	PanicOnFailure
)

// AuditClient is a client for communicating with the Linux kernels audit
// interface over netlink.
type AuditClient struct {
	Netlink         NetlinkSendReceiver
	pendingAcks     []uint32
	clearPIDOnClose bool
	closeOnce       sync.Once
}

// NewMulticastAuditClient creates a new AuditClient that binds to the multicast
// socket subscribes to the audit group. The process should have the
// CAP_AUDIT_READ capability to use this. This audit client should not be used
// for command and control. The resp parameter is optional. If provided resp
// will receive a copy of all data read from the netlink socket. This is useful
// for debugging purposes.
func NewMulticastAuditClient(resp io.Writer) (*AuditClient, error) {
	return newAuditClient(NetlinkGroupReadLog, resp)
}

// NewAuditClient creates a new AuditClient. The resp parameter is optional. If
// provided resp will receive a copy of all data read from the netlink socket.
// This is useful for debugging purposes.
func NewAuditClient(resp io.Writer) (*AuditClient, error) {
	return newAuditClient(NetlinkGroupNone, resp)
}

func newAuditClient(netlinkGroups uint32, resp io.Writer) (*AuditClient, error) {
	buf := make([]byte, syscall.NLMSG_HDRLEN+AuditMessageMaxLength)

	netlink, err := NewNetlinkClient(syscall.NETLINK_AUDIT, netlinkGroups, buf, resp)
	if err != nil {
		switch {
		case errors.Is(err, syscall.EINVAL),
			errors.Is(err, syscall.EPROTONOSUPPORT),
			errors.Is(err, syscall.EAFNOSUPPORT):
			return nil, fmt.Errorf("audit not supported by kernel: %w", err)
		default:
			return nil, fmt.Errorf("failed to open audit netlink socket: %w", err)
		}
	}

	return &AuditClient{Netlink: netlink}, nil
}

// GetStatus returns the current status of the kernel's audit subsystem.
func (c *AuditClient) GetStatus() (*AuditStatus, error) {
	// Send AUDIT_GET message to the kernel.
	seq, err := c.GetStatusAsync(true)
	if err != nil {
		return nil, fmt.Errorf("failed sending request: %w", err)
	}

	// Get the ack message which is a NLMSG_ERROR type whose error code is SUCCESS.
	ack, err := c.getReply(seq)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit status ack: %w", err)
	}

	if ack.Header.Type != syscall.NLMSG_ERROR {
		return nil, fmt.Errorf("unexpected ACK to GET, got type=%d", ack.Header.Type)
	}

	if err = ParseNetlinkError(ack.Data); err != nil {
		return nil, err
	}

	// Get the audit_status reply message. It has the same sequence number as
	// our original request.
	reply, err := c.getReply(seq)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit status reply: %w", err)
	}

	if reply.Header.Type != AuditGet {
		return nil, fmt.Errorf("unexpected reply to GET, got type=%d", reply.Header.Type)
	}

	replyStatus := &AuditStatus{}
	if err := replyStatus.FromWireFormat(reply.Data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal reply: %w", err)
	}

	return replyStatus, nil
}

// GetStatusAsync sends a request for the status of the kernel's audit subsystem
// and returns without waiting for a response.
func (c *AuditClient) GetStatusAsync(requireACK bool) (seq uint32, err error) {
	flags := uint16(syscall.NLM_F_REQUEST)
	if requireACK {
		flags |= syscall.NLM_F_ACK
	}
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  AuditGet,
			Flags: flags,
		},
		Data: nil,
	}

	// Send AUDIT_GET message to the kernel.
	return c.Netlink.Send(msg)
}

// GetRules returns a list of audit rules (in binary format).
func (c *AuditClient) GetRules() ([][]byte, error) {
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  uint16(auparse.AUDIT_LIST_RULES),
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: nil,
	}

	// Send AUDIT_LIST_RULES message to the kernel.
	seq, err := c.Netlink.Send(msg)
	if err != nil {
		return nil, fmt.Errorf("failed sending request: %w", err)
	}

	// Get the ack message which is a NLMSG_ERROR type whose error code is SUCCESS.
	ack, err := c.getReply(seq)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit ACK: %w", err)
	}

	if ack.Header.Type != syscall.NLMSG_ERROR {
		return nil, fmt.Errorf("unexpected ACK to LIST_RULES, got type=%d", ack.Header.Type)
	}

	if err = ParseNetlinkError(ack.Data); err != nil {
		return nil, err
	}

	var rules [][]byte
	for {
		reply, err := c.getReply(seq)
		if err != nil {
			return nil, fmt.Errorf("failed receiving rule data: %w", err)
		}

		if reply.Header.Type == syscall.NLMSG_DONE {
			break
		}

		if reply.Header.Type != uint16(auparse.AUDIT_LIST_RULES) {
			return nil, fmt.Errorf("unexpected message type %d while receiving rules", reply.Header.Type)
		}

		rule := make([]byte, len(reply.Data))
		copy(rule, reply.Data)
		rules = append(rules, rule)
	}

	return rules, nil
}

// DeleteRules deletes all rules.
func (c *AuditClient) DeleteRules() (int, error) {
	rules, err := c.GetRules()
	if err != nil {
		return 0, err
	}

	for i, rule := range rules {
		if err := c.DeleteRule(rule); err != nil {
			return 0, fmt.Errorf("failed to delete rule %v of %v: %w", i, len(rules), err)
		}
	}

	return len(rules), nil
}

// DeleteRule deletes the given rule (specified in binary format).
func (c *AuditClient) DeleteRule(rule []byte) error {
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  uint16(auparse.AUDIT_DEL_RULE),
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: rule,
	}

	// Send AUDIT_DEL_RULE message to the kernel.
	seq, err := c.Netlink.Send(msg)
	if err != nil {
		return fmt.Errorf("failed sending delete rule request: %w", err)
	}

	_, err = c.getReply(seq)
	if err != nil {
		return fmt.Errorf("failed to get ACK to rule delete request: %w", err)
	}

	return nil
}

// AddRule adds the given rule to the kernel's audit rule list.
func (c *AuditClient) AddRule(rule []byte) error {
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  uint16(auparse.AUDIT_ADD_RULE),
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: rule,
	}

	// Send AUDIT_ADD_RULE message to the kernel.
	seq, err := c.Netlink.Send(msg)
	if err != nil {
		return fmt.Errorf("failed sending add rule request: %w", err)
	}

	ack, err := c.getReply(seq)
	if err != nil {
		return fmt.Errorf("failed to get ACK to add rule request: %w", err)
	}

	if ack.Header.Type != syscall.NLMSG_ERROR {
		return fmt.Errorf("unexpected ACK to AUDIT_ADD_RULE, got type=%d", ack.Header.Type)
	}

	if err = ParseNetlinkError(ack.Data); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return errors.New("rule exists")
		}
		return fmt.Errorf("error adding audit rule: %w", err)
	}

	return nil
}

// SetPID sends a netlink message to the kernel telling it the PID of the
// client that should receive audit messages.
// https://github.com/linux-audit/audit-userspace/blob/990aa27ccd02f9743c4f4049887ab89678ab362a/lib/libaudit.c#L432-L464
func (c *AuditClient) SetPID(wm WaitMode) error {
	status := AuditStatus{
		Mask: AuditStatusPID,
		PID:  uint32(os.Getpid()),
	}
	c.clearPIDOnClose = true
	return c.set(status, wm)
}

// SetRateLimit will set the maximum number of messages that the kernel will
// send per second. This can be used to throttle the rate if systems become
// unresponsive. Of course the trade off is that events will be dropped.
// The default value is 0, meaning no limit.
func (c *AuditClient) SetRateLimit(perSecondLimit uint32, wm WaitMode) error {
	status := AuditStatus{
		Mask:      AuditStatusRateLimit,
		RateLimit: perSecondLimit,
	}
	return c.set(status, wm)
}

// SetBacklogLimit sets the queue length for audit events awaiting transfer to
// the audit daemon. The default value is 64 which can potentially be overrun by
// bursts of activity. When the backlog limit is reached, the kernel consults
// the failure_flag to see what action to take.
func (c *AuditClient) SetBacklogLimit(limit uint32, wm WaitMode) error {
	status := AuditStatus{
		Mask:         AuditStatusBacklogLimit,
		BacklogLimit: limit,
	}
	return c.set(status, wm)
}

// SetEnabled is used to control whether or not the audit system is
// active. When the audit system is enabled (enabled set to 1), every syscall
// will pass through the audit system to collect information and potentially
// trigger an event.
func (c *AuditClient) SetEnabled(enabled bool, wm WaitMode) error {
	var e uint32
	if enabled {
		e = 1
	}

	status := AuditStatus{
		Mask:    AuditStatusEnabled,
		Enabled: e,
	}
	return c.set(status, wm)
}

// SetImmutable is used to lock the audit configuration so that it can't be
// changed. Locking the configuration is intended to be the last command you
// issue. Any attempt to change the configuration in this mode will be
// audited and denied. The configuration can only be changed by rebooting the
// machine.
func (c *AuditClient) SetImmutable(wm WaitMode) error {
	status := AuditStatus{
		Mask:    AuditStatusEnabled,
		Enabled: 2,
	}
	return c.set(status, wm)
}

// SetFailure sets the action that the kernel will perform when the backlog
// limit is reached or when it encounters an error and cannot proceed.
func (c *AuditClient) SetFailure(fm FailureMode, wm WaitMode) error {
	status := AuditStatus{
		Mask:    AuditStatusFailure,
		Failure: uint32(fm),
	}
	return c.set(status, wm)
}

// SetBacklogWaitTime sets the time that the kernel will wait for a buffer in
// the backlog queue to become available before dropping the event. This has
// the side effect of blocking the thread that was invoking the syscall being
// audited.
// waitTime is measured in jiffies, default in kernel is 60*HZ (60 seconds).
// A value of 0 disables the wait time completely, causing the failure mode
// to be invoked immediately when the backlog queue is full.
// Attempting to set a negative value or a value 10x larger than the default
// will fail with EINVAL.
func (c *AuditClient) SetBacklogWaitTime(waitTime int32, wm WaitMode) error {
	status := AuditStatus{
		Mask:            AuditStatusBacklogWaitTime,
		BacklogWaitTime: uint32(waitTime),
	}
	return c.set(status, wm)
}

// RawAuditMessage is a raw audit message received from the kernel.
type RawAuditMessage struct {
	Type auparse.AuditMessageType
	Data []byte // RawData is backed by the read buffer so make a copy.
}

// Receive reads an audit message from the netlink socket. If you are going to
// use the returned message then you should make a copy of the raw data before
// calling receive again because the raw data is backed by the read buffer.
func (c *AuditClient) Receive(nonBlocking bool) (*RawAuditMessage, error) {
	msgs, err := c.Netlink.Receive(nonBlocking, parseNetlinkAuditMessage)
	if err != nil {
		return nil, err
	}

	// ParseNetlinkAuditMessage always return a slice with 1 item.
	return &RawAuditMessage{
		Type: auparse.AuditMessageType(msgs[0].Header.Type),
		Data: msgs[0].Data,
	}, nil
}

// Close closes the AuditClient and frees any associated resources. If the audit
// PID was set it will be cleared (set 0). Any invocations beyond the first
// become no-ops.
func (c *AuditClient) Close() error {
	var err error
	// Only unregister and close the socket once.
	c.closeOnce.Do(func() {
		if c.clearPIDOnClose {
			// Unregister from the kernel for a clean exit.
			err = c.closeAndUnsetPid()
		}

		err = errors.Join(err, c.Netlink.Close())
	})

	return err
}

// WaitForPendingACKs waits for acknowledgements messages for operations
// executed with a WaitMode of NoWait. Such ACK messages are expected in the
// same order as the operations have been performed. If it receives an error,
// it is returned and no further ACKs are processed.
func (c *AuditClient) WaitForPendingACKs() error {
	for _, reqID := range c.pendingAcks {
		ack, err := c.getReply(reqID)
		if err != nil {
			return err
		}
		if ack.Header.Type != syscall.NLMSG_ERROR {
			return fmt.Errorf("unexpected ACK to SET, type=%d", ack.Header.Type)
		}
		if err := ParseNetlinkError(ack.Data); err != nil {
			return err
		}
	}
	return nil
}

// getReply reads from the netlink socket and find the message with the given
// sequence number. The caller should inspect the returned message's type,
// flags, and error code.
func (c *AuditClient) getReply(seq uint32) (*syscall.NetlinkMessage, error) {
	var msg syscall.NetlinkMessage
	var msgs []syscall.NetlinkMessage
	var err error

	for receiveMore := true; receiveMore; {
		// Retry the non-blocking read multiple times until a response is received.
		for i := 0; i < 10; i++ {
			msgs, err = c.Netlink.Receive(true, parseNetlinkAuditMessage)
			if err != nil {
				switch {
				case errors.Is(err, syscall.EINTR):
					continue
				case errors.Is(err, syscall.EAGAIN):
					time.Sleep(50 * time.Millisecond)
					continue
				default:
					return nil, fmt.Errorf("error receiving audit reply: %w", err)
				}
			}
			break
		}

		if len(msgs) == 0 {
			return nil, errors.New("no reply received")
		}
		msg = msgs[0]
		// Skip audit event that sneak between the request/response
		receiveMore = msg.Header.Seq == 0 && seq != 0
	}
	if msg.Header.Seq != seq {
		return nil, fmt.Errorf("unexpected sequence number for reply (expected %v but got %v)",
			seq, msg.Header.Seq)
	}
	return &msg, nil
}

// unset our pid from the audit subsystem and close the socket.
// This is a sort of isolated refactor, meant to deal with the deadlocks that can happen when we're not careful with blocking operations throughout a lot of this code.
func (c *AuditClient) closeAndUnsetPid() error {
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  AuditSet,
			Flags: syscall.NLM_F_REQUEST,
		},
		Data: AuditStatus{
			Mask: AuditStatusPID,
			PID:  0,
		}.toWireFormat(),
	}

	// If our request to unset the PID would block, then try to drain events from
	// the netlink socket, resend, try again.
	// In netlink, EAGAIN usually indicates our read buffer is full.
	// The auditd code (which I'm using as a reference implementation) doesn't wait for a response when unsetting the audit pid.
	// The retry count here is largely arbitrary, and provides a buffer for either transient errors (EINTR) or retries.
	retries := 5
outer:
	for i := 0; i < retries; i++ {
		_, err := c.Netlink.SendNoWait(msg)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			// got a transient interrupt, try again
			continue
		case errors.Is(err, syscall.EAGAIN):
			// send would block, try to drain the receive socket. The recv count here is just so we have enough of a buffer to attempt a send again/
			// The number is just here so we ideally have enough of a buffer to attempt the send again.
			maxRecv := 10000
			for i := 0; i < maxRecv; i++ {
				_, err = c.Netlink.Receive(true, noParse)
				switch {
				case err == nil, errors.Is(err, syscall.EINTR), errors.Is(err, syscall.ENOBUFS):
					// continue with receive, try to read more data
					continue
				case errors.Is(err, syscall.EAGAIN):
					// receive would block, try to send again
					continue outer
				default:
					// if receive returns an other error, just return that.
					return err
				}
			}
		default:
			// if Send returns and other error, just return that
			return err
		}

	}
	// we may not want to treat this as a hard error?
	// It's not a massive error if this fails, since the kernel will unset the PID if it can't communicate with the process,
	// so this is largely for neatness.
	return fmt.Errorf("could not unset pid from audit after retries")
}

// noParse is a no-op parser used by closeAndUnsetPID
func noParse([]byte) ([]syscall.NetlinkMessage, error) {
	return nil, nil
}

func (c *AuditClient) set(status AuditStatus, mode WaitMode) error {
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  AuditSet,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: status.toWireFormat(),
	}

	seq, err := c.Netlink.Send(msg)
	if err != nil {
		return fmt.Errorf("failed sending request: %w", err)
	}

	if mode == NoWait {
		c.storePendingAck(seq)
		return nil
	}

	ack, err := c.getReply(seq)
	if err != nil {
		return err
	}

	if ack.Header.Type != syscall.NLMSG_ERROR {
		return fmt.Errorf("unexpected ACK to SET, type=%d", ack.Header.Type)
	}

	if err := ParseNetlinkError(ack.Data); err != nil {
		return err
	}

	return nil
}

// parseNetlinkAuditMessage parses an audit message received from the kernel.
// Audit messages differ significantly from typical netlink messages in that
// a single message is sent and the length in the header should be ignored.
// This is why syscall.ParseNetlinkMessage is not used.
func parseNetlinkAuditMessage(buf []byte) ([]syscall.NetlinkMessage, error) {
	if len(buf) < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL
	}
	return []syscall.NetlinkMessage{{
		Header: *(*syscall.NlMsghdr)(unsafe.Pointer(&buf[0])),
		Data:   buf[syscall.NLMSG_HDRLEN:],
	}}, nil
}

// audit_status message

// AuditStatusMask is a bitmask used to convey the fields used in AuditStatus.
// https://github.com/linux-audit/audit-kernel/blob/v4.7/include/uapi/linux/audit.h#L318-L325
type AuditStatusMask uint32

// Mask types for AuditStatus. Originally defined in the kernel at audit.h
const (
	AuditStatusEnabled AuditStatusMask = 1 << iota
	AuditStatusFailure
	AuditStatusPID
	AuditStatusRateLimit
	AuditStatusBacklogLimit
	AuditStatusBacklogWaitTime
	AuditStatusLost
)

// AuditFeatureBitmap is a mask used to indicate which features are currently
// supported by the audit subsystem.
type AuditFeatureBitmap uint32

const (
	AuditFeatureBitmapBacklogLimit = 1 << iota
	AuditFeatureBitmapBacklogWaitTime
	AuditFeatureBitmapExecutablePath
	AuditFeatureBitmapExcludeExtend
	AuditFeatureBitmapSessionIDFilter
	AuditFeatureBitmapLostReset
)

// AuditStatus is a status message and command and control message exchanged
// between the kernel and user-space.
// https://github.com/linux-audit/audit-kernel/blob/v5.9/include/uapi/linux/audit.h#L457-L474
type AuditStatus struct {
	Mask                  AuditStatusMask // Bit mask for valid entries.
	Enabled               uint32          // 1 = enabled, 0 = disabled, 2 = immutable
	Failure               uint32          // Failure-to-log action.
	PID                   uint32          // PID of auditd process.
	RateLimit             uint32          // Messages rate limit (per second).
	BacklogLimit          uint32          // Waiting messages limit.
	Lost                  uint32          // Messages lost.
	Backlog               uint32          // Messages waiting in queue.
	FeatureBitmap         uint32          // Bitmap of kernel audit features (previously to 3.19 it was the audit api version number).
	BacklogWaitTime       uint32          // Message queue wait timeout.
	BacklogWaitTimeActual uint32          // Time the kernel has spent waiting while the backlog limit is exceeded.
}

const (
	sizeofAuditStatus = int(unsafe.Sizeof(AuditStatus{}))

	// MinSizeofAuditStatus is the minimum usable message size for
	// the earliest 2.6.32 kernel supported by Go.
	// https://elixir.bootlin.com/linux/v2.6.32/source/include/linux/audit.h#L317
	// Messages this size do not report features after the Backlog field.
	// Users should consult the feature bitmap to determine which
	// features are valid.
	MinSizeofAuditStatus = int(unsafe.Offsetof(AuditStatus{}.Backlog) + unsafe.Sizeof(AuditStatus{}.Backlog))
)

func (s AuditStatus) toWireFormat() []byte {
	return (*[sizeofAuditStatus]byte)(unsafe.Pointer(&s))[:]
}

// FromWireFormat unmarshals the given buffer to an AuditStatus object.
// It returns io.ErrUnexpectedEOF if len(buf) is less than MinSizeofAuditStatus.
func (s *AuditStatus) FromWireFormat(buf []byte) error {
	if len(buf) < MinSizeofAuditStatus {
		return io.ErrUnexpectedEOF
	}
	if len(buf) < sizeofAuditStatus {
		*s = AuditStatus{}
	}
	copy((*[unsafe.Sizeof(AuditStatus{})]byte)(unsafe.Pointer(s))[:], buf)
	return nil
}

func (c *AuditClient) storePendingAck(requestID uint32) {
	c.pendingAcks = append(c.pendingAcks, requestID)
}
