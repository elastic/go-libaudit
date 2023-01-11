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

package libaudit

import (
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SEKOIA-IO/go-libaudit/v2/auparse"
)

var errReassemblerClosed = errors.New("reassembler closed")

// Stream is implemented by the user of the Reassembler to handle reassembled
// audit data.
type Stream interface {
	// ReassemblyComplete notifies that a complete group of events has been
	// received and provides those events.
	ReassemblyComplete(msgs []*auparse.AuditMessage)

	// EventsLost notifies that some events were lost. This is based on gaps
	// in the sequence numbers of received messages. Lost events can be caused
	// by a slow receiver or because the kernel is configured to rate limit
	// events.
	EventsLost(count int)
}

// Type - Reassembler

// Reassembler combines related messages in to an event based on their timestamp
// and sequence number. It handles messages that may be have been received out
// of order or are interleaved. Reassembler is concurrency-safe.
//
// The Reassembler uses callbacks (see Stream interface) to notify the user of
// completed messages. Callbacks for reassembled events will occur in order of
// sequence number unless a late message is received that falls outside of the
// sequences held in memory.
type Reassembler struct {
	closed int32 // closed is set to 1 when after the Reassembler is closed.

	// cache contains the in-flight event messages. Eviction occurs when an
	// event is completed via an EOE message, the cache reaches max size
	// (lowest sequence is evicted first), or an event expires base on time.
	list *eventList

	// stream is the callback interface used for delivering completed events.
	stream Stream
}

// NewReassembler returns a new Reassembler. maxInFlight controls the maximum
// number of events (based on timestamp + sequence) that are buffered. timeout
// controls how long the Reassembler waits for an EOE message (end-of-event)
// before evicting the event. And stream receives the callbacks for completed
// events and lost events.
func NewReassembler(maxInFlight int, timeout time.Duration, stream Stream) (*Reassembler, error) {
	if stream == nil {
		return nil, errors.New("stream cannot be nil")
	}

	return &Reassembler{
		list:   newEventList(maxInFlight, timeout),
		stream: stream,
	}, nil
}

// PushMessage pushes a new AuditMessage message into the Reassembler. Callbacks
// may be triggered as a result.
func (r *Reassembler) PushMessage(msg *auparse.AuditMessage) {
	if msg == nil {
		return
	}

	r.list.Put(msg)
	evicted, lost := r.list.CleanUp()
	r.callback(evicted, lost)
}

// Push pushes a new audit message into the Reassembler. This is a convenience
// function that handles calling auparse.Parse() to extract the message's
// timestamp and sequence number. It copies the rawData contents. If parsing
// fails then an error will be returned. See PushMessage.
func (r *Reassembler) Push(typ auparse.AuditMessageType, rawData []byte) error {
	msg, err := auparse.Parse(typ, string(rawData))
	if err != nil {
		return err
	}

	r.PushMessage(msg)
	return nil
}

// Maintain performs maintenance on the cached message. It can be called
// periodically to evict timed-out events. It returns a non-nil error if
// the Reassembler has been closed.
func (r *Reassembler) Maintain() error {
	if atomic.LoadInt32(&r.closed) == 1 {
		return errReassemblerClosed
	}
	evicted, lost := r.list.CleanUp()
	r.callback(evicted, lost)
	return nil
}

// Close flushes any cached events and closes the Reassembler.
func (r *Reassembler) Close() error {
	if atomic.CompareAndSwapInt32(&r.closed, 0, 1) {
		evicted, lost := r.list.Clear()
		r.callback(evicted, lost)
		return nil
	}
	return errReassemblerClosed
}

func (r *Reassembler) callback(events []*event, lost int) {
	for _, e := range events {
		r.stream.ReassemblyComplete(e.msgs)
	}

	if lost > 0 {
		r.stream.EventsLost(lost)
	}
}

type sequenceNum uint32

// Type - sequenceNumSlice

// maxSortRange defines the maximum range that sequence number can differ
// before being considered to have rolled over. When two values differ by more
// than this constant, the larger values is treated as being less.
const maxSortRange = 1<<24 - 1

type sequenceNumSlice []sequenceNum

func (p sequenceNumSlice) Len() int      { return len(p) }
func (p sequenceNumSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p sequenceNumSlice) Sort()         { sort.Sort(p) }

func sequenceHasRollover(i, j sequenceNum) bool {
	return abs(int64(i)-int64(j)) > maxSortRange
}

func (p sequenceNumSlice) Less(i, j int) bool {
	// Handle sequence number rollover.
	if sequenceHasRollover(p[i], p[j]) {
		return p[i] > p[j]
	}

	return p[i] < p[j]
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// Type - event

type event struct {
	expireTime time.Time
	msgs       []*auparse.AuditMessage
	complete   bool
}

func (e *event) Add(msg *auparse.AuditMessage) {
	e.msgs = append(e.msgs, msg)

	// These messages all signal the completion of an event.
	if msg.RecordType == auparse.AUDIT_PROCTITLE ||
		msg.RecordType <= auparse.AUDIT_LAST_DAEMON ||
		msg.RecordType >= auparse.AUDIT_ANOM_LOGIN_FAILURES {
		e.complete = true
	}
}

func (e *event) IsExpired() bool {
	return time.Now().After(e.expireTime)
}

// Type - eventList

type eventList struct {
	sync.Mutex
	seqs             sequenceNumSlice
	events           map[sequenceNum]*event
	lastSeq          sequenceNum
	maxSize          int
	timeout          time.Duration
	missingSequences map[sequenceNum]time.Time
}

func newEventList(maxSize int, timeout time.Duration) *eventList {
	return &eventList{
		seqs:             make([]sequenceNum, 0, maxSize+1),
		events:           make(map[sequenceNum]*event, maxSize+1),
		maxSize:          maxSize,
		timeout:          timeout,
		missingSequences: make(map[sequenceNum]time.Time, maxSize+1),
	}
}

// remove the first event (lowest sequence) in the list.
func (l *eventList) remove() {
	if len(l.seqs) > 0 {
		seq := l.seqs[0]
		l.seqs = l.seqs[1:]
		delete(l.events, seq)
	}
}

// Clear removes all events from the list and returns the events and the number
// of lost events.
func (l *eventList) Clear() ([]*event, int) {
	l.Lock()
	defer l.Unlock()

	var lost int
	var seq sequenceNum
	var evicted []*event
	for {
		size := len(l.seqs)
		if size == 0 {
			break
		}

		// Get event.
		seq = l.seqs[0]
		event := l.events[seq]

		lost += l.processSequence(seq)
		evicted = append(evicted, event)
		l.remove()
	}

	// All remaining missing sequences are marked as lost
	lost += len(l.missingSequences)
	l.missingSequences = make(map[sequenceNum]time.Time, l.maxSize+1)

	return evicted, lost
}

// Put a new message in the list.
func (l *eventList) Put(msg *auparse.AuditMessage) {
	l.Lock()
	defer l.Unlock()

	seq := sequenceNum(msg.Sequence)
	e, found := l.events[seq]

	// Mark as complete, but do not append.
	if msg.RecordType == auparse.AUDIT_EOE {
		if found {
			e.complete = true
		}
		return
	}

	if !found {
		l.seqs = append(l.seqs, seq)
		l.seqs.Sort()

		e = &event{
			expireTime: time.Now().Add(l.timeout),
			msgs:       make([]*auparse.AuditMessage, 0, 4),
		}
		l.events[seq] = e
	}

	e.Add(msg)
}

func (l *eventList) CleanUp() ([]*event, int) {
	l.Lock()
	defer l.Unlock()

	var lost int
	var seq sequenceNum
	var evicted []*event
	for {
		size := len(l.seqs)
		if size == 0 {
			break
		}

		// Get event.
		seq = l.seqs[0]
		event := l.events[seq]

		if event.complete || size > l.maxSize || event.IsExpired() {
			lost += l.processSequence(seq)
			evicted = append(evicted, event)
			l.remove()
			continue
		}

		break
	}

	lost += l.cleanExpiredMissingSequences()

	return evicted, lost
}

// trackMissingSequences marks all the sequences between the start sequence and the end sequence
// as missing, start and end excluded
func (l *eventList) trackMissingSequences(start, end sequenceNum) int {
	missingSequences := end - start - 1
	if missingSequences == 0 {
		return 0 // No missing sequences
	}
	var lost int
	if missingSequences > sequenceNum(l.maxSize) {
		// The gap is bigger than the maximum size allowed.
		// We keep only the last ones and discard the others
		newStart := end - sequenceNum(l.maxSize) - 1 // -1 to offset the + 1 in the for loop below
		lost += int(newStart - start)
		start = newStart
	}
	// If we have too many missing events we remove the old ones
	nextMapSize := int(missingSequences + sequenceNum(len(l.missingSequences)))
	if nextMapSize > l.maxSize {
		lost += l.removeOldestMissingSequences(nextMapSize - l.maxSize)
	}
	// Add new sequences to the missing ones
	l.addMissingSequencesToMap(start, end)
	return lost
}

// addMissingSequencesToMap effectively adds the missing sequence to the tracking map
func (l *eventList) addMissingSequencesToMap(start, end sequenceNum) {
	if start > end {
		// We lost events during the sequence id rollover
		// so we fill the gap until the end and start again from 0
		maxSeq := sequenceNum(math.MaxUint32)
		seq := start + 1
		for {
			l.missingSequences[seq] = time.Now().Add(l.timeout)
			if seq == maxSeq {
				break
			}
			seq++
		}
		start = maxSeq // maxSeq + 1  == 0
	}
	for seq := start + 1; seq < end; seq++ {
		l.missingSequences[seq] = time.Now().Add(l.timeout)
	}
}

// cleanExpiredMissingSequences remove from tracking expired missing sequences
// and returns their number
func (l *eventList) cleanExpiredMissingSequences() int {
	lost := 0
	now := time.Now()
	for seq, expireTime := range l.missingSequences {
		if now.After(expireTime) {
			delete(l.missingSequences, seq)
			lost += 1
		}
	}
	return lost
}

// removeOldestMissingSequences removes the oldest n sequences from the map
func (l *eventList) removeOldestMissingSequences(n int) int {
	sequences := make(sequenceNumSlice, 0, l.maxSize+1)
	for seq := range l.missingSequences {
		sequences = append(sequences, seq)
	}
	sequences.Sort()
	if n > len(sequences) {
		n = len(sequences) // avoid having errors while slicing sequences
	}
	for _, seq := range sequences[:n] {
		delete(l.missingSequences, seq)
	}
	return n
}

func (l *eventList) processSequence(seq sequenceNum) int {
	delete(l.missingSequences, seq) // In case the sequence was marked as missing
	if seq <= l.lastSeq && !sequenceHasRollover(l.lastSeq, seq) {
		// We already handled a sequence after this one,
		// so no need to add missing sequences nor update the last sequence
		return 0
	}
	var lost int
	if l.lastSeq > 0 {
		lost = l.trackMissingSequences(l.lastSeq, seq)
	}
	l.lastSeq = seq
	return lost
}
