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

package libaudit

import (
	"sort"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/go-libaudit/auparse"
)

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
// of order or are interleaved.
//
// The Reassembler uses callbacks (see Stream interface) to notify the user of
// completed messages. Callbacks for reassembled events will occur in order of
// sequence number unless a late message is received that falls outside of the
// sequences held in memory.
type Reassembler struct {
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

// Push pushes a new audit message into the Reassembler. This is a convenence
// function that handles calling auparse.Parse() to extract the message's
// timestamp and sequence number. If parsing fails then an error will be
// returned. See PushMessage.
func (r *Reassembler) Push(typ uint16, rawData []byte) error {
	msg, err := auparse.Parse(auparse.AuditMessageType(typ), string(rawData))
	if err != nil {
		return err
	}

	r.PushMessage(msg)
	return nil
}

// Maintain performs maintenance on the cached message. It can be called
// periodically to evict timed-out events.
func (r *Reassembler) Maintain() {
	evicted, lost := r.list.CleanUp()
	r.callback(evicted, lost)
}

// Close flushes any cached events and closes the Reassembler.
func (r *Reassembler) Close() error {
	evicted, lost := r.list.Clear()
	r.callback(evicted, lost)
	return nil
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

func (p sequenceNumSlice) Less(i, j int) bool {
	// Handle sequence number rollover.
	diff := abs(int64(p[i]) - int64(p[j]))
	if diff > maxSortRange {
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

	if msg.RecordType == auparse.AUDIT_EOE {
		e.complete = true
	}
}

func (e *event) IsExpired() bool {
	return e.expireTime.After(time.Now())
}

// Type - eventList

type eventList struct {
	seqs    sequenceNumSlice
	events  map[sequenceNum]*event
	lastSeq sequenceNum
	maxSize int
	timeout time.Duration
}

func newEventList(maxSize int, timeout time.Duration) *eventList {
	return &eventList{
		seqs:    make([]sequenceNum, 0, maxSize+1),
		events:  make(map[sequenceNum]*event, maxSize+1),
		maxSize: maxSize,
		timeout: timeout,
	}
}

// Remove the first event (lowest sequence) in the list.
func (l *eventList) Remove() {
	if len(l.seqs) > 0 {
		seq := l.seqs[0]
		l.seqs = l.seqs[1:]
		delete(l.events, seq)
	}
}

// Clear removes all events from the list and returns the events and the number
// of list events.
func (l *eventList) Clear() ([]*event, int) {
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

		if l.lastSeq > 0 {
			lost += int(seq - l.lastSeq - 1)
		}
		l.lastSeq = seq
		evicted = append(evicted, event)
		l.Remove()
	}

	return evicted, lost
}

// Put a new message in the list.
func (l *eventList) Put(msg *auparse.AuditMessage) {
	seq := sequenceNum(msg.Sequence)
	e, found := l.events[seq]
	if !found {
		l.seqs = append(l.seqs, seq)
		l.seqs.Sort()

		e = &event{
			expireTime: time.Now(),
			msgs:       make([]*auparse.AuditMessage, 0, 4),
		}
		l.events[seq] = e
	}

	e.Add(msg)
}

func (l *eventList) CleanUp() ([]*event, int) {
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
			if l.lastSeq > 0 {
				lost += int(seq - l.lastSeq - 1)
			}
			l.lastSeq = seq
			evicted = append(evicted, event)
			l.Remove()
			continue
		}

		break
	}

	return evicted, lost
}
