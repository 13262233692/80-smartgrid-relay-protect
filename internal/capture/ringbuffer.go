package capture

import (
	"sync/atomic"
)

type PacketBuffer struct {
	Data      []byte
	Timestamp int64
	Length    int
}

type LockFreeRingBuffer struct {
	buffer    []PacketBuffer
	capacity  uint64
	mask      uint64
	head      uint64
	tail      uint64
	dropped   uint64
	processed uint64
	pool      []PacketBuffer
}

func NewLockFreeRingBuffer(capacity int) *LockFreeRingBuffer {
	cap := nextPow2Uint64(uint64(capacity))
	if cap < 8 {
		cap = 8
	}

	rb := &LockFreeRingBuffer{
		buffer:   make([]PacketBuffer, cap),
		capacity: cap,
		mask:     cap - 1,
		pool:     make([]PacketBuffer, 0, cap),
	}

	for i := uint64(0); i < cap; i++ {
		rb.buffer[i].Data = make([]byte, 2048)
	}

	return rb
}

func nextPow2Uint64(v uint64) uint64 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	v++
	return v
}

func (rb *LockFreeRingBuffer) Enqueue(data []byte, timestamp int64) bool {
	head := atomic.LoadUint64(&rb.head)
	tail := atomic.LoadUint64(&rb.tail)

	if head-tail >= rb.capacity {
		atomic.AddUint64(&rb.dropped, 1)
		return false
	}

	idx := head & rb.mask
	buf := &rb.buffer[idx]

	if len(buf.Data) < len(data) {
		buf.Data = make([]byte, len(data)+512)
	}
	copy(buf.Data, data)
	buf.Length = len(data)
	buf.Timestamp = timestamp

	atomic.StoreUint64(&rb.head, head+1)
	return true
}

func (rb *LockFreeRingBuffer) Dequeue(buf *PacketBuffer) bool {
	tail := atomic.LoadUint64(&rb.tail)
	head := atomic.LoadUint64(&rb.head)

	if head == tail {
		return false
	}

	idx := tail & rb.mask
	src := &rb.buffer[idx]

	if len(buf.Data) < src.Length {
		buf.Data = make([]byte, src.Length+512)
	}
	copy(buf.Data, src.Data[:src.Length])
	buf.Length = src.Length
	buf.Timestamp = src.Timestamp

	atomic.StoreUint64(&rb.tail, tail+1)
	atomic.AddUint64(&rb.processed, 1)
	return true
}

func (rb *LockFreeRingBuffer) DequeueBatch(bufs []PacketBuffer) int {
	count := 0
	for count < len(bufs) {
		if !rb.Dequeue(&bufs[count]) {
			break
		}
		count++
	}
	return count
}

func (rb *LockFreeRingBuffer) IsEmpty() bool {
	return atomic.LoadUint64(&rb.head) == atomic.LoadUint64(&rb.tail)
}

func (rb *LockFreeRingBuffer) IsFull() bool {
	head := atomic.LoadUint64(&rb.head)
	tail := atomic.LoadUint64(&rb.tail)
	return head-tail >= rb.capacity
}

func (rb *LockFreeRingBuffer) Size() int {
	head := atomic.LoadUint64(&rb.head)
	tail := atomic.LoadUint64(&rb.tail)
	return int(head - tail)
}

func (rb *LockFreeRingBuffer) Capacity() int {
	return int(rb.capacity)
}

func (rb *LockFreeRingBuffer) Dropped() uint64 {
	return atomic.LoadUint64(&rb.dropped)
}

func (rb *LockFreeRingBuffer) Processed() uint64 {
	return atomic.LoadUint64(&rb.processed)
}

func (rb *LockFreeRingBuffer) Reset() {
	atomic.StoreUint64(&rb.head, 0)
	atomic.StoreUint64(&rb.tail, 0)
	atomic.StoreUint64(&rb.dropped, 0)
	atomic.StoreUint64(&rb.processed, 0)
}

type SPSCLockFreeQueue struct {
	buffer    []PacketBuffer
	capacity  uint64
	mask      uint64
	head      uint64
	tail      uint64
	dropped   uint64
	processed uint64
}

func NewSPSCLockFreeQueue(capacity int) *SPSCLockFreeQueue {
	cap := nextPow2Uint64(uint64(capacity))
	if cap < 8 {
		cap = 8
	}

	q := &SPSCLockFreeQueue{
		buffer:   make([]PacketBuffer, cap),
		capacity: cap,
		mask:     cap - 1,
	}

	for i := uint64(0); i < cap; i++ {
		q.buffer[i].Data = make([]byte, 2048)
	}

	return q
}

func (q *SPSCLockFreeQueue) Enqueue(data []byte, timestamp int64) bool {
	head := q.head
	nextHead := (head + 1) & q.mask

	if nextHead == q.tail {
		q.dropped++
		return false
	}

	buf := &q.buffer[head]
	if len(buf.Data) < len(data) {
		buf.Data = make([]byte, len(data)+512)
	}
	copy(buf.Data, data)
	buf.Length = len(data)
	buf.Timestamp = timestamp

	q.head = nextHead
	return true
}

func (q *SPSCLockFreeQueue) Dequeue(buf *PacketBuffer) bool {
	if q.tail == q.head {
		return false
	}

	src := &q.buffer[q.tail]

	if len(buf.Data) < src.Length {
		buf.Data = make([]byte, src.Length+512)
	}
	copy(buf.Data, src.Data[:src.Length])
	buf.Length = src.Length
	buf.Timestamp = src.Timestamp

	q.tail = (q.tail + 1) & q.mask
	q.processed++
	return true
}

func (q *SPSCLockFreeQueue) DequeueAll(bufs []PacketBuffer) int {
	count := 0
	for count < len(bufs) {
		if !q.Dequeue(&bufs[count]) {
			break
		}
		count++
	}
	return count
}

func (q *SPSCLockFreeQueue) IsEmpty() bool {
	return q.tail == q.head
}

func (q *SPSCLockFreeQueue) Size() int {
	if q.head >= q.tail {
		return int(q.head - q.tail)
	}
	return int(q.capacity - q.tail + q.head)
}

func (q *SPSCLockFreeQueue) Capacity() int {
	return int(q.capacity)
}

func (q *SPSCLockFreeQueue) Dropped() uint64 {
	return q.dropped
}

func (q *SPSCLockFreeQueue) Processed() uint64 {
	return q.processed
}

type PacketBatch struct {
	Packets   [256]PacketBuffer
	Count     int
}

func NewPacketBatch() *PacketBatch {
	pb := &PacketBatch{}
	for i := range pb.Packets {
		pb.Packets[i].Data = make([]byte, 2048)
	}
	return pb
}

func (pb *PacketBatch) Reset() {
	pb.Count = 0
}

func (pb *PacketBatch) Add(data []byte, timestamp int64) bool {
	if pb.Count >= len(pb.Packets) {
		return false
	}
	buf := &pb.Packets[pb.Count]
	if len(buf.Data) < len(data) {
		buf.Data = make([]byte, len(data)+512)
	}
	copy(buf.Data, data)
	buf.Length = len(data)
	buf.Timestamp = timestamp
	pb.Count++
	return true
}
