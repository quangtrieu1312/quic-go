package quic

import (
	"context"
	"expvar"
	"sync"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
)

// Datagram-queue drop counters. These are the blind spot the app-level drop
// counters don't cover — a full send/recv queue here silently drops an
// (unrecoverable) datagram. Exposed via expvar, so they show up at
// /debug/vars on any binary that serves net/http/pprof (server :6060,
// client :9484). Watch the delta across a test to localize tunnel loss.
var (
	datagramSendDrops = expvar.NewInt("quic_datagram_send_drops")
	datagramRcvDrops  = expvar.NewInt("quic_datagram_rcv_drops")
)

// Phase 1 (perf): this is the upstream quic-go datagram queue — a per-connection
// sync.Mutex + ring buffer, pure Go, zero allocation on the send hot path.
//
// It replaces a CGO lock-free MPMC queue that required, per datagram and on BOTH
// send and receive: new(runtime.Pinner) + Pinner.Pin (which calls
// runtime.SetFinalizer — a process-GLOBAL lock) + a sync.Map insert + a cgocall.
// That machinery serialized every connection through one global lock and pinned
// throughput to ~1 core. The only per-packet lock here is this connection's own
// mutex, held just long enough to push/pop a pointer.
const (
	maxDatagramSendQueueLen = 1024
	maxDatagramRcvQueueLen  = 1024
	// Pooled receive-buffer size. Inner MTU is ~1252; a QUIC DATAGRAM payload
	// (contextID varint + inner packet) stays well under this. Larger frames
	// fall back to a fresh allocation.
	maxDatagramRcvBufSize = 1500
)

// datagramRcvBufPool recycles the per-datagram receive buffers allocated in
// HandleDatagramFrame, eliminating one alloc+GC cycle per received datagram on
// the hot path (bulk data AND the ACK flood). See Receive for the recycling
// invariant.
var datagramRcvBufPool = sync.Pool{New: func() any { return make([]byte, maxDatagramRcvBufSize) }}

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	lastRcv  []byte        // buffer handed out by the previous Receive, recycled on the next
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

// Add queues a new DATAGRAM frame for sending. The queue is bounded; when full
// it DROPS (returns nil) rather than blocking.
//
// This is deliberately NOT upstream's blocking Add. Datagrams are unreliable and
// every other stage of this dataplane drops on overflow. Worse, blocking here
// deadlocks the caller's goroutine until the connection's idle timeout: with
// congestion control disabled the sender keeps emitting to a vanished peer until
// MaxOutstandingSentPackets is hit, at which point SendMode stops draining the
// queue — so a blocking Add would wedge the per-connection drain goroutine for
// the full MaxIdleTimeout (~30s) after a disconnect, stalling the next reconnect.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()
	if h.sendQueue.Len() >= maxDatagramSendQueueLen {
		h.sendMx.Unlock()
		datagramSendDrops.Add(1)
		return nil // queue full → drop (unreliable datagram)
	}
	h.sendQueue.PushBack(f)
	h.sendMx.Unlock()
	h.hasData()
	return nil
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	var data []byte
	if len(f.Data) <= maxDatagramRcvBufSize {
		data = datagramRcvBufPool.Get().([]byte)[:len(f.Data)]
	} else {
		data = make([]byte, len(f.Data))
	}
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued {
		if cap(data) == maxDatagramRcvBufSize {
			datagramRcvBufPool.Put(data[:cap(data)])
		}
		datagramRcvDrops.Add(1)
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			// Recycle the buffer returned by the PREVIOUS Receive call. Safe
			// because there is a single sequential consumer per connection
			// (connect-ip Conn.ReadPacket) that fully copies the slice out
			// before calling Receive again. Do NOT call Receive concurrently
			// for one connection, or this becomes a use-after-free.
			if h.lastRcv != nil {
				datagramRcvBufPool.Put(h.lastRcv[:cap(h.lastRcv)])
				h.lastRcv = nil
			}
			if cap(data) == maxDatagramRcvBufSize {
				h.lastRcv = data
			}
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}
