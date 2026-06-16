package quic

import (
	"context"
	"encoding/binary"
	"expvar"
	"os"
	"sync"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"
)

// dgObserveEnabled gates the diagnostic inner-TCP-seq reorder counters
// (dg_send/dg_rcvin/dg_rcvout/dg_packer). They run a per-flow seen-set map op +
// flow-hash on EVERY datagram — profiling showed ~5% of gw CPU under load — so they
// default OFF. Set QUIC_GO_DG_OBSERVE=1 to re-enable for reorder diagnostics.
var dgObserveEnabled = os.Getenv("QUIC_GO_DG_OBSERVE") == "1"

// Datagram-queue drop counters. These are the blind spot the app-level drop
// counters don't cover — a full send/recv queue here silently drops an
// (unrecoverable) datagram. Exposed via expvar, so they show up at
// /debug/vars on any binary that serves net/http/pprof (server :6060,
// client :9484). Watch the delta across a test to localize tunnel loss.
var (
	datagramSendDrops = expvar.NewInt("quic_datagram_send_drops")
	datagramRcvDrops  = expvar.NewInt("quic_datagram_rcv_drops")
)

// Datagram inner-TCP-seq order counters. These localize where the download inner
// reorder enters the quic-go datagram transport. Each counts a datagram as
// out-of-order when its inner TCP seq is below the per-flow high-water mark seen
// so far at that point (a retransmit also registers, but the retransmit baseline
// is constant across points, so the DELTA between points = genuine reorder added):
//   dg_send_*   : at Pop (sender commits datagram to a packet) — server=download send
//   dg_rcvin_*  : at HandleDatagramFrame (receiver enqueues)    — client=download recv-in
//   dg_rcvout_* : at Receive (receiver delivers to app)         — client=download recv-out
// Payload is connect-ip [contextID varint][IP packet]; non-TCP/short frames skipped.
var (
	dgSendTotal   = expvar.NewInt("dg_send_total")
	dgSendOOO     = expvar.NewInt("dg_send_ooo")
	dgRcvInTotal  = expvar.NewInt("dg_rcvin_total")
	dgRcvInOOO    = expvar.NewInt("dg_rcvin_ooo")
	dgRcvOutTotal = expvar.NewInt("dg_rcvout_total")
	dgRcvOutOOO   = expvar.NewInt("dg_rcvout_ooo")

	// Post-packer seen-set counters (split retransmits vs genuine reorder), measured
	// AFTER the anti-ossification frame shuffle in appendPacketPayload, in the order
	// frames will be serialized on the wire. Compared against the source-side
	// pre-send (tunChan consumer, also seen-set) to localize whether the quic-go
	// packer reorders DATAGRAM frames between SendDatagram and wire encoding.
	dgPackerTotal   = expvar.NewInt("dg_packer_total")
	dgPackerGenuine = expvar.NewInt("dg_packer_genuine")
	dgPackerRetr    = expvar.NewInt("dg_packer_retr")

	// Seen-set companions for dg_send / dg_rcvin / dg_rcvout. Same observation
	// points as the *_total/_ooo above but split retransmits from genuine reorder.
	// Reorder enters between two consecutive points if their genuine deltas differ.
	dgSendGenuine   = expvar.NewInt("dg_send_genuine")
	dgSendRetr      = expvar.NewInt("dg_send_retr")
	dgRcvInGenuine  = expvar.NewInt("dg_rcvin_genuine")
	dgRcvInRetr     = expvar.NewInt("dg_rcvin_retr")
	dgRcvOutGenuine = expvar.NewInt("dg_rcvout_genuine")
	dgRcvOutRetr    = expvar.NewInt("dg_rcvout_retr")
)

// dgInnerSeq parses a quic-level DATAGRAM payload into a 5-tuple flow key and the
// inner TCP sequence number. At the quic layer the payload is HTTP/3-datagram framed:
// [Quarter Stream ID varint][Context ID varint][IP packet] (RFC 9297 + connect-ip).
// ok is false for non-IPv4, non-TCP, or truncated frames.
func dgInnerSeq(p []byte) (key [13]byte, seq uint32, ok bool) {
	off := 0
	// skip the Quarter Stream ID then the Context ID varint
	for i := 0; i < 2; i++ {
		if off >= len(p) {
			return
		}
		off += 1 << (p[off] >> 6)
	}
	if len(p) < off+20 {
		return
	}
	ip := p[off:]
	if ip[0]>>4 != 4 || ip[9] != 6 { // IPv4 + TCP
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+8 {
		return
	}
	tcp := ip[ihl:]
	seq = binary.BigEndian.Uint32(tcp[4:8])
	copy(key[0:4], ip[12:16])
	copy(key[4:8], ip[16:20])
	copy(key[8:12], tcp[0:4]) // src+dst ports
	key[12] = 6
	ok = true
	return
}

// dgObs tracks per-flow inner-seq high-water marks at one observation point. Each
// instance is touched by a single goroutine (Pop/HandleDatagramFrame by the conn
// run loop; Receive by the app reader), so it needs no lock.
type dgObs struct{ maxSeq map[[13]byte]uint32 }

func newDgObs() *dgObs { return &dgObs{maxSeq: make(map[[13]byte]uint32)} }

func (o *dgObs) observe(p []byte, total, ooo *expvar.Int) {
	key, seq, ok := dgInnerSeq(p)
	if !ok {
		return
	}
	total.Add(1)
	mx, seen := o.maxSeq[key]
	switch {
	case !seen:
		if len(o.maxSeq) >= 1<<16 {
			o.maxSeq = make(map[[13]byte]uint32)
		}
		o.maxSeq[key] = seq
	case int32(seq-mx) < 0:
		ooo.Add(1)
	default:
		o.maxSeq[key] = seq
	}
}

// dgGenObs is the genuine-reorder variant: per-flow seen-set on a bounded ring of
// recent seqs, so a sub-max seq is classified RETR (already in ring) vs GENUINE
// (not in ring — the producer reordered new data). Mirrors PreSendGenuineObserver
// in tmasqued's utility package. Single-goroutine per instance (the conn send loop
// at the packer), so no lock. Bounded memory: ≤256 flows * (1024 uint32 + map) ≈ 9MB.
const dgPackerRingSize = 1024

type dgPackerFlow struct {
	maxSeq uint32
	ring   [dgPackerRingSize]uint32
	in     map[uint32]struct{}
	head   int
	count  int
}

type dgGenObs struct {
	flows map[[13]byte]*dgPackerFlow
}

func newDgGenObs() *dgGenObs { return &dgGenObs{flows: make(map[[13]byte]*dgPackerFlow)} }

func (o *dgGenObs) observe(p []byte, total, genuine, retr *expvar.Int) {
	key, seq, ok := dgInnerSeq(p)
	if !ok {
		return
	}
	total.Add(1)
	f, exists := o.flows[key]
	if !exists {
		if len(o.flows) >= 256 {
			o.flows = make(map[[13]byte]*dgPackerFlow)
		}
		f = &dgPackerFlow{in: make(map[uint32]struct{}, dgPackerRingSize)}
		o.flows[key] = f
	}
	if _, dup := f.in[seq]; dup {
		retr.Add(1)
		return
	}
	if f.count == dgPackerRingSize {
		delete(f.in, f.ring[f.head])
	} else {
		f.count++
	}
	f.ring[f.head] = seq
	f.head = (f.head + 1) % dgPackerRingSize
	f.in[seq] = struct{}{}
	if f.count == 1 || int32(seq-f.maxSeq) >= 0 {
		f.maxSeq = seq
		return
	}
	genuine.Add(1)
}

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
	maxDatagramSendQueueLen = 8192
	maxDatagramRcvQueueLen  = 1024
)

// We used to have a sync.Pool of fixed-size buffers here that HandleDatagramFrame
// copied into, with Receive recycling the buffer on the NEXT call. That broke when
// the consumer turned out to be a two-stage pipeline (http3 stream queue → connect-ip
// ReadPacket), because the recycle fired before the final consumer had finished
// reading the slice — a use-after-free that surfaced as inner-TCP reorder during
// bursts. Removed: parseDatagramFrame already allocates f.Data fresh per packet,
// so storing the reference directly is one alloc (same as before, just GC-owned)
// with no race, no extra copy, and lower GC pressure than the copy-on-enqueue
// workaround. See HandleDatagramFrame for details.

// sendDatagramDataPool recycles the SEND-side DatagramFrame.Data buffer. The
// allocation site is Conn.SendDatagram (connection.go); the bytes are read once
// when packet_packer.go appendPacketPayload calls f.Append(raw, v), which copies
// them into the wire buffer. After that, no quic-go code reads f.Data again:
//   - DatagramFrame.Handler is nil for app-sent datagrams (the packer attaches no
//     handler), so OnAcked/OnLost are no-ops.
//   - connection_logging.go toQlogFrame reads only len(f.Data).
//   - wire.LogFrame's DatagramFrame branch is gated by logger.Debug() — prod runs
//     at info, so the %#v fallback never fires.
// Recycling at appendPacketPayload's tail removes ~75 MB/s of GC at line rate
// (60k pkt/s × 1260B). The pool returns ≥1600-cap bufs; SendDatagram falls back
// to a fresh make() if the payload exceeds the pool cap. Recv-side
// DatagramFrames take a different path (HandleDatagramFrame → rcvQueue) and
// never reach the packer's recycle point.
const sendDatagramPoolBufCap = 1600

var sendDatagramDataPool = sync.Pool{
	New: func() any { return make([]byte, 0, sendDatagramPoolBufCap) },
}

// recycleSendDatagramData returns f.Data to the send-side pool if it came from
// there (cap == pool cap). Oversized payloads bypassed the pool in SendDatagram
// and have a smaller cap, so they're left for GC. Called from the packet packer
// right after the frame's bytes have been Append'd into the wire buffer.
func recycleSendDatagramData(f *wire.DatagramFrame) {
	if cap(f.Data) == sendDatagramPoolBufCap {
		sendDatagramDataPool.Put(f.Data[:0])
	}
	f.Data = nil
}

// computeFlowHash returns a STABLE per-inner-flow hash for a SendDatagram
// payload — layout [QSID varint][connect-ip contextID varint][IP packet]. The
// same (src IP, dst IP, proto, src port, dst port) always maps to the same
// 32-bit value, so TX dispatch can route a flow's frames to one worker for
// life and avoid intra-flow reorder. FNV-1a; cheap (~tens of ns per pkt).
//
// Returns 0 for anything that doesn't parse cleanly as IPv4 or IPv6 (control
// traffic, malformed frames, etc.) — these are uncommon and all collapse to
// worker 0 deterministically, which is fine because they're not bandwidth
// drivers and ordering still holds (single worker = serial).
//
// CRITICAL: this is computed ONCE at SendDatagram time and stashed on the
// DatagramFrame. NEVER recompute from f.Data later — the buffer may have been
// recycled into [[sendDatagramDataPool]] by the time the packer/TX touches it.
func computeFlowHash(p []byte) uint32 {
	// Skip QSID varint (added by http3 sendDatagram).
	_, n1, err := quicvarint.Parse(p)
	if err != nil || n1 >= len(p) {
		return 0
	}
	// Skip connect-ip contextID varint.
	_, n2, err := quicvarint.Parse(p[n1:])
	if err != nil || n1+n2 >= len(p) {
		return 0
	}
	ip := p[n1+n2:]
	if len(ip) < 1 {
		return 0
	}
	var srcIP, dstIP []byte
	var proto uint8
	var l4 []byte
	switch ip[0] >> 4 {
	case 4:
		if len(ip) < 20 {
			return 0
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl {
			return 0
		}
		proto = ip[9]
		srcIP = ip[12:16]
		dstIP = ip[16:20]
		l4 = ip[ihl:]
	case 6:
		if len(ip) < 40 {
			return 0
		}
		proto = ip[6]
		srcIP = ip[8:24]
		dstIP = ip[24:40]
		l4 = ip[40:]
	default:
		return 0
	}
	var srcPort, dstPort uint16
	if (proto == 6 /* TCP */ || proto == 17 /* UDP */) && len(l4) >= 4 {
		srcPort = binary.BigEndian.Uint16(l4[0:2])
		dstPort = binary.BigEndian.Uint16(l4[2:4])
	}
	const offset64 = uint64(1469598103934665603) // FNV-1a 64-bit offset basis
	const prime64 = uint64(1099511628211)        // FNV-1a 64-bit prime
	h := offset64
	for _, b := range srcIP {
		h = (h ^ uint64(b)) * prime64
	}
	for _, b := range dstIP {
		h = (h ^ uint64(b)) * prime64
	}
	h = (h ^ uint64(proto)) * prime64
	h = (h ^ uint64(srcPort)) * prime64
	h = (h ^ uint64(dstPort)) * prime64
	return uint32(h ^ (h >> 32))
}

type datagramQueue struct {
	sendMx sync.Mutex
	// sendBuckets holds N FIFO ring buffers, one per FlowHash bucket. With N=1
	// (default, today's behavior), the single bucket holds all datagrams in
	// arrival order. With N>1, [[datagramQueue.Add]] routes by
	// `f.FlowHash % N` so a flow's frames always land in the SAME bucket —
	// consumed by the SAME TX worker/socket downstream → no intra-flow reorder
	// when the TX path fans out. Existing Peek()/Pop() shim to bucket 0 so the
	// single-bucket case is byte-identical to the pre-bucketing code.
	sendBuckets []*ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent        chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	sendObs   *dgObs
	rcvInObs  *dgObs
	rcvOutObs *dgObs

	// seen-set observers (genuine reorder vs retransmit) at the same 3 points
	sendGen   *dgGenObs
	rcvInGen  *dgGenObs
	rcvOutGen *dgGenObs

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return newDatagramQueueBucketed(hasData, logger, 1)
}

// newDatagramQueueBucketed creates a datagram queue with N send buckets. With
// numBuckets == 1 the queue is byte-identical in behavior to the pre-bucketing
// code (single FIFO across all flows). With N>1, [[datagramQueue.Add]] routes
// each frame to bucket `f.FlowHash % N` so per-flow ordering is preserved when
// the downstream TX path picks a socket by bucket index.
func newDatagramQueueBucketed(hasData func(), logger utils.Logger, numBuckets int) *datagramQueue {
	if numBuckets < 1 {
		numBuckets = 1
	}
	buckets := make([]*ringbuffer.RingBuffer[*wire.DatagramFrame], numBuckets)
	for i := range buckets {
		buckets[i] = &ringbuffer.RingBuffer[*wire.DatagramFrame]{}
	}
	return &datagramQueue{
		hasData:     hasData,
		rcvd:        make(chan struct{}, 1),
		sent:        make(chan struct{}, 1),
		closed:      make(chan struct{}),
		sendBuckets: buckets,
		sendObs:     newDgObs(),
		rcvInObs:    newDgObs(),
		rcvOutObs:   newDgObs(),
		sendGen:     newDgGenObs(),
		rcvInGen:    newDgGenObs(),
		rcvOutGen:   newDgGenObs(),
		logger:      logger,
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
	bucket := h.sendBuckets[int(f.FlowHash%uint32(len(h.sendBuckets)))]
	if bucket.Len() >= maxDatagramSendQueueLen {
		h.sendMx.Unlock()
		datagramSendDrops.Add(1)
		return nil // bucket full → drop (unreliable datagram)
	}
	bucket.PushBack(f)
	h.sendMx.Unlock()
	h.hasData()
	return nil
}

// Peek gets the next DATAGRAM frame for sending. Shim over PeekBucket(0) — with
// the default single bucket this is byte-identical to the pre-bucketing code.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	return h.PeekBucket(0)
}

// Pop removes the frame at the front of bucket 0 (shim over PopBucket(0)).
// Identical to the pre-bucketing behavior under the default single-bucket
// configuration.
func (h *datagramQueue) Pop() {
	h.PopBucket(0)
}

// PeekBucket returns the front frame of bucket `idx` without removing it. Out-of-
// range indices return nil so callers iterating buckets can safely probe.
func (h *datagramQueue) PeekBucket(idx int) *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if idx < 0 || idx >= len(h.sendBuckets) {
		return nil
	}
	bucket := h.sendBuckets[idx]
	if bucket.Empty() {
		return nil
	}
	return bucket.PeekFront()
}

// PopBucket removes the front frame of bucket `idx`, runs the dg_send_* observers
// on it (so they see frames in the order they leave the queue), and signals the
// `sent` channel. No-op for an empty bucket or out-of-range index.
func (h *datagramQueue) PopBucket(idx int) {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if idx < 0 || idx >= len(h.sendBuckets) {
		return
	}
	bucket := h.sendBuckets[idx]
	if bucket.Empty() {
		return
	}
	f := bucket.PopFront()
	if f != nil && dgObserveEnabled {
		h.sendObs.observe(f.Data, dgSendTotal, dgSendOOO)
		h.sendGen.observe(f.Data, dgSendTotal, dgSendGenuine, dgSendRetr)
	}
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// NumBuckets returns the number of send buckets; useful for the packet packer
// and TX path when deciding rotation / per-socket dispatch.
func (h *datagramQueue) NumBuckets() int {
	return len(h.sendBuckets)
}

// HandleDatagramFrame handles a received DATAGRAM frame.
//
// Buffer ownership: f.Data is freshly allocated by parseDatagramFrame (see
// wire/datagram_frame.go: `f.Data = make([]byte, length)`), so we can store the
// reference directly without an additional copy. The previous version copied
// into a sync.Pool buffer and recycled it on the NEXT Receive() call — but the
// consumer is actually a TWO-STAGE pipeline (datagram_queue → http3 stream
// queue → connect-ip ReadPacket), and the recycle fired BEFORE the final
// consumer had read the slice. That caused a use-after-free that surfaced as
// inner-TCP reorder. Holding f.Data directly: one allocation per packet (same
// as parseDatagramFrame already does), no race, no extra copy, no pool — and
// the keepalive PING handling is no longer delayed by per-packet copy GC.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	if dgObserveEnabled {
		h.rcvInObs.observe(f.Data, dgRcvInTotal, dgRcvInOOO)
		h.rcvInGen.observe(f.Data, dgRcvInTotal, dgRcvInGenuine, dgRcvInRetr)
	}
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, f.Data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued {
		datagramRcvDrops.Add(1)
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
	}
}

// Receive gets a received DATAGRAM frame. The buffer is the same f.Data
// allocation `parseDatagramFrame` made on the wire-decode path; GC owns it
// after the consumer is done. No pool recycling, no use-after-free.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			h.rcvMx.Unlock()
			if dgObserveEnabled {
				h.rcvOutObs.observe(data, dgRcvOutTotal, dgRcvOutOOO)
				h.rcvOutGen.observe(data, dgRcvOutTotal, dgRcvOutGenuine, dgRcvOutRetr)
			}
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
