package congestion

import (
	"expvar"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

const maxBurstSizePackets = 10

// pacingFloorBytesPerSec is a lower bound on the pacer's rate, decoupled from the
// congestion window. The dataplane runs with congestion control disabled (see
// SendMode), but cwnd still shrinks on loss — and since the pacing rate is
// derived from cwnd, re-enabling pacing without this floor would let loss drag
// the send rate toward zero. The floor keeps the tunnel pacing at ~link rate:
// bursts are still smoothed (token bucket), but loss can't throttle throughput.
//
// Tune this to just under the path's bottleneck rate. Too high → bursts still
// overflow buffers; too low → caps throughput. 0 disables the floor (stock
// cwnd-derived pacing). Configurable at startup via TUNNEL_PACING_FLOOR_MBIT
// (Mbit/s; 0 disables); default ~150 Mbit/s per connection.
var pacingFloorBytesPerSec uint64 = 150 * 1000 * 1000 / 8

// quicPacerRateBps exposes the pacer's current send-rate ceiling (bits/s) for
// diagnostics: when this sits at the floor while throughput is capped, the floor
// is the bottleneck. Served at /debug/vars.
var quicPacerRateBps = expvar.NewInt("quic_pacer_rate_bps")

// maxBurstCapPackets caps the token-bucket max burst (in packets). This is the
// ONLY egress shaper under the CC-off dataplane invariant: with congestion
// control disabled the cwnd (and hence the pacing RATE) still tracks the
// bottleneck fine, but the stock max burst = bw×(MinPacingDelay+TimerGranularity)
// reaches ~150 packets at link rate. With the bucket sitting full, the inner
// TCP's bursts egress as line-rate microbursts that overrun a shallow fabric/NIC
// queue — measured as ~2% inner-TCP retransmits even though the SAME fabric
// carries smooth TCP at 22 Gbit/s with ZERO loss (so the loss is self-inflicted
// burstiness, not the underlay). Bounding the burst to a few MSS spreads the
// send (the pacer is continuous-time, so throughput = rate is preserved; only
// the instantaneous burst shrinks).
//
// Default 0 (uncapped/stock). Capping smooths egress but is COUPLED to the GSO
// batch size, so it trades throughput for loss (burst=4 → 0 loss but ~1.5G,
// syscall-bound; uncapped → ~3.2G but ~4% loss). There is no value that gives
// both, so this stays off by default and is exposed only as a tuning knob via
// TUNNEL_PACING_MAX_BURST_PKTS (now honored below the stock 10-packet floor).
// Kernel SO_MAX_PACING_RATE + fq (TUNNEL_SO_MAX_PACING_MBIT) was also tried and
// does NOT help: above the flow rate it doesn't engage, below it fq queue-drops.
var maxBurstCapPackets uint64 = 0

func init() {
	if v := os.Getenv("TUNNEL_PACING_FLOOR_MBIT"); v != "" {
		if m, err := strconv.ParseUint(v, 10, 64); err == nil {
			pacingFloorBytesPerSec = m * 1000 * 1000 / 8
		}
	}
	if v := os.Getenv("TUNNEL_PACING_MAX_BURST_PKTS"); v != "" {
		if m, err := strconv.ParseUint(v, 10, 64); err == nil {
			maxBurstCapPackets = m
		}
	}
}

// The pacer implements a token bucket pacing algorithm.
type pacer struct {
	budgetAtLastSent  protocol.ByteCount
	maxDatagramSize   protocol.ByteCount
	lastSentTime      monotime.Time
	adjustedBandwidth func() uint64 // in bytes/s
}

func newPacer(getBandwidth func() Bandwidth) *pacer {
	p := &pacer{
		maxDatagramSize: initialMaxDatagramSize,
		adjustedBandwidth: func() uint64 {
			// Bandwidth is in bits/s. We need the value in bytes/s.
			bw := uint64(getBandwidth() / BytesPerSecond)
			// Use a slightly higher value than the actual measured bandwidth.
			// RTT variations then won't result in under-utilization of the congestion window.
			// Ultimately, this will result in sending packets as acknowledgments are received rather than when timers fire,
			// provided the congestion window is fully utilized and acknowledgments arrive at regular intervals.
			bw = bw * 5 / 4
			// Floor the rate so loss-driven cwnd reduction can't throttle the
			// (congestion-control-disabled) dataplane. See pacingFloorBytesPerSec.
			if pacingFloorBytesPerSec > 0 && bw < pacingFloorBytesPerSec {
				bw = pacingFloorBytesPerSec
			}
			quicPacerRateBps.Set(int64(bw * 8))
			return bw
		},
	}
	p.budgetAtLastSent = p.maxBurstSize()
	return p
}

func (p *pacer) SentPacket(sendTime monotime.Time, size protocol.ByteCount) {
	budget := p.Budget(sendTime)
	if size >= budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *pacer) Budget(now monotime.Time) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	delta := now.Sub(p.lastSentTime)
	var added protocol.ByteCount
	if delta > 0 {
		added = p.timeScaledBandwidth(uint64(delta.Nanoseconds()))
	}
	budget := p.budgetAtLastSent + added
	if added > 0 && budget < p.budgetAtLastSent {
		budget = protocol.MaxByteCount
	}
	return min(p.maxBurstSize(), budget)
}

func (p *pacer) maxBurstSize() protocol.ByteCount {
	b := max(
		p.timeScaledBandwidth(uint64((protocol.MinPacingDelay + protocol.TimerGranularity).Nanoseconds())),
		maxBurstSizePackets*p.maxDatagramSize,
	)
	// Hard cap on the instantaneous burst to smooth egress (see maxBurstCapPackets).
	// Honor the configured value EVEN BELOW the stock maxBurstSizePackets floor:
	// under CC-off the pacer is the only shaper, and the whole point is to allow a
	// burst smaller than stock. Clamped to >=2 MSS so a 1-packet pathology can't
	// stall a GSO super-packet that is itself multiple segments.
	if maxBurstCapPackets > 0 {
		capPkts := maxBurstCapPackets
		if capPkts < 2 {
			capPkts = 2
		}
		cap := protocol.ByteCount(capPkts) * p.maxDatagramSize
		if b > cap {
			b = cap
		}
	}
	return b
}

// timeScaledBandwidth calculates the number of bytes that may be sent within
// a given time interval (ns nanoseconds), based on the current bandwidth estimate.
// It caps the scaled value to the maximum allowed burst and handles overflows.
func (p *pacer) timeScaledBandwidth(ns uint64) protocol.ByteCount {
	bw := p.adjustedBandwidth()
	if bw == 0 {
		return 0
	}
	const nsPerSecond = 1e9
	maxBurst := maxBurstSizePackets * p.maxDatagramSize
	var scaled protocol.ByteCount
	if ns > math.MaxUint64/bw {
		scaled = maxBurst
	} else {
		scaled = protocol.ByteCount(bw * ns / nsPerSecond)
	}
	return scaled
}

// TimeUntilSend returns when the next packet should be sent.
// It returns zero if a packet can be sent immediately.
func (p *pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := p.adjustedBandwidth()
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(protocol.MinPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *pacer) SetMaxDatagramSize(s protocol.ByteCount) {
	p.maxDatagramSize = s
}
