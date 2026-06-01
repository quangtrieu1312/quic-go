package http3

import (
	"context"
	"errors"
	"expvar"
	"os"
	"sync"

	"github.com/quic-go/quic-go"
)

// streamDatagramQueueLen sits between quic-go's datagramQueue.Receive and
// connect-ip's ReadPacket. Empirical tuning at P100 -R:
//   - 1024: ~700 Mbps, ~29k drops (drops are LOSS signals, not reorder — cwnd
//     backoff keeps the cwnd-ramp aggressive so throughput is higher).
//   - 4096: 637-686 Mbps, 0 drops, ~26ms bufferbloat (drops vanish but the deeper
//     queue stalls inner-TCP cwnd ramp; net-negative).
//   - 16384: ~620 Mbps, same bufferbloat — diminishing returns.
// 1024 is the sweet spot: best throughput. Reorder is unaffected (this queue is
// FIFO; only drops change, and a drop is loss not reorder).
const streamDatagramQueueLen = 1024

// Instrumentation for the http3 per-stream datagram receive queue — the layer
// between quic-go's datagramQueue.Receive and connect-ip's ReadPacket. Drops here
// are silent client-side download loss, invisible to the quic-layer dg_* counters.
// h3_stream_dgram_drops counts overflow drops; h3_stream_dgram_highwater is the
// max observed queue depth (== streamDatagramQueueLen means it saturated).
var (
	h3StreamDatagramDrops     = expvar.NewInt("h3_stream_dgram_drops")
	h3StreamDatagramHighWater = expvar.NewInt("h3_stream_dgram_highwater")
)

// stateTrackingStream is an implementation of quic.Stream that delegates
// to an underlying stream
// it takes care of proxying send and receive errors onto an implementation of
// the errorSetter interface (intended to be occupied by a datagrammer)
// it is also responsible for clearing the stream based on its ID from its
// parent connection, this is done through the streamClearer interface when
// both the send and receive sides are closed
type stateTrackingStream struct {
	*quic.Stream

	sendDatagram func([]byte) error
	hasData      chan struct{}
	queue        [][]byte // TODO: use a ring buffer

	mx      sync.Mutex
	sendErr error
	recvErr error

	clearer streamClearer
}

var _ datagramStream = &stateTrackingStream{}

type streamClearer interface {
	clearStream(quic.StreamID)
}

func newStateTrackingStream(s *quic.Stream, clearer streamClearer, sendDatagram func([]byte) error) *stateTrackingStream {
	t := &stateTrackingStream{
		Stream:       s,
		clearer:      clearer,
		sendDatagram: sendDatagram,
		hasData:      make(chan struct{}, 1),
	}

	context.AfterFunc(s.Context(), func() {
		t.closeSend(context.Cause(s.Context()))
	})

	return t
}

func (s *stateTrackingStream) closeSend(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.sendErr == nil {
		if s.recvErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.sendErr = e
	}
}

func (s *stateTrackingStream) closeReceive(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.recvErr == nil {
		if s.sendErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.recvErr = e
		s.signalHasDatagram()
	}
}

func (s *stateTrackingStream) Close() error {
	s.closeSend(errors.New("write on closed stream"))
	return s.Stream.Close()
}

func (s *stateTrackingStream) CancelWrite(e quic.StreamErrorCode) {
	s.closeSend(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelWrite(e)
}

func (s *stateTrackingStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeSend(err)
	}
	return n, err
}

func (s *stateTrackingStream) CancelRead(e quic.StreamErrorCode) {
	s.closeReceive(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelRead(e)
}

func (s *stateTrackingStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeReceive(err)
	}
	return n, err
}

func (s *stateTrackingStream) SendDatagram(b []byte) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}

	return s.sendDatagram(b)
}

func (s *stateTrackingStream) signalHasDatagram() {
	select {
	case s.hasData <- struct{}{}:
	default:
	}
}

func (s *stateTrackingStream) enqueueDatagram(data []byte) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.recvErr != nil {
		return
	}
	if len(s.queue) >= streamDatagramQueueLen {
		h3StreamDatagramDrops.Add(1)
		return
	}
	s.queue = append(s.queue, data)
	if d := int64(len(s.queue)); d > h3StreamDatagramHighWater.Value() {
		h3StreamDatagramHighWater.Set(d)
	}
	s.signalHasDatagram()
}

func (s *stateTrackingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
start:
	s.mx.Lock()
	if len(s.queue) > 0 {
		data := s.queue[0]
		s.queue = s.queue[1:]
		s.mx.Unlock()
		return data, nil
	}
	if receiveErr := s.recvErr; receiveErr != nil {
		s.mx.Unlock()
		return nil, receiveErr
	}
	s.mx.Unlock()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.hasData:
	}
	goto start
}

func (s *stateTrackingStream) QUICStream() *quic.Stream {
	return s.Stream
}
