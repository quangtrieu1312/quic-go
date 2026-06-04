package quic

import (
	"bytes"
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// These tests exercise sendPacketsWithGSO (connection.go), the fork's GSO
// coalescer for the DATAGRAM datapath. Unlike upstream — which only coalesces
// full-maxSize packets and therefore can never produce an oversize trailing
// segment — this fork coalesces uniform sub-maxSize packets (a QUIC packet
// carrying one MTU-sized DATAGRAM lands a few bytes under maxSize). That makes
// it possible for a smaller packet to lead and a larger one to follow, which
// must NOT be appended as an oversize trailing segment: Linux UDP_SEGMENT
// requires every non-final segment to equal gso_size and the final one to be
// <= gso_size, else the whole sendmsg is rejected with EINVAL and the
// connection is torn down.
//
// The tests drive sendPacketsWithGSO directly (it runs entirely on the conn's
// run goroutine in production, so a synchronous call is faithful) and capture
// every buffer handed to the send queue via a MockSender.

type gsoSend struct {
	data    []byte
	gsoSize uint16
	ecn     protocol.ECN
}

// assertValidGSO checks that data is a legal UDP_SEGMENT payload AND that its
// segment boundaries align with real packet boundaries. Each packet in these
// tests is filled with a distinct byte value, so a coalesced buffer's packets
// are recoverable as maximal runs of equal bytes. The bug under test produces a
// buffer whose packet boundaries do NOT align with gsoSize (a packet larger
// than gso_size), which the kernel rejects.
func assertValidGSO(t *testing.T, data []byte, gsoSize uint16) {
	t.Helper()
	require.NotEmpty(t, data)

	var runs []int
	for i := 0; i < len(data); {
		j := i + 1
		for j < len(data) && data[j] == data[i] {
			j++
		}
		runs = append(runs, j-i)
		i = j
	}

	if gsoSize == 0 {
		require.Lenf(t, runs, 1, "a single-segment buffer (gsoSize=0) must hold exactly one packet, got %d", len(runs))
		return
	}
	for k, r := range runs {
		if k == len(runs)-1 {
			require.LessOrEqualf(t, r, int(gsoSize),
				"final segment %d is %d bytes, exceeds gsoSize %d -> sendmsg EINVAL", k, r, gsoSize)
		} else {
			require.Equalf(t, int(gsoSize), r,
				"non-final segment %d is %d bytes, != gsoSize %d -> sendmsg EINVAL", k, r, gsoSize)
		}
	}
}

// newGSOTestConn builds a server connection wired for direct sendPacketsWithGSO
// calls: the real send queue is replaced by a MockSender that records every
// Send into the returned slice and reports WouldBlock from the returned flag.
func newGSOTestConn(t *testing.T, ctrl *gomock.Controller, sph ackhandler.SentPacketHandler) (*testConnection, *[]gsoSend, *bool) {
	t.Helper()
	tc := newServerTestConnection(t, ctrl, nil, true,
		connectionOptHandshakeConfirmed(),
		connectionOptSentPacketHandler(sph),
	)
	sends := new([]gsoSend)
	wouldBlock := new(bool) // false: the send queue has room
	ms := NewMockSender(ctrl)
	ms.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
			*sends = append(*sends, gsoSend{
				data:    append([]byte(nil), p.Data...),
				gsoSize: gsoSize,
				ecn:     ecn,
			})
		},
	).AnyTimes()
	ms.EXPECT().WouldBlock().DoAndReturn(func() bool { return *wouldBlock }).AnyTimes()
	tc.conn.sendQueue = ms
	return tc, sends, wouldBlock
}

// allowAllSends configures the sent-packet handler to permit unrestricted
// sending with a constant ECT(1) marking.
func allowAllSends(sph *mockackhandler.MockSentPacketHandler) {
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
	sph.EXPECT().TimeUntilSend().AnyTimes()
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
	sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()
}

// stubPackets makes the packer append, in order, one short-header packet per
// given size (each filled with a distinct byte value so packet boundaries are
// recoverable from a coalesced buffer), then return errNothingToPack.
func stubPackets(packer *MockPacker, sizes ...int) {
	var calls []any
	for i, size := range sizes {
		payload := bytes.Repeat([]byte{byte(i)}, size)
		pn := protocol.PacketNumber(i)
		calls = append(calls, packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
				buf.Data = append(buf.Data, payload...)
				return shortHeaderPacket{PacketNumber: pn}, nil
			},
		))
	}
	calls = append(calls, packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(shortHeaderPacket{}, errNothingToPack).AnyTimes())
	gomock.InOrder(calls...)
}

// A small packet (e.g. a pure-ACK) followed by a full-MTU packet. The buggy
// code recorded the small packet's size as the GSO segment size and then
// appended the larger packet as an oversize trailing segment -> EINVAL. The fix
// flushes the small packet, detaches the large one, and sends it as its own
// datagram.
func TestGSOFlushBeforeOversizeSegment(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	allowAllSends(sph)
	tc, sends, _ := newGSOTestConn(t, ctrl, sph)

	maxSize := int(tc.conn.maxPacketSize())
	const small = 30
	stubPackets(tc.packer, small, maxSize)

	require.NoError(t, tc.conn.sendPacketsWithGSO(monotime.Now()))

	require.Len(t, *sends, 2)
	for _, s := range *sends {
		assertValidGSO(t, s.data, s.gsoSize)
	}
	require.Equal(t, small, len((*sends)[0].data))
	require.Equal(t, uint16(0), (*sends)[0].gsoSize)
	require.Equal(t, maxSize, len((*sends)[1].data))
	require.Equal(t, uint16(0), (*sends)[1].gsoSize)
}

// The fork's reason to exist: coalesce uniform sub-maxSize DATAGRAM packets into
// one multi-segment GSO buffer (upstream would flush each separately because
// size != maxSize).
func TestGSOCoalesceUniformSubMaxSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	allowAllSends(sph)
	tc, sends, _ := newGSOTestConn(t, ctrl, sph)

	seg := int(tc.conn.maxPacketSize()) - 24
	stubPackets(tc.packer, seg, seg, seg)

	require.NoError(t, tc.conn.sendPacketsWithGSO(monotime.Now()))

	require.Len(t, *sends, 1)
	s := (*sends)[0]
	require.Equal(t, uint16(seg), s.gsoSize)
	require.Equal(t, 3*seg, len(s.data))
	assertValidGSO(t, s.data, s.gsoSize)
}

// Full-maxSize packets coalesce into one GSO buffer (the upstream-compatible
// path; must still work after the fix).
func TestGSOCoalesceMaxSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	allowAllSends(sph)
	tc, sends, _ := newGSOTestConn(t, ctrl, sph)

	maxSize := int(tc.conn.maxPacketSize())
	stubPackets(tc.packer, maxSize, maxSize, maxSize, maxSize)

	require.NoError(t, tc.conn.sendPacketsWithGSO(monotime.Now()))

	require.Len(t, *sends, 1)
	s := (*sends)[0]
	require.Equal(t, uint16(maxSize), s.gsoSize)
	require.Equal(t, 4*maxSize, len(s.data))
	assertValidGSO(t, s.data, s.gsoSize)
}

// A packet smaller than segSize is a valid final segment and ends the batch;
// the send loop then starts a fresh batch for the next packet.
func TestGSOSmallerPacketEndsBatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	allowAllSends(sph)
	tc, sends, _ := newGSOTestConn(t, ctrl, sph)

	maxSize := int(tc.conn.maxPacketSize())
	stubPackets(tc.packer, maxSize, maxSize, maxSize, maxSize-1, 6)

	require.NoError(t, tc.conn.sendPacketsWithGSO(monotime.Now()))

	require.Len(t, *sends, 2)
	require.Equal(t, uint16(maxSize), (*sends)[0].gsoSize)
	require.Equal(t, 3*maxSize+(maxSize-1), len((*sends)[0].data))
	assertValidGSO(t, (*sends)[0].data, (*sends)[0].gsoSize)
	require.Equal(t, uint16(0), (*sends)[1].gsoSize)
	require.Equal(t, 6, len((*sends)[1].data))
}

// A change in ECN marking ends the current GSO batch (each buffer carries a
// single ECN value).
func TestGSOECNChangeEndsBatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	ecnMode := protocol.ECT1
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
	sph.EXPECT().TimeUntilSend().AnyTimes()
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
	sph.EXPECT().ECNMode(gomock.Any()).DoAndReturn(func(bool) protocol.ECN { return ecnMode }).AnyTimes()
	tc, sends, _ := newGSOTestConn(t, ctrl, sph)

	maxSize := int(tc.conn.maxPacketSize())
	var calls []any
	for i := range 3 {
		payload := bytes.Repeat([]byte{byte(i)}, maxSize)
		flip := i == 2
		calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
				buf.Data = append(buf.Data, payload...)
				if flip {
					ecnMode = protocol.ECNCE
				}
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(20 + i)}, nil
			},
		))
	}
	calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
			buf.Data = append(buf.Data, bytes.Repeat([]byte{0xff}, 6)...)
			return shortHeaderPacket{PacketNumber: protocol.PacketNumber(24)}, nil
		},
	))
	calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(shortHeaderPacket{}, errNothingToPack).AnyTimes())
	gomock.InOrder(calls...)

	require.NoError(t, tc.conn.sendPacketsWithGSO(monotime.Now()))

	require.Len(t, *sends, 2)
	require.Equal(t, 3*maxSize, len((*sends)[0].data))
	require.Equal(t, uint16(maxSize), (*sends)[0].gsoSize)
	require.Equal(t, protocol.ECT1, (*sends)[0].ecn)
	assertValidGSO(t, (*sends)[0].data, (*sends)[0].gsoSize)
	require.Equal(t, 6, len((*sends)[1].data))
	require.Equal(t, uint16(0), (*sends)[1].gsoSize)
	require.Equal(t, protocol.ECNCE, (*sends)[1].ecn)
}

// When the send queue fills up right after the small prefix is flushed, the
// detached oversize packet — already registered as sent — must be stashed and
// flushed first on the next call, never dropped.
func TestGSOStashOversizeOnFullQueue(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(ctrl)
	allowAllSends(sph)
	tc, sends, wouldBlock := newGSOTestConn(t, ctrl, sph)

	maxSize := int(tc.conn.maxPacketSize())
	const small = 30
	stubPackets(tc.packer, small, maxSize)

	*wouldBlock = true // the queue is full immediately after the first Send
	require.NoError(t, tc.conn.sendPacketsWithGSO(monotime.Now()))

	require.Len(t, *sends, 1)
	require.Equal(t, small, len((*sends)[0].data))
	require.NotNil(t, tc.conn.gsoStash, "oversize packet must be stashed, not dropped")
	require.Equal(t, maxSize, int(tc.conn.gsoStash.Len()))

	*wouldBlock = false // room again
	require.NoError(t, tc.conn.sendPacketsWithGSO(monotime.Now()))

	require.Nil(t, tc.conn.gsoStash)
	require.Len(t, *sends, 2)
	require.Equal(t, maxSize, len((*sends)[1].data))
	require.Equal(t, uint16(0), (*sends)[1].gsoSize)
	assertValidGSO(t, (*sends)[1].data, (*sends)[1].gsoSize)
}
