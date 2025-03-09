// https://github.com/pion/sctp/blob/bf53986cb1bbb4f7a71552bdd47f3e5a9802526a/stream.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

import (
    "errors"
    "fmt"
    "io"
    "os"
    "sync"
    "sync/atomic"
    "time"
)

use pion_rs_logging::logging;
use pion_rs_transport::deadline;

use crate::chunk_payload_data::PayloadProtocolIdentifier;

#[repr(u8)]
pub enum ReliabilityType {
    /// ReliabilityTypeReliable is used for reliable transmission.
    Reliable = 0,
    /// ReliabilityTypeRexmit is used for partial reliability by retransmission count.
    Rexmit = 1,
    /// ReliabilityTypeTimed is used for partial reliability by retransmission duration.
    Timed = 2,
}

/// StreamState is an enum for SCTP Stream state field
/// This field identifies the state of stream.
#[repr(i32)]
pub enum StreamState {
    /// Stream object starts with StreamStateOpen
    Open = 0,
    /// Outgoing stream is being reset
    Closing = 1,
    /// Stream has been closed
    Closed = 2,
}

impl StreamState {
    pub fn string(&self) -> String {
        match self {
            StreamState::Open => "open".to_string(),
            StreamState::Closing => "closing".to_string(),
            StreamState::Closed => "closed".to_string(),
        }
    }
}

// SCTP stream errors.
var (
    ErrOutboundPacketTooLarge = errors.New("outbound packet larger than maximum message size")
    ErrStreamClosed           = errors.New("stream closed")
    ErrReadDeadlineExceeded   = fmt.Errorf("read deadline exceeded: %w", os.ErrDeadlineExceeded)
)

/// Stream represents an SCTP stream.
pub struct Stream {
    association         *Association
    lock                sync.RWMutex
    streamIdentifier    uint16
    default_payload_type  PayloadProtocolIdentifier
    reassemblyQueue     *reassemblyQueue
    sequenceNumber      uint16
    readNotifier        *sync.Cond
    readErr             error
    read_timeout_cancel   chan struct{}
    writeDeadline       *deadline.Deadline
    writeLock           sync.Mutex
    unordered           bool
    reliabilityType     byte
    reliabilityValue    uint32
    bufferedAmount      uint64
    bufferedAmountLow   uint64
    onBufferedAmountLow func()
    state               StreamState
    log                 logging.LeveledLogger
    name                string
}

impl Stream {
    /// StreamIdentifier returns the Stream identifier associated to the stream.
    pub fn stream_identifier(&self) -> u16 {
        s.lock.RLock()
        defer s.lock.RUnlock()

        self.stream_identifier
    }

    /// SetDefaultPayloadType sets the default payload type used by Write.
    pub fn set_default_payload_type(&self, default_payload_type: PayloadProtocolIdentifier) {
        atomic.StoreUint32((*uint32)(&self.default_payload_type), default_payload_type as u32)
    }

    /// SetReliabilityParams sets reliability parameters for this stream.
    pub fn set_reliability_params(
        &self,
        unordered: bool,
        rel_type: ReliabilityType,
        rel_val: u32,
    ) {
        s.lock.Lock()
        defer s.lock.Unlock()

        s.setReliabilityParams(unordered, relType, relVal)
    }

    /// setReliabilityParams sets reliability parameters for this stream.
    /// The caller should hold the lock.
    fn setReliabilityParams(
        &self,
        unordered: bool,
        rel_type: ReliabilityType,
        rel_val: u32,
    ) {
        self.log.Debugf("[%s] reliability params: ordered=%v type=%d value=%d",
            s.name, !unordered, relType, relVal)
        s.unordered = unordered
        s.reliabilityType = relType
        s.reliabilityValue = relVal
    }

    /// Read reads a packet of len(p) bytes, dropping the Payload Protocol Identifier.
    /// Returns EOF when the stream is reset or an error if the stream is closed
    /// otherwise.
    pub fn read(&self, p: &mut [u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let (n, _) = self.read_sctp(p)?;

        Ok(n)
    }

    /// ReadSCTP reads a packet of len(payload) bytes and returns the associated Payload
    /// Protocol Identifier.
    /// Returns EOF when the stream is reset or an error if the stream is closed
    /// otherwise.
    pub fn read_sctp(
        &self,
        payload: &mut [u8],
    ) -> Result<(usize, PayloadProtocolIdentifier), Box<dyn std::error::Error>> {
        s.lock.Lock()
        defer s.lock.Unlock()

        defer func() {
            // close read_timeout_cancel if the current read timeout routine is no longer effective
            if self.read_timeout_cancel != nil && self.read_err != nil {
                close(self.read_timeout_cancel)
                self.read_timeout_cancel = nil
            }
        }()

        loop {
            match self.reassembly_queue.read(payload) {
                Ok((n, ppi)) => {
                    return Ok((n, ppi));
                }
                Err(e) => {
                    if errors.Is(e, io.ErrShortBuffer) {
                        return Ok((0, 0));
                    }

                    if let Some(err) = &self.read_err {
                        return Err(err.clone());
                    }
                }
            }

            self.read_notifier.wait();
        }
    }


    /// SetReadDeadline sets the read deadline in an identical way to net.Conn.
    pub fn set_read_deadline(&self, deadline: SystemTime) -> Result<(), StreamError> {
        s.lock.Lock()
        defer s.lock.Unlock()

        if self.read_timeout_cancel != nil {
            close(self.read_timeout_cancel)
            self.read_timeout_cancel = nil
        }

        if self.read_err != nil {
            if !errors.Is(self.read_err, ErrReadDeadlineExceeded) {
                return nil
            }
            self.read_err = nil
        }

        if !deadline.IsZero() {
            self.read_timeout_cancel = make(chan struct{})

            go func(read_timeout_cancel chan struct{}) {
                t := time.NewTimer(time.Until(deadline))
                select {
                case <-read_timeout_cancel:
                    t.Stop()

                    return
                case <-t.C:
                    select {
                    case <-read_timeout_cancel:
                        return
                    default:
                    }
                    s.lock.Lock()
                    if self.read_err == nil {
                        self.read_err = ErrReadDeadlineExceeded
                    }
                    self.read_timeout_cancel = nil
                    s.lock.Unlock()

                    self.read_notifier.Signal()
                }
            }(self.read_timeout_cancel)
        }

        return nil
    }

    func (s *Stream) handleData(pd *chunkPayloadData) {
        s.lock.Lock()
        defer s.lock.Unlock()

        var readable bool
        if self.reassembly_queue.push(pd) {
            readable = self.reassembly_queue.isReadable()
            self.log.Debugf("[%s] reassemblyQueue readable=%v", s.name, readable)
            if readable {
                self.log.Debugf("[%s] readNotifier.signal()", s.name)
                self.read_notifier.Signal()
                self.log.Debugf("[%s] readNotifier.signal() done", s.name)
            }
        }
    }

    fn handle_forward_tsn_for_ordered(&self, ssn: u16) {
        var readable bool

        func() {
            s.lock.Lock()
            defer s.lock.Unlock()

            if s.unordered {
                return // unordered chunks are handled by handleForwardUnordered method
            }

            // Remove all chunks older than or equal to the new TSN from
            // the reassemblyQueue.
            self.reassembly_queue.forwardTSNForOrdered(ssn)
            readable = self.reassembly_queue.isReadable()
        }()

        // Notify the reader asynchronously if there's a data chunk to read.
        if readable {
            self.read_notifier.Signal()
        }
    }

    func (s *Stream) handleForwardTSNForUnordered(newCumulativeTSN uint32) {
        var readable bool

        func() {
            s.lock.Lock()
            defer s.lock.Unlock()

            if !s.unordered {
                return // ordered chunks are handled by handleForwardTSNOrdered method
            }

            // Remove all chunks older than or equal to the new TSN from
            // the reassemblyQueue.
            self.reassembly_queue.forwardTSNForUnordered(newCumulativeTSN)
            readable = self.reassembly_queue.isReadable()
        }()

        // Notify the reader asynchronously if there's a data chunk to read.
        if readable {
            self.read_notifier.Signal()
        }
    }

    /// Write writes len(payload) bytes from payload with the default Payload Protocol Identifier.
    pub fn write(&self, payload: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let ppi = PayloadProtocolIdentifier(atomic.LoadUint32((*uint32)(&self.default_payload_type)));

        self.write_sctp(payload, ppi)
    }

    /// WriteSCTP writes len(payload) bytes from payload to the DTLS connection.
    pub fn write_sctp(
        &self,
        payload: &[u8],
        ppi: PayloadProtocolIdentifier,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let max_message_size = self.association.MaxMessageSize();
        if payload.len() > int(max_message_size) {
            return 0, fmt.Errorf("%w: %v", ErrOutboundPacketTooLarge, max_message_size)
        }

        if s.State() != StreamStateOpen {
            return 0, ErrStreamClosed
        }

        // the send could fail if the association is blocked for writing (timeout), it will left a hole
        // in the stream sequence number space, so we need to lock the write to avoid concurrent send and decrement
        // the sequence number in case of failure
        if self.association.isBlockWrite() {
            s.writeLock.Lock()
        }
        chunks, unordered := s.packetize(payload, ppi)
        n := len(payload)
        err := self.association.sendPayloadData(s.writeDeadline, chunks)
        if err != nil {
            s.lock.Lock()
            s.bufferedAmount -= uint64(n)
            if !unordered {
                s.sequenceNumber--
            }
            s.lock.Unlock()
            n = 0
        }
        if self.association.isBlockWrite() {
            s.writeLock.Unlock()
        }

        return n, err
    }

    // SetWriteDeadline sets the write deadline in an identical way to net.Conn,
    // it will only work for blocking writes.
    func (s *Stream) SetWriteDeadline(deadline time.Time) error {
        s.writeDeadline.Set(deadline)

        return nil
    }

    // SetDeadline sets the read and write deadlines in an identical way to net.Conn.
    func (s *Stream) SetDeadline(t time.Time) error {
        if err := s.SetReadDeadline(t); err != nil {
            return err
        }

        return s.SetWriteDeadline(t)
    }

    func (s *Stream) packetize(raw []byte, ppi PayloadProtocolIdentifier) ([]*chunkPayloadData, bool) {
        s.lock.Lock()
        defer s.lock.Unlock()

        offset := uint32(0)
        remaining := uint32(len(raw)) //nolint:gosec // G115

        // From draft-ietf-rtcweb-data-protocol-09, section 6:
        //   All Data Channel Establishment Protocol messages MUST be sent using
        //   ordered delivery and reliable transmission.
        unordered := ppi != PayloadTypeWebRTCDCEP && s.unordered

        var chunks []*chunkPayloadData
        var head *chunkPayloadData
        for remaining != 0 {
            fragmentSize := min32(self.association.maxPayloadSize, remaining)

            // Copy the userdata since we'll have to store it until acked
            // and the caller may re-use the buffer in the mean time
            userData := make([]byte, fragmentSize)
            copy(userData, raw[offset:offset+fragmentSize])

            chunk := &chunkPayloadData{
                streamIdentifier:     s.streamIdentifier,
                userData:             userData,
                unordered:            unordered,
                beginningFragment:    offset == 0,
                endingFragment:       remaining-fragmentSize == 0,
                immediateSack:        false,
                payloadType:          ppi,
                streamSequenceNumber: s.sequenceNumber,
                head:                 head,
            }

            if head == nil {
                head = chunk
            }

            chunks = append(chunks, chunk)

            remaining -= fragmentSize
            offset += fragmentSize
        }

        // RFC 4960 Sec 6.6
        // Note: When transmitting ordered and unordered data, an endpoint does
        // not increment its Stream Sequence Number when transmitting a DATA
        // chunk with U flag set to 1.
        if !unordered {
            s.sequenceNumber++
        }

        s.bufferedAmount += uint64(len(raw))
        self.log.Tracef("[%s] bufferedAmount = %d", s.name, s.bufferedAmount)

        return chunks, unordered
    }

    // Close closes the write-direction of the stream.
    // Future calls to Write are not permitted after calling Close.
    func (s *Stream) Close() error {
        if sid, resetOutbound := func() (uint16, bool) {
            s.lock.Lock()
            defer s.lock.Unlock()

            self.log.Debugf("[%s] Close: state=%s", s.name, s.state.String())

            if s.state == StreamStateOpen {
                if self.read_err == nil {
                    s.state = StreamStateClosing
                } else {
                    s.state = StreamStateClosed
                }
                self.log.Debugf("[%s] state change: open => %s", s.name, s.state.String())

                return s.streamIdentifier, true
            }

            return s.streamIdentifier, false
        }(); resetOutbound {
            // Reset the outgoing stream
            // https://tools.ietf.org/html/rfc6525
            return self.association.sendResetRequest(sid)
        }

        return nil
    }

    // BufferedAmount returns the number of bytes of data currently queued to be sent over this stream.
    func (s *Stream) BufferedAmount() uint64 {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.bufferedAmount
    }

    // BufferedAmountLowThreshold returns the number of bytes of buffered outgoing data that is
    // considered "low." Defaults to 0.
    func (s *Stream) BufferedAmountLowThreshold() uint64 {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.bufferedAmountLow
    }

    // SetBufferedAmountLowThreshold is used to update the threshold.
    // See BufferedAmountLowThreshold().
    func (s *Stream) SetBufferedAmountLowThreshold(th uint64) {
        s.lock.Lock()
        defer s.lock.Unlock()

        s.bufferedAmountLow = th
    }

    // OnBufferedAmountLow sets the callback handler which would be called when the number of
    // bytes of outgoing data buffered is lower than the threshold.
    func (s *Stream) OnBufferedAmountLow(f func()) {
        s.lock.Lock()
        defer s.lock.Unlock()

        s.onBufferedAmountLow = f
    }

    // This method is called by association's readLoop (go-)routine to notify this stream
    // of the specified amount of outgoing data has been delivered to the peer.
    func (s *Stream) onBufferReleased(nBytesReleased int) {
        if nBytesReleased <= 0 {
            return
        }

        s.lock.Lock()

        fromAmount := s.bufferedAmount

        if s.bufferedAmount < uint64(nBytesReleased) {
            s.bufferedAmount = 0
            self.log.Errorf("[%s] released buffer size %d should be <= %d",
                s.name, nBytesReleased, s.bufferedAmount)
        } else {
            s.bufferedAmount -= uint64(nBytesReleased)
        }

        self.log.Tracef("[%s] bufferedAmount = %d", s.name, s.bufferedAmount)

        if s.onBufferedAmountLow != nil && fromAmount > s.bufferedAmountLow && s.bufferedAmount <= s.bufferedAmountLow {
            f := s.onBufferedAmountLow
            s.lock.Unlock()
            f()

            return
        }

        s.lock.Unlock()
    }

    func (s *Stream) getNumBytesInReassemblyQueue() int {
        // No lock is required as it reads the size with atomic load function.
        return self.reassembly_queue.getNumBytes()
    }

    func (s *Stream) onInboundStreamReset() {
        s.lock.Lock()
        defer s.lock.Unlock()

        self.log.Debugf("[%s] onInboundStreamReset: state=%s", s.name, s.state.String())

        // No more inbound data to read. Unblock the read with io.EOF.
        // This should cause DCEP layer (datachannel package) to call Close() which
        // will reset outgoing stream also.

        // See RFC 8831 section 6.7:
        //    if one side decides to close the data channel, it resets the corresponding
        //    outgoing stream.  When the peer sees that an incoming stream was
        //    reset, it also resets its corresponding outgoing stream.  Once this
        //    is completed, the data channel is closed.

        self.read_err = io.EOF
        self.read_notifier.Broadcast()

        if s.state == StreamStateClosing {
            self.log.Debugf("[%s] state change: closing => closed", s.name)
            s.state = StreamStateClosed
        }
    }

    // State return the stream state.
    func (s *Stream) State() StreamState {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.state
    }
        return chunks, unordered
    }

    // Close closes the write-direction of the stream.
    // Future calls to Write are not permitted after calling Close.
    func (s *Stream) Close() error {
        if sid, resetOutbound := func() (uint16, bool) {
            s.lock.Lock()
            defer s.lock.Unlock()

            self.log.Debugf("[%s] Close: state=%s", s.name, s.state.String())

            if s.state == StreamStateOpen {
                if self.read_err == nil {
                    s.state = StreamStateClosing
                } else {
                    s.state = StreamStateClosed
                }
                self.log.Debugf("[%s] state change: open => %s", s.name, s.state.String())

                return s.streamIdentifier, true
            }

            return s.streamIdentifier, false
        }(); resetOutbound {
            // Reset the outgoing stream
            // https://tools.ietf.org/html/rfc6525
            return self.association.sendResetRequest(sid)
        }

        return nil
    }

    // BufferedAmount returns the number of bytes of data currently queued to be sent over this stream.
    func (s *Stream) BufferedAmount() uint64 {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.bufferedAmount
    }

    // BufferedAmountLowThreshold returns the number of bytes of buffered outgoing data that is
    // considered "low." Defaults to 0.
    func (s *Stream) BufferedAmountLowThreshold() uint64 {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.bufferedAmountLow
    }

    // SetBufferedAmountLowThreshold is used to update the threshold.
    // See BufferedAmountLowThreshold().
    func (s *Stream) SetBufferedAmountLowThreshold(th uint64) {
        s.lock.Lock()
        defer s.lock.Unlock()

        s.bufferedAmountLow = th
    }

    // OnBufferedAmountLow sets the callback handler which would be called when the number of
    // bytes of outgoing data buffered is lower than the threshold.
    func (s *Stream) OnBufferedAmountLow(f func()) {
        s.lock.Lock()
        defer s.lock.Unlock()

        s.onBufferedAmountLow = f
    }

    // This method is called by association's readLoop (go-)routine to notify this stream
    // of the specified amount of outgoing data has been delivered to the peer.
    func (s *Stream) onBufferReleased(nBytesReleased int) {
        if nBytesReleased <= 0 {
            return
        }

        s.lock.Lock()

        fromAmount := s.bufferedAmount

        if s.bufferedAmount < uint64(nBytesReleased) {
            s.bufferedAmount = 0
            self.log.Errorf("[%s] released buffer size %d should be <= %d",
                s.name, nBytesReleased, s.bufferedAmount)
        } else {
            s.bufferedAmount -= uint64(nBytesReleased)
        }

        self.log.Tracef("[%s] bufferedAmount = %d", s.name, s.bufferedAmount)

        if s.onBufferedAmountLow != nil && fromAmount > s.bufferedAmountLow && s.bufferedAmount <= s.bufferedAmountLow {
            f := s.onBufferedAmountLow
            s.lock.Unlock()
            f()

            return
        }

        s.lock.Unlock()
    }

    func (s *Stream) getNumBytesInReassemblyQueue() int {
        // No lock is required as it reads the size with atomic load function.
        return self.reassembly_queue.getNumBytes()
    }

    func (s *Stream) onInboundStreamReset() {
        s.lock.Lock()
        defer s.lock.Unlock()

        self.log.Debugf("[%s] onInboundStreamReset: state=%s", s.name, s.state.String())

        // No more inbound data to read. Unblock the read with io.EOF.
        // This should cause DCEP layer (datachannel package) to call Close() which
        // will reset outgoing stream also.

        // See RFC 8831 section 6.7:
        //    if one side decides to close the data channel, it resets the corresponding
        //    outgoing stream.  When the peer sees that an incoming stream was
        //    reset, it also resets its corresponding outgoing stream.  Once this
        //    is completed, the data channel is closed.

        self.read_err = io.EOF
        self.read_notifier.Broadcast()

        if s.state == StreamStateClosing {
            self.log.Debugf("[%s] state change: closing => closed", s.name)
            s.state = StreamStateClosed
        }
    }

    // State return the stream state.
    func (s *Stream) State() StreamState {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.state
    }
        return chunks, unordered
    }

    // Close closes the write-direction of the stream.
    // Future calls to Write are not permitted after calling Close.
    func (s *Stream) Close() error {
        if sid, resetOutbound := func() (uint16, bool) {
            s.lock.Lock()
            defer s.lock.Unlock()

            self.log.Debugf("[%s] Close: state=%s", s.name, s.state.String())

            if s.state == StreamStateOpen {
                if self.read_err == nil {
                    s.state = StreamStateClosing
                } else {
                    s.state = StreamStateClosed
                }
                self.log.Debugf("[%s] state change: open => %s", s.name, s.state.String())

                return s.streamIdentifier, true
            }

            return s.streamIdentifier, false
        }(); resetOutbound {
            // Reset the outgoing stream
            // https://tools.ietf.org/html/rfc6525
            return self.association.sendResetRequest(sid)
        }

        return nil
    }

    // BufferedAmount returns the number of bytes of data currently queued to be sent over this stream.
    func (s *Stream) BufferedAmount() uint64 {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.bufferedAmount
    }

    // BufferedAmountLowThreshold returns the number of bytes of buffered outgoing data that is
    // considered "low." Defaults to 0.
    func (s *Stream) BufferedAmountLowThreshold() uint64 {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.bufferedAmountLow
    }

    // SetBufferedAmountLowThreshold is used to update the threshold.
    // See BufferedAmountLowThreshold().
    func (s *Stream) SetBufferedAmountLowThreshold(th uint64) {
        s.lock.Lock()
        defer s.lock.Unlock()

        s.bufferedAmountLow = th
    }

    // OnBufferedAmountLow sets the callback handler which would be called when the number of
    // bytes of outgoing data buffered is lower than the threshold.
    func (s *Stream) OnBufferedAmountLow(f func()) {
        s.lock.Lock()
        defer s.lock.Unlock()

        s.onBufferedAmountLow = f
    }

    // This method is called by association's readLoop (go-)routine to notify this stream
    // of the specified amount of outgoing data has been delivered to the peer.
    func (s *Stream) onBufferReleased(nBytesReleased int) {
        if nBytesReleased <= 0 {
            return
        }

        s.lock.Lock()

        fromAmount := s.bufferedAmount

        if s.bufferedAmount < uint64(nBytesReleased) {
            s.bufferedAmount = 0
            self.log.Errorf("[%s] released buffer size %d should be <= %d",
                s.name, nBytesReleased, s.bufferedAmount)
        } else {
            s.bufferedAmount -= uint64(nBytesReleased)
        }

        self.log.Tracef("[%s] bufferedAmount = %d", s.name, s.bufferedAmount)

        if s.onBufferedAmountLow != nil && fromAmount > s.bufferedAmountLow && s.bufferedAmount <= s.bufferedAmountLow {
            f := s.onBufferedAmountLow
            s.lock.Unlock()
            f()

            return
        }

        s.lock.Unlock()
    }

    func (s *Stream) getNumBytesInReassemblyQueue() int {
        // No lock is required as it reads the size with atomic load function.
        return self.reassembly_queue.getNumBytes()
    }

    func (s *Stream) onInboundStreamReset() {
        s.lock.Lock()
        defer s.lock.Unlock()

        self.log.Debugf("[%s] onInboundStreamReset: state=%s", s.name, s.state.String())

        // No more inbound data to read. Unblock the read with io.EOF.
        // This should cause DCEP layer (datachannel package) to call Close() which
        // will reset outgoing stream also.

        // See RFC 8831 section 6.7:
        //    if one side decides to close the data channel, it resets the corresponding
        //    outgoing stream.  When the peer sees that an incoming stream was
        //    reset, it also resets its corresponding outgoing stream.  Once this
        //    is completed, the data channel is closed.

        self.read_err = io.EOF
        self.read_notifier.Broadcast()

        if s.state == StreamStateClosing {
            self.log.Debugf("[%s] state change: closing => closed", s.name)
            s.state = StreamStateClosed
        }
    }

    // State return the stream state.
    func (s *Stream) State() StreamState {
        s.lock.RLock()
        defer s.lock.RUnlock()

        return s.state
    }
}
