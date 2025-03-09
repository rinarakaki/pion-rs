// https://github.com/pion/datachannel/blob/15a4d100b9b29b106edebbbdc4e8e0dd9941d0de/datachannel.go
// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package datachannel implements WebRTC Data Channels

use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use pion_rs_sctp::{self as sctp, PayloadProtocolIdentifier};
use pion_rs_logging as logging;

use crate::message_channel_ack::ChannelAck;
use crate::message_channel_open::{ChannelOpen, ChannelType};
use crate::message::parse;

const RECEIVE_MTU: usize = 8192;

/// Reader is an extended io.Reader
/// that also returns if the message is text.
pub trait Reader {
    fn read_data_channel(&self, pkt: &mut [u8]) -> Result<(usize, bool), Box<dyn std::error::Error>>;
}

/// ReadDeadliner extends an io.Reader to expose setting a read deadline.
pub trait ReadDeadliner {
    fn set_read_deadline(&self, t: Instant) -> Result<(), Box<dyn std::error::Error>>;
}

/// Writer is an extended io.Writer
/// that also allows indicating if a message is text.
pub trait Writer {
    fn write_data_channel(&self, pkt: &[u8], is_string: bool) -> Result<usize, Box<dyn std::error::Error>>;
}

/// WriteDeadliner extends an io.Writer to expose setting a write deadline.
pub trait WriteDeadliner {
    fn set_write_deadline(&self, t: Instant) -> Result<(), Box<dyn std::error::Error>>;
}

/// ReadWriteCloser is an extended io.ReadWriteCloser
/// that also implements our Reader and Writer.
pub trait ReadWriteCloser: io::Reader
+ io::Writer
+ Reader
+ Writer
+ io::Closer {}

/// ReadWriteCloserDeadliner is an extended ReadWriteCloser
/// that also implements r/w deadline.
pub trait ReadWriteCloserDeadliner: ReadWriteCloser
+ ReadDeadliner
+ WriteDeadliner{}

/// DataChannel represents a data channel.
#[derive(Default)]
pub struct DataChannel {
    config: Config,

    // stats
    messages_sent: AtomicU32,
    messages_received: AtomicU32,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,

    on_open_complete_handler: func(),
    open_complete_handler_once: sync::Once,

    stream: Arc<sctp::Stream>,
    log: logging::LeveledLogger,
}

/// Config is used to configure the data channel.
pub struct Config {
    pub channel_type: ChannelType,
    pub negotiated: bool,
    pub priority: u16,
    pub reliability_parameter: u32,
    pub label: String,
    pub protocol: String,
    pub logger_factory: Arc<dyn logging::LoggerFactory>,
}

impl DataChannel {
    pub fn new(stream: Arc<sctp::Stream>, config: Config) -> DataChannel {
        DataChannel {
            config: config.clone(),
            stream,
            log: config.logger_factory.NewLogger("datachannel"),
            ..Default::default()
        }
    }

    /// Dial opens a data channels over SCTP.
    pub fn dial(
        a: &sctp::Association,
        id: u16,
        config: Config,
    ) -> Result<Arc<DataChannel>, Box<dyn std::error::Error>> {
        let stream = a.open_stream(id, sctp::PayloadTypeWebRTCBinary)?;

        let dc = Self::client(stream, config)?;

        Ok(dc)
    }

    /// Client opens a data channel over an SCTP stream.
    pub fn client(stream: Arc<SctpStream>, config: Config) -> Result<Arc<DataChannel>, Box<dyn std::error::Error>> {
        let msg = ChannelOpen {
            channel_type: config.channel_type,
            priority: config.priority,
            reliability_parameter: config.reliability_parameter,

            label: config.label.clone(),
            protocol: config.protocol.clone(),
        };

        if !config.negotiated {
            let raw_msg = match msg.marshal() {
                Ok(raw_msg) => raw_msg,
                Err(err) => return Err(Box::new(format!("failed to marshal ChannelOpen {}", err))),
            };
            if let Err(err) = stream.write_sctp(&raw_msg, sctp::PayloadTypeWebRTCDCEP) {
                return Err(Box::new(format!("failed to send ChannelOpen {}", err)));
            }
        }

        Ok(Self::new(stream, config))
    }

    /// Accept is used to accept incoming data channels over SCTP.
    pub fn accept(
        a: &sctp::Association,
        mut config: Config,
        existing_channels: &[Arc<DataChannel>],
    ) -> Result<Arc<DataChannel>, Box<dyn std::error::Error>> {
        let stream = a.accept_stream()?;
        for ch in existing_channels {
            if ch.stream_identifier() == stream.stream_identifier() {
                ch.stream.set_default_payload_type(sctp::PayloadTypeWebRTCBinary);

                return Ok(Arc::clone(ch));
            }
        }

        stream.set_default_payload_type(PayloadProtocolIdentifier::WebRTCBinary);

        let dc = Self::server(stream, &mut config)?;
        Ok(dc)
    }

    /// Server accepts a data channel over an SCTP stream.
    pub fn server(
        stream: Arc<SctpStream>,
        config: &mut Config,
    ) -> Result<Arc<DataChannel>, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; RECEIVE_MTU];
        let (n, ppi) = stream.read_sctp(&mut buffer)?;

        if ppi != sctp::PayloadTypeWebRTCDCEP {
            return Err(Box::new(format!("{} {}", ErrInvalidPayloadProtocolIdentifier, ppi)));
        }

        let open_msg = match parse_expect_data_channel_open(&buffer[..n]) {
            Ok(open_msg) => open_msg,
            Err(err) => return Err(Box::new(format!("failed to parse DataChannelOpen packet {}", err))),
        };

        config.channel_type = open_msg.channel_type;
        config.priority = open_msg.priority;
        config.reliability_parameter = open_msg.reliability_parameter;
        config.label = open_msg.label;
        config.protocol = open_msg.protocol;

        let data_channel = Self::new(stream, config.clone());

        data_channel.write_data_channel_ack()?;

        data_channel.commit_reliability_params()?;

        Ok(data_channel)
    }

    /// Read reads a packet of len(pkt) bytes as binary data.
    pub fn read(&self, pkt: &mut [u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let (n, _) = self.read_data_channel(pkt)?;

        Ok(n)
    }

    /// ReadDataChannel reads a packet of len(pkt) bytes.
    pub fn read_data_channel(&self, mut pkt: &mut [u8]) -> Result<(usize, bool), Box<dyn std::error::Error>> {
        loop {
            let (mut n, ppi) = match self.stream.read_sctp(&mut pkt) {
                Ok((n, ppi)) => (n, ppi),
                Err(err) if err == io.EOF => {
                    // When the peer sees that an incoming stream was
                    // reset, it also resets its corresponding outgoing stream.
                    self.stream.close()?;
                }
                Err(err) => return Err(Box::new(err)),
            };

            if ppi == sctp::PayloadTypeWebRTCDCEP {
                if let Err(err) = self.handle_dcep(&pkt[..n]) {
                    self.log.error("Failed to handle DCEP: {}", err);
                }

                continue;
            } else if ppi == sctp::PayloadTypeWebRTCBinaryEmpty
                || ppi == sctp::PayloadTypeWebRTCStringEmpty
            {
                n = 0;
            }

            self.messages_received.fetch_add(1, Ordering::SeqCst);
            self.bytes_received
                .fetch_add(n as u64, Ordering::SeqCst);

            let is_string =
            sctp::PayloadTypeWebRTCString || ppi == sctp::PayloadTypeWebRTCStringEmpty;

            return Ok((n, is_string));
        }
    }

    /// SetReadDeadline sets a deadline for reads to return.
    pub fn set_read_deadline(&self, t: Instant) -> Result<(), Box<dyn std::error::Error>> {
        self.stream.set_read_deadline(t)
    }

    /// SetWriteDeadline sets a deadline for writes to return,
    /// only available if the BlockWrite is enabled for sctp.
    pub fn set_write_deadline(&self, t: Instant) -> Result<(), Box<dyn std::error::Error>> {
        self.stream.set_write_deadline(t);
    }

    /// MessagesSent returns the number of messages sent.
    pub fn messages_sent(&self) -> u32 {
        self.messages_sent.load(Ordering::SeqCst)
    }

    /// MessagesReceived returns the number of messages received.
    pub fn messages_received(&self) -> u32 {
        self.messages_received.load(Ordering::SeqCst)
    }

    /// OnOpen sets an event handler which is invoked when
    /// a DATA_CHANNEL_ACK message is received.
    /// The handler is called only on thefor the channel opened
    /// https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-data-protocol-09#section-5.2
    pub fn on_open<F>(&self, f: F)
    where
        F: Fn() + 'static + Send,
    {
        // let mut handler = self.on_open_complete_handler.lock().unwrap();
        // let mut once = self.open_complete_handler_once.lock().unwrap();
        // *once = false;
        // *handler = Some(Box::new(f));
    }

    fn on_open_complete(&self) {
        // c.mu.Lock()
        // hdlr := c.onOpenCompleteHandler
        // c.mu.Unlock()

        // if hdlr != nil {
        //     go c.openCompleteHandlerOnce.Do(func() {
        //         hdlr()
        //     })
        // }
    }

    /// BytesSent returns the number of bytes sent.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::SeqCst)
    }

    // BytesReceived returns the number of bytes received.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::SeqCst)
    }

    /// StreamIdentifier returns the Stream identifier associated to the stream.
    pub fn stream_identifier(&self) -> u16 {
        self.stream.stream_identifier()
    }

    fn handle_dcep(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let msg = match parse(data) {
            Ok(msg) => msg,
            Err(err) => return Err(Box::new(format!("failed to parse DataChannel packet {}", err))),
        };

        match msg {
            ChannelAck(_) => {
                self.commit_reliability_params()?;
                self.on_open_complete();
            }
            _ => {
                return Err(Box::new(format!("{}, wanted ACK got {}", ErrUnexpectedDataChannelType, msg)));
            }
        }

        Ok(())
    }

    /// Write writes len(pkt) bytes from pkt as binary data.
    pub fn write(&self, pkt: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        self.write_data_channel(pkt, false)
    }

    /// WriteDataChannel writes len(pkt) bytes from pkt.
    pub fn write_data_channel(&self, pkt: &[u8], is_string: bool) -> Result<usize, Box<dyn std::error::Error>> {
        // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-12#section-6.6
        // SCTP does not support the sending of empty user messages.  Therefore,
        // if an empty message has to be sent, the appropriate PPID (WebRTC
        // String Empty or WebRTC Binary Empty) is used and the SCTP user
        // message of one zero byte is sent.  When receiving an SCTP user
        // message with one of these PPIDs, the receiver MUST ignore the SCTP
        // user message and process it as an empty message.
        let ppi = if !is_string && !pkt.is_empty() {
            sctp::PayloadTypeWebRTCBinary
        } else if !is_string && pkt.is_empty() {
            sctp::PayloadTypeWebRTCBinaryEmpty
        } else if is_string && !pkt.is_empty() {
            sctp::PayloadTypeWebRTCString
        } else if is_string && pkt.is_empty() {
            sctp::PayloadTypeWebRTCStringEmpty
        };

        self.messages_sent.fetch_add(1, Ordering::SeqCst);
        self.bytes_sent
            .fetch_add(pkt.len() as u64, Ordering::SeqCst);

        if pkt.is_empty() {
            self.stream.write_sctp(&[0], ppi)?;

            return Ok(0);
        }

        self.stream.write_sctp(pkt, ppi)
    }

    fn write_data_channel_ack(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ack = ChannelAck {};
        let ack_msg = match ack.marshal() {
            Ok(ack_msg) => ack_msg,
            Err(err) => return Err(Box::new(format!("failed to marshal ChannelOpen ACK {}", err))),
        };

        if let Err(err) = self.stream.write_sctp(&ack_msg, sctp::PayloadTypeWebRTCDCEP) {
            return Err(Box::new(format!("failed to send ChannelOpen ACK {}", err)));
        }

        Ok(())
    }

    /// Close closes the DataChannel and the underlying SCTP stream.
    pub fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.7
        // Closing of a data channel MUST be signaled by resetting the
        // corresponding outgoing streams [RFC6525].  This means that if one
        // side decides to close the data channel, it resets the corresponding
        // outgoing stream.  When the peer sees that an incoming stream was
        // reset, it also resets its corresponding outgoing stream.  Once this
        // is completed, the data channel is closed.  Resetting a stream sets
        // the Stream Sequence Numbers (SSNs) of the stream back to 'zero' with
        // a corresponding notification to the application layer that the reset
        // has been performed.  Streams are available for reuse after a reset
        // has been performed.
        self.stream.close()
    }

    /// BufferedAmount returns the number of bytes of data currently queued to be
    /// sent over this stream.
    pub fn buffered_amount(&self) -> u64 {
        self.stream.buffered_amount()
    }

    /// BufferedAmountLowThreshold returns the number of bytes of buffered outgoing
    /// data that is considered "low." Defaults to 0.
    pub fn buffered_amount_low_threshold(&self) -> u64 {
        self.stream.buffered_amount_low_threshold()
    }

    /// SetBufferedAmountLowThreshold is used to update the threshold.
    /// See BufferedAmountLowThreshold().
    pub fn set_buffered_amount_low_threshold(&self, th: u64) {
        self.stream.set_buffered_amount_low_threshold(th)
    }

    /// OnBufferedAmountLow sets the callback handler which would be called when the
    /// number of bytes of outgoing data buffered is lower than the threshold.
    pub fn on_buffered_amount_low(&self, f: fn()) {
        self.stream.on_buffered_amount_low(f)
    }

    fn commit_reliability_params(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.config.channel_type {
            ChannelType::Reliable => self.stream.set_reliability_params(
                false,
                sctp::ReliabilityType::Reliable,
                self.config.reliability_parameter,
            ),
            ChannelType::ReliableUnordered => self.stream.set_reliability_params(
                true,
                sctp::ReliabilityType::Reliable,
                self.config.reliability_parameter,
            ),
            ChannelType::PartialReliableRexmit => self.stream.set_reliability_params(
                false,
                sctp::ReliabilityType::Rexmit,
                self.config.reliability_parameter,
            ),
            ChannelType::PartialReliableRexmitUnordered => self.stream.set_reliability_params(
                true,
                sctp::ReliabilityType::Rexmit,
                self.config.reliability_parameter,
            ),
            ChannelType::PartialReliableTimed => self.stream.set_reliability_params(
                false,
                sctp::ReliabilityType::Timed,
                self.config.reliability_parameter,
            ),
            ChannelType::PartialReliableTimedUnordered => self.stream.set_reliability_params(
                true,
                sctp::ReliabilityType::Timed,
                self.config.reliability_parameter,
            ),
        }

        Ok(())
    }
}
