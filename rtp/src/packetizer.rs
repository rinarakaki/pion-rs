/// https://github.com/pion/rtp/blob/ee5524bed13b5f257ae7083ba4923001b59dfa59/packetizer.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use std::time;
use crate::packet::{Header, Packet};

/// Payloader payloads a byte array for use as rtp.Packet payloads.
pub trait Payloader {
    fn payload(&self, mtu: u16, payload: &[u8]) -> Vec<Vec<u8>>;
}

// /// Packetizer packetizes a payload.
// pub trait Packetizer {
//     fn packetize(&self, payload: [u8], samples: u32) -> Vec<Packet>;

//     fn generate_padding(&self, samples: u32) -> Vec<Packet>;

//     fn enable_abs_send_time(&mut self, value: int);

//     fn skip_samples(&self, skipped_samples: u32);
// }

pub struct Packetizer {
    pub mtu: u16,
    pub payload_type: u8,
    pub ssrc: u32,
    pub payloader: Payloader,
    pub sequencer: Sequencer,
    pub timestamp: u32,

    // Deprecated: will be removed in a future version.
    #[deprecated]
    pub clock_rate: u32,

    // put extension numbers in here. If they're 0, the extension is disabled (0 is not a legal extension number)
    extension_numbers: struct {
        AbsSendTime int // http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
    }
    pub timegen: fn() -> time.Time
}

impl Packetizer {
    /// NewPacketizer returns a new instance of a Packetizer for a specific payloader.
    pub fn new(
        mtu: u16,
        payload_type: u8,
        ssrc: u32,
        payloader: Payloader,
        sequencer: Sequencer,
        clock_rate: u32,
    ) -> Self {
        return Self {
            mtu,
            payload_type,
            ssrc,
            payloader,
            sequencer,
            timestamp: globalMathRandomGenerator.Uint32(),
            clock_rate,
            timegen: time.Now,
        }
    }

    pub fn enable_abs_send_time(&mut self, value: int) {
        self.extension_numbers.AbsSendTime = value;
    }

    /// Packetize packetizes the payload of an RTP packet and returns one or more RTP packets.
    pub fn packetize(&self, payload: &[u8], samples: u32) -> Vec<Packet> {
        // Guard against an empty payload
        if payload.is_empty() {
            return Vec::new();
        }

        let payloads = self.payloader.payload(p.MTU-12, payload);
        let mut packets: Vec<Packet> = Vec::with_capacity(payloads.len());

        for (i, pp) in payloads.into_iter().enumerate() {
            packets[i] = Packet {
                header: Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker: i == payloads.len() - 1,
                    payload_type: self.payload_type,
                    sequence_number: self.sequencer.next_sequence_number(),
                    timestamp: self.timestamp, // Figure out how to do timestamps
                    ssrc: self.ssrc,
                    csrc: Vec::new(),
                },
                payload: pp,
            };
        }
        self.timestamp += samples;

        if packets.len() != 0 && self.extension_numbers.AbsSendTime != 0 {
            let send_time = NewAbsSendTimeExtension(self.timegen());
            // apply http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
            let (b, err) = send_time.Marshal();
            if err != nil {
                return nil // never happens
            }
            err = packets[packets.len()-1].set_extension(uint8(self.extension_numbers.AbsSendTime), b);
            if err != nil {
                return nil // never happens
            }
        }

        packets
    }

    /// GeneratePadding returns required padding-only packages.
    pub fn generate_padding(&self, samples: u32) -> Vec<Packet> {
        // Guard against an empty payload
        if samples == 0 {
            return Vec::new();
        }

        let mut packets: Vec<Packet> = Vec::with_capacity(samples as usize);

        for _ in 0..samples {
            let mut payload = vec![0u8; 255];
            payload[254] = 255;

            let packet =  Packet {
                header: Header {
                    version: 2,
                    padding: true,
                    extension: false,
                    marker: false,
                    payload_type: self.payload_type,
                    sequence_number: self.sequencer.next_sequence_number(),
                    timestamp: self.timestamp,  // Use latest timestamp
                    ssrc: self.ssrc,
                    csrc: []uint32{},
                },
                payload,
            }
            packets.push(packet);
        }

        packets
    }

    /// SkipSamples causes a gap in sample count between Packetize requests so the
    /// RTP payloads produced have a gap in timestamps.
    pub fn skip_samples(&mut self, skipped_samples: u32) {
        self.timestamp += skipped_samples;
    }
}
