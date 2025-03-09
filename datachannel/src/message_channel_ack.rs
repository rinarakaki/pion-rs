// https://github.com/pion/datachannel/blob/15a4d100b9b29b106edebbbdc4e8e0dd9941d0de/message_channel_ack.go
// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use crate::message::MessageType::DataChannelAck;

// channelAck is used to ACK a DataChannel open.
pub(crate) struct ChannelAck;

const CHANNEL_OPEN_ACK_LENGTH: usize = 4;

impl ChannelAck {
    /// Marshal returns raw bytes for the given message.
    pub fn marshal(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut raw = vec![0u8; CHANNEL_OPEN_ACK_LENGTH];
        raw[0] = DataChannelAck as u8;

        Ok(raw)
    }

    /// Unmarshal populates the struct with the given raw data.
    pub fn unmarshal(&mut self, _: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // Message type already checked in Parse and there is no further data
        Ok(())
    }

    pub fn string(&self) -> String {
        "ACK".to_string()
    }
}
