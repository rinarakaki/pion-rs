// https://github.com/pion/sctp/blob/bf53986cb1bbb4f7a71552bdd47f3e5a9802526a/chunkheader.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

/*
chunkHeader represents a SCTP Chunk header, defined in https://tools.ietf.org/html/rfc4960#section-3.2
The figure below illustrates the field format for the chunks to be
transmitted in the SCTP packet.  Each chunk is formatted with a Chunk
Type field, a chunk-specific Flag field, a Chunk Length field, and a
Value field.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                          Chunk Value                          |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
pub(crate) struct ChunkHeader {
    typ: ChunkType,
    flags: u8,
    raw: Vec<u8>,
}

const CHUNK_HEADER_SIZE: usize = 4;

// SCTP chunk header errors.
var (
    ErrChunkHeaderTooSmall       = errors.New("raw is too small for a SCTP chunk")
    ErrChunkHeaderNotEnoughSpace = errors.New("not enough data left in SCTP packet to satisfy requested length")
    ErrChunkHeaderPaddingNonZero = errors.New("chunk padding is non-zero at offset")
)

impl ChunkHeader {
    fn unmarshal(&mut self, raw: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if raw.len() < CHUNK_HEADER_SIZE {
            return Err(Box::new(format!(
                "{}: raw only {} bytes, {} is the minimum length",
                ErrChunkHeaderTooSmall, raw.len(), CHUNK_HEADER_SIZE,
            )));
        }

        self.typ = ChunkType(raw[0]);
        self.flags = raw[1];
        let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;

        // Length includes Chunk header
        let value_length = length.saturating_sub(CHUNK_HEADER_SIZE);
        let length_after_value = raw.len().saturating_sub(CHUNK_HEADER_SIZE + value_length);

        if length_after_value < 0 {
            return Err(Box::new(format!(
                "{}: remain {} req {} ",
                ErrChunkHeaderNotEnoughSpace, value_length, raw.len() - CHUNK_HEADER_SIZE,
            )));
        } else if length_after_value < 4 {
            // https://tools.ietf.org/html/rfc4960#section-3.2
            // The Chunk Length field does not count any chunk padding.
            // Chunks (including Type, Length, and Value fields) are padded out
            // by the sender with all zero bytes to be a multiple of 4 bytes
            // long.  This padding MUST NOT be more than 3 bytes in total.  The
            // Chunk Length value does not include terminating padding of the
            // chunk.  However, it does include padding of any variable-length
            // parameter except the last parameter in the chunk.  The receiver
            // MUST ignore the padding.
            for i in (0..length_after_value).rev() {
                let padding_offset = CHUNK_HEADER_SIZE + value_length + (i - 1);
                if raw[padding_offset] != 0 {
                    return Err(Box::new(format!(
                        "{}: {} ",
                        ErrChunkHeaderPaddingNonZero, padding_offset,
                    )));
                }
            }
        }

        self.raw = raw[CHUNK_HEADER_SIZE..(CHUNK_HEADER_SIZE + value_length)].to_vec();

        Ok()
    }

    pub fn marshal(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut raw = vec![0u8; CHUNK_HEADER_SIZE + self.raw.len()];

        raw[0] = self.typ as u8;
        raw[1] = self.flags;

        raw[2..].copy_from_slice(&((self.raw.len() + CHUNK_HEADER_SIZE) as u16).to_be_bytes());

        raw[4..].copy_from_slice(&self.raw);
        Ok(raw)
    }

    pub fn value_length(&self) -> usize {
        self.raw.len()
    }

    pub fn string(&self) -> String {
        self.typ.string()
    }
}
