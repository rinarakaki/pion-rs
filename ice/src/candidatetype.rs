// https://github.com/pion/ice/blob/f92d05f17c76e8ce326bad6cd9002f383b8d1415/candidatetype.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

/// CandidateType represents the type of candidate.
#[derive(PartialEq)]
#[repr(u8)]
pub enum CandidateType {
    Unspecified,
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}

impl std::fmt::Display for CandidateType {
    /// String makes CandidateType printable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
            CandidateType::Unspecified => "Unknown candidate type",
        };
        write!(f, "{}", s)
    }
}

impl CandidateType {
    /// Preference returns the preference weight of a CandidateType
    ///
    /// 4.1.2.2.  Guidelines for Choosing Type and Local Preferences
    /// The RECOMMENDED values are 126 for host candidates, 100
    /// for server reflexive candidates, 110 for peer reflexive candidates,
    /// and 0 for relayed candidates.
    pub fn preference(&self) -> u16 {
        match self {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay | CandidateType::Unspecified => 0,
        }
    }
}

pub(crate) fn contains_candidate_type(
    candidate_type: CandidateType,
    candidate_type_list: &[CandidateType],
) -> bool {
    candidate_type_list.contains(&candidate_type)
}
