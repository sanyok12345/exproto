#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Classic,
    FakeTls,
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Classic => f.write_str("classic"),
            Self::FakeTls => f.write_str("fake-tls"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoTag {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl ProtoTag {
    pub fn from_raw(tag: u32) -> Option<Self> {
        match tag {
            0xefefefef => Some(Self::Abridged),
            0xeeeeeeee => Some(Self::Intermediate),
            0xdddddddd => Some(Self::PaddedIntermediate),
            _ => None,
        }
    }

    pub fn to_raw(self) -> u32 {
        match self {
            Self::Abridged => 0xefefefef,
            Self::Intermediate => 0xeeeeeeee,
            Self::PaddedIntermediate => 0xdddddddd,
        }
    }
}

impl std::fmt::Display for ProtoTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abridged => f.write_str("abridged"),
            Self::Intermediate => f.write_str("intermediate"),
            Self::PaddedIntermediate => f.write_str("padded-intermediate"),
        }
    }
}
