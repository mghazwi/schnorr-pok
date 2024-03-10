use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use crate::serde_utils::ArkSerializationError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum SchnorrError {
    ExpectedSameSizeSequences(usize, usize),
    IndexOutOfBounds(usize, usize),
    InvalidResponse,
    #[serde(with = "ArkSerializationError")]
    Serialization(SerializationError),
    ValueMustNotBeEqual,
    InvalidProofOfEquality,
}

impl From<SerializationError> for SchnorrError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
