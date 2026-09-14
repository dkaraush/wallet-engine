//! Requests for TON encrypted transfer comments.

use crate::{Boc, TonAddressString};

/// Requests a ready-to-send TON encrypted-comment body.
///
/// The engine uses the supplied recipient public key or loads it from chain
/// state, then asks the platform host to authorize access to this wallet's
/// protected mnemonic.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct CreateEncryptedCommentRequest {
    /// Recipient wallet address. Must expose `get_public_key` when no key is supplied.
    pub recipient: TonAddressString,
    /// UTF-8 comment to encrypt. Its encoded form must not exceed 960 bytes.
    pub comment: String,
    /// Optional 32-byte Ed25519 public key used instead of an on-chain lookup.
    ///
    /// The caller must verify that this key belongs to `recipient`; the engine
    /// does not check the key against the address.
    #[serde(default)]
    #[uniffi(default = None)]
    pub recipient_public_key: Option<Vec<u8>>,
}

/// Requests explicit decryption of one encrypted-comment message body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct DecryptCommentRequest {
    /// Address that sent the encrypted comment.
    ///
    /// TON binds this bounceable, URL-safe, non-test-only address to the
    /// authentication tag. For an incoming activity item this is its
    /// `counterparty`.
    pub sender: TonAddressString,
    /// Complete message-body cell encoded as a Base64 BOC.
    pub body: Boc,
}
