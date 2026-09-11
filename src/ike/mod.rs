//! IKEv2 (RFC 7296): wire codec, key derivation, initiator state machine, UDP transport.
//! Only the initiator role and EAP-only authentication (RFC 5998) are implemented;
//! the auth method is behind [`auth::AuthMethod`] so PSK/signature auth can be added.

pub mod auth;
pub mod constants;
pub mod fragment;
pub mod header;
pub mod keys;
pub mod message;
pub mod nat;
pub mod payload;
pub mod session;
pub mod transport;
