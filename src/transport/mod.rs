pub mod client;
pub mod server;

use uuid::Uuid;

// Version 2 uses the same vendor service for discovery as the previous build,
// but the authenticated handshake domains and encrypted messages have changed.
// v1 peers will be rejected during authentication instead of silently syncing.
pub const SERVICE_ID: Uuid = Uuid::from_u128(0xc1c0a8a0_0d82_4d22_9a36_a6bdc91e85aa);
pub const WRITE_ID: Uuid = Uuid::from_u128(0xc1c0a8a0_0d82_4d22_9a36_a6bdc91e85ab);
pub const READ_ID: Uuid = Uuid::from_u128(0xc1c0a8a0_0d82_4d22_9a36_a6bdc91e85ac);
