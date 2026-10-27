pub mod bulk;
pub mod client;
pub mod server;

use uuid::Uuid;

// v3 uses its own BLE service identifiers and handshake domains; no v2 interop.
pub const SERVICE_ID: Uuid = Uuid::from_u128(0xc1c0a8a0_0d82_4d22_9a36_a6bdc91e85ba);
pub const WRITE_ID: Uuid = Uuid::from_u128(0xc1c0a8a0_0d82_4d22_9a36_a6bdc91e85bb);
pub const READ_ID: Uuid = Uuid::from_u128(0xc1c0a8a0_0d82_4d22_9a36_a6bdc91e85bc);
// Optional, authenticated L2CAP endpoint exchange; old v3 peers ignore it.
pub const BULK_ID: Uuid = Uuid::from_u128(0xc1c0a8a0_0d82_4d22_9a36_a6bdc91e85bd);
