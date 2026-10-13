# BLEClip v0.2 — multi-peer encrypted Bluetooth clipboard mesh

A **serverless, Windows/Linux Rust CLI** that synchronizes *newly copied UTF-8 text* between multiple trusted computers using Bluetooth Low Energy (BLE). Every computer runs the same `peer` command: it advertises a GATT service, scans nearby BLEClip advertisements and independently maintains encrypted links. Messages may be relayed by intermediate peers; no Wi-Fi, cloud, internet service, IP address, or permanently designated server is required.

> **Status:** implementation + unit tests, **not yet built/tested on actual Windows/Linux BLE hardware**. The source artifact cannot be presented as a production-verified application. Cross-platform CI has been provided for validation on GitHub Actions.

## Features

- **Many peers:** configurable per-process maxima (`--max-inbound 16` / `--max-outbound 8` by default; up to 32 each as *software* limits). Bluetooth hardware/driver typically supports far fewer concurrent connections.
- **Identical peer mode:** all devices run `bleclip peer`, advertise and scan automatically. Symmetric peer operation may result in **two BLE connections between the same two computers**; event IDs prevent clipboard loops, but these duplicate radio links consume resources.
- **Hybrid broadcast/P2P:** Bluetooth advertisements are **discovery only**; clipboard content uses direct authenticated **GATT** connections. It is **not connectionless broadcast of clipboard data**.
- **Multi-hop forwarding:** peers forward remote updates to other authenticated peers up to eight hops. Devices can synchronize indirectly when there's a nearby relay, even without direct radio range, while relay is online.
- **Application-layer encryption:** 256-bit out-of-band group PSK, mutually authenticated ephemeral X25519, HKDF-SHA256 directional keys and XChaCha20-Poly1305. Each BLE link is an independent encrypted session; Bluetooth OS pairing is not needed for payload confidentiality (OS policy can still require pairing).
- **Anti-loop/anti-replay:** random update UUIDs, hop budget, bounded 8,192-ID duplicate cache, per-session random nonces and replay rejection. Each peer has an independent persistent node ID.
- **Automatic link recovery:** scans for newly seen peers, retries failed connections and restarts scan/advertise tasks after errors.
- **Direction policy:** `--direction both|send|receive`. Receive-only nodes don't relay; send-only nodes don't accept other peers' clipboard updates.
- **Memory bounds:** 16 KiB of UTF-8 per clipboard item, outgoing GATT queues capped, bounded routing channels.

## Quick start: three computers

Install Rust from <https://rustup.rs/> on Windows/Linux, extract this project, and build:

```bash
cargo build --release
```

Generate one random PSK on **one** computer:

```bash
./target/release/bleclip keygen --output bleclip.key
```

Copy `bleclip.key` to **every trusted computer using a secure out-of-band method**. Never transmit it over BLE. On Windows, run `target\release\bleclip.exe` instead of `./target/release/bleclip`.

On **Windows A**, **Linux B**, and **Linux C**, run the same command:

```bash
bleclip peer --key-file bleclip.key
```

If the binary is not installed on your `PATH`, use `cargo run --release -- peer --key-file bleclip.key` or the binary in `target/release/`.

Whenever one clipboard changes, the text is encrypted for each connected link and received by the other peers. Each peer can also relay encrypted updates to other nearby peers. Updates are *re-encrypted per hop*, so all participating, PSK-authorized devices are trusted to access the text; this is not end-to-end encrypted to a particular destination in a network of untrusted relays.

The first run automatically creates a random **per-machine** node UUID under the user config directory:

- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/bleclip/node-id`
- Windows: `%APPDATA%\bleclip\node-id`

You may override with `--identity-file path`. **Never copy this ID file across devices.** Only share the PSK. Distinct installations need distinct node identities.

### Larger groups

```bash
bleclip peer --key-file bleclip.key --max-inbound 16 --max-outbound 12
```

`--max-inbound` limits central devices concurrently served by your local GATT peripheral, while `--max-outbound` limits outbound BLE connection workers. They do not guarantee that a Bluetooth dongle and the OS can sustain that many simultaneous links. Default **16+8 is a software upper bound**, not a hardware tested claim. Start with 2–3 devices, then increase. This is a BLE *mesh-style relay overlay*, not Bluetooth SIG Mesh or its managed-flooding protocol.

### Hardware fallback

Some Windows Bluetooth dongles can scan as a central but cannot serve as a peripheral; others cannot scan and advertise simultaneously. Run:

```bash
# Windows: scan/connect, but don't advertise.
bleclip peer --key-file bleclip.key --no-advertise

# Linux: advertise/accept multiple connections, but don't scan.
bleclip peer --key-file bleclip.key --no-scan
```

Both processes remain equal **application** peers capable of sending and receiving text across a GATT connection. These flags only affect which BLE protocol role a device performs. `serve` and `connect` are retained as command shortcuts for `--no-scan` and `--no-advertise`, respectively, and support the new v2 protocol; they do **not** interoperate with the old v1 binary.

A useful fallback topology is one advertising Linux PC and several scanning Windows PCs. Windows-to-Windows updates will relay through Linux while it is online, as long as all computers use `--direction both`.

### Direction control

```bash
bleclip peer --key-file bleclip.key --direction send
bleclip peer --key-file bleclip.key --direction receive
```

`send` only sends local changes; `receive` only accepts remote updates, without forwarding them to other devices. `both` sends, receives and relays (default).

## Supported environments

### Linux / Arch Linux

```bash
sudo pacman -S --needed base-devel rust pkgconf dbus bluez bluez-utils libx11 libxcb wayland
sudo systemctl enable --now bluetooth
cargo build --release
```

Debian/Ubuntu:

```bash
sudo apt install build-essential pkg-config libdbus-1-dev libudev-dev libx11-dev libxcb1-dev libwayland-dev
sudo systemctl enable --now bluetooth
cargo build --release
```

BlueZ must have Bluetooth enabled and permit user processes to register local GATT advertisements/services. A graphical session is necessary for clipboard access. Run BLEClip under your **ordinary desktop user**, not root. The `arboard` Wayland data-control feature works only if your compositor supports it; otherwise try XWayland or a suitable Wayland clipboard implementation.

### Windows 10/11

Install the Rust MSVC toolchain and Microsoft C++ Build Tools, then:

```powershell
cargo build --release
.\target\release\bleclip.exe peer --key-file .\bleclip.key
```

Windows GATT peripheral advertising requires a supported Bluetooth controller/driver. In peripheral mode, `ble-peripheral-rust` uses Windows `GattServiceProvider`, which does not set a custom advertising name; discovery prioritizes the advertised service UUID and uses `--name` as a name fallback on other devices. OS pairing may be needed according to system policies.

## Security and privacy

- **Shared group trust:** all devices possessing the same PSK can participate and decrypt text relayed to them. Any one compromised peer can impersonate another group member or inject clipboard data. For private subsets, use a different group key on a separate instance.
- Application-layer AEAD encrypts all clipboard payloads, even when BLE link pairing is absent. Advertisements show a **public static BLEClip service UUID** and may reveal that the service is running. They do not contain clipboard text or the key.
- An ephemeral authenticated handshake derives new encryption keys per link and provides forward secrecy for past captures assuming uncompromised ephemeral secrets.
- **Clipboard may contain passwords, security tokens, banking data, etc.** The program does not detect sensitive material. To avoid forwarding it, stop the program or use a restrictive direction.
- Only new text changes while the program is running are shared; clipboard contents present at startup are not sent. Clipboard history, images, files, automatic peer approval, per-device revocation, and clipboard clear events are not implemented.
- Unit tests exercise cryptographic tamper/replay checks, handshake freshness, framing, identities, relay bounds/loops, and 16-subscriber fan-out. This is **not** independently security-audited.

## Protocol outline

A broadcast advertisement announces the service UUID. On discovering an advertising peer, a central establishes a BLE GATT connection. The connecting central writes length-prefixed fragments (<= 20-byte ATT payload), and the peripheral provides a per-client outgoing queue through a GATT READ characteristic.

Each session uses mutually authenticated v2 HMAC-proven ephemeral X25519 keys, HKDF for two directional keys, and XChaCha20-Poly1305 for encrypted application messages. Immediately after authentication, the peers exchange encrypted 128-bit random node IDs. An encrypted clipboard message contains a UUID event ID, origin UUID, remaining-hop count, and UTF-8 bytes. The update UUID survives relay, but every BLE link **re-encrypts** it with that link's session key.

Forwarding is done only for authenticated incoming updates that have not been seen before. Hop budgets decrease on each forwarding step and updates from a node are not sent back to their declared origin. The local clipboard is managed by a single router per process, which suppresses local re-broadcast of remote clipboard writes.

**Limitations:** polling GATT reads instead of notifications adds latency and power consumption; the BLE transport can drop messages on disconnect, buffer overflow, or a slow peer. The application does **not** implement end-to-end delivery acknowledgements or durable offline replay. When many nodes edit simultaneously, the last update delivered locally wins; there is no global total ordering or conflict resolution. Maximum useful throughput and number of links depend on actual hardware and drivers. A fully connected set of peers can establish multiple redundant radio links; this is a prototype design.

## Tests and cross-platform CI

```bash
cargo fmt --all
cargo test --all-targets
cargo clippy --all-targets
cargo build --release
```

The included GitHub Actions workflow builds and runs unit tests on Linux and Windows. Hardware integration tests must verify GATT read/write behavior, concurrent scanning/advertising, reconnection, and fan-out on the actual adapters. In particular, do not assume the Windows peripheral role or scan+advertise concurrency is supported on every Bluetooth dongle.
