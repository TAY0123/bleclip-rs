# BLEClip v0.4.2 — encrypted P2P clipboard mesh with a system tray

BLEClip is a **serverless Bluetooth Low Energy** Rust app (CLI or system tray) that automatically synchronizes **text, clipboard images, and copied files** between multiple trusted Windows/Linux computers. Each node advertises, scans, and can relay an update to other online nodes. BLE advertisements are for discovery only; content travels over mutually authenticated and encrypted GATT connections, with optional LE L2CAP bulk channels between Linux peers.

> **Experimental / hardware testing needed.** The system tray feature does not replace device-level BLE validation. A successful `cargo test` / `cargo build` does not prove the Bluetooth hardware, Windows GATT peripheral mode, or desktop clipboard integration works. See [SECURITY.md](SECURITY.md).

## Features and hard limits

| Content | Source | Remote action | Maximum per clipboard event |
| --- | --- | --- | --- |
| Text | New copied text | Set clipboard text | 8 MiB UTF-8 |
| Image | New copied bitmap/screenshot | Transfer lossless PNG, set remote clipboard image | 4 MiB *compressed*, maximum 8 million pixels |
| File list | Copy 1–16 regular files in Windows Explorer / Linux file manager | Announce names/sizes; download on paste and expose local file paths | 64 MiB total, 16 files |
| Send file… | Right-click tray menu, choose files | Download immediately into Downloads/BLEClip | 64 MiB total, 16 files |

Text larger than 16 KiB is compressed for transfer. Update all receiving and relay peers to support these transfers and the higher limits; older builds cannot decode compressed text or accept the larger payloads.

Large transfers can take a long time or time out, and each active transfer is buffered in memory.

### Optional BLE L2CAP bulk transfer

On **Linux-to-Linux** links, payloads larger than **1 MiB after text compression** automatically try an LE credit-based L2CAP channel. Smaller payloads stay on GATT. The channel uses the same Bluetooth radio, without Wi-Fi or a shared network; its actual speed depends on the adapters, negotiated PHY, OS, and radio conditions.

The existing authenticated GATT link exchanges a short-lived capability for the bulk channel. L2CAP then performs a fresh, separately authenticated and encrypted handshake, verifies the peer identity and capability, and checks the completed transfer's digest before acknowledging it. The tray transfer rows show **BLE L2CAP** or **BLE GATT**.

If negotiation, connection, authentication, transfer, or acknowledgement fails, the same update is retried over GATT. A failed attempt suppresses further L2CAP attempts on that link for 60 seconds. A partial transfer restarts from the beginning; an update already delivered before its acknowledgement was lost is deduplicated by its UUID. Closing the GATT link, pausing, or quitting revokes its bulk capability and cancels active bulk transfers.

**Windows currently uses GATT**, because the application's Windows backend does not expose LE L2CAP sockets. Older peers and Linux systems without working L2CAP sockets also use GATT. All receiving and relay peers must still support the payload type and size being sent. Use `bleclip peer --no-l2cap ...` or `bleclip tray --no-l2cap ...` to force GATT. No measured throughput guarantee is provided; the automated tests use in-memory streams, and hardware performance needs two-device testing.

**Tray mode enables file copy/paste and file receiving by default**, including the Windows double-click launcher. CLI `peer`, `serve`, and `connect` modes require `--sync-files` on nodes that send, receive, or relay files. Images and text are enabled by default; use `--no-images` to turn off image synchronization. Directories, symlinks, folders, virtual clipboard files, huge files, and file lists beyond the limits are not transferred. Original files are never deleted, and received files are never executed.

### Download prebuilt binaries (public)

After a successful Windows/Linux GitHub Actions run, anyone can download ZIP and tar.gz binaries directly from the [public GitHub Releases page](https://github.com/TAY0123/bleclip-rs/releases).

- **Windows x86-64:** [bleclip-windows-x86_64.zip](https://github.com/TAY0123/bleclip-rs/releases/download/continuous/bleclip-windows-x86_64.zip)
- **Linux x86-64:** [bleclip-linux-x86_64.tar.gz](https://github.com/TAY0123/bleclip-rs/releases/download/continuous/bleclip-linux-x86_64.tar.gz)
- **Checksums:** [SHA256SUMS](https://github.com/TAY0123/bleclip-rs/releases/download/continuous/SHA256SUMS)

These links become available **only after CI passes** and the `continuous` release is created. For an official versioned build, use the corresponding `v*` tagged Release. CI run artifacts also appear in the [Actions tab](https://github.com/TAY0123/bleclip-rs/actions), but GitHub Releases are the stable **anonymous public download** endpoint. These are experimental binaries, not signed or independently security-audited.

### Quick start

Install a recent stable Rust toolchain via <https://rustup.rs/> and build:

```bash
cargo build --release
```

Create a random 256-bit shared key on one computer:

```bash
bleclip keygen --output bleclip.key
```

Provision `bleclip.key` to the other computers **through a separate secure channel**. Do not commit it. Run the **same command** on Windows A, Linux B, and Windows/Linux C:

```bash
bleclip peer --key-file bleclip.key --sync-files
```

To save incoming files somewhere specific:

```bash
bleclip peer --key-file bleclip.key --sync-files --receive-dir ~/Downloads/BLEClip
```

Windows PowerShell:

```powershell
.\target\release\bleclip.exe peer --key-file .\bleclip.key --sync-files --receive-dir "$env:USERPROFILE\Downloads\BLEClip"
```

**Use the desktop clipboard:** copy some text, copy a screenshot/image, or select files in Explorer or your Linux file manager and press Ctrl+C. Each reachable peer receives the new item. Images are put directly on the target clipboard. Copying files sends only names and byte sizes, without uploading contents. Receivers show a desktop notification listing filenames and sizes and install a delayed file-list clipboard offer. Ctrl+V in a file manager requests the contents from the source peer, saves them inside `Downloads/BLEClip/<transfer UUID>/` (or `--receive-dir`), and supplies the downloaded local paths to the file manager. Repeated pastes reuse the downloaded files. The configured OS Downloads location is respected, with `~/Downloads` as fallback. Clipboard file-list support depends on the source application and desktop session.

BLEClip only sends clipboard changes after startup. The tray menu also offers an explicit file picker for immediate sending; drag-and-drop is not implemented. If a copied file is larger than the limit, the item is skipped with an error.

### System tray (Windows + Linux)

Use the **tray** command on each computer for a persistent system tray / notification area icon:

```bash
bleclip tray --key-file bleclip.key
```

- **Left click** the tray icon to pause/resume clipboard sharing. **Green** = enabled; **gray with slash** = paused.
- **Right click → Send file…** to choose up to 16 files and send immediately to reachable trusted peers. Recipients save them under Downloads/BLEClip and receive a notification; explicit sends do not replace their clipboard. On Linux install `kdialog` (KDE) or `zenity` for the picker, and `notify-send` (`libnotify` / `libnotify-bin`) for notifications. Windows uses the native file picker and notification area balloon tips.
- **Right click** also provides **Pause sharing / Resume sharing** and **Quit BLEClip**.

- The context menu shows the current transfer or the most recent result. **Transfers (N active)** lists live and recent text, file, and image transfers with peer ID, percentage, transferred/total bytes, retries, and completion/failure status. Updates are throttled to four per second per transfer. Sending remains below 100% until the peer acknowledges receipt; receiving reaches 100% after payload integrity validation. The menu retains the latest eight completed or failed transfers. Pausing or disconnecting marks unfinished transfers as interrupted. Byte counts cover the transmitted payload, including file bundle headers and compressed text.

- The right-click menu shows **Connection: N authenticated peers** and a
  **Connected peers (N)** submenu listing peer ID prefixes and each link role
  (inbound, outbound, or both). A device with simultaneous inbound/outbound
  links counts as one peer. Raw discovered devices and unauthenticated pairing
  attempts are not counted as connected.
- While connecting or authenticating, the menu shows the number of connection
  attempts in progress; a peer is counted only after authentication succeeds.
- With no connected peers, the menu shows **disconnected (searching)**. BLE
  scanning starts at launch and the discovered-device cache is checked every
  2 seconds while outgoing connection slots remain free. After a failed link,
  that address has a 15-second retry cooldown; other devices can still connect.
  A link ending also prompts an immediate discovery check. A server-only peer
  shows **incoming connections only**. The check interval does not determine
  the Bluetooth radio's scan-window duration.
- Inbound GATT clients that disconnect without an explicit disconnect event
  are removed after the server's inactivity cleanup (typically 25–35 seconds).
  Pausing or stopping a peer clears its connection list immediately.
- Pausing cancels advertising, scanning and active encrypted BLE connections, dropping queued/in-flight clipboard transfers. Resuming reinitializes BLE, reconnects peers, and starts monitoring again. Content already on the clipboard is not uploaded on resume; only subsequent changes are sent.
- Text and image sync use the same settings as regular peer mode; file transfer is enabled automatically in tray mode, with `--no-images` to disable images, and `--no-advertise` when a device cannot offer the peripheral role.
- The headless `bleclip peer` command remains supported for unattended terminals/services.

**Windows:** Download the public Windows ZIP and use `bleclip-tray.exe` for a GUI-subsystem launcher without a console window. Generate or securely copy `bleclip.key` **into the same directory as `bleclip-tray.exe`**, then double-click the launcher. The launcher defaults to text/image/file sync and accepts normal CLI parameters when invoked with arguments, for example:

```powershell
.\bleclip-tray.exe tray --key-file .\bleclip.key --sync-files
```

The archive also includes `bleclip.exe` for CLI usage (including key generation).

**Linux (KDE Plasma / Wayland or X11):** Run `bleclip tray --key-file /absolute/path/bleclip.key` from your graphical login session, or create a desktop-session autostart entry using that command with **Terminal=false**. The Linux backend uses D-Bus StatusNotifierItem (`ksni`), not GTK, so KDE Plasma works natively. Other desktop environments may require an extension or a visible StatusNotifierItem host; running without a graphical login session will not show an icon.

The tray controls access to the clipboard transfer subsystem, **not OS-wide Bluetooth**; it does not disable your Bluetooth adapter or other Bluetooth applications.


#### File offers and paste behavior

- Keep the source peer connected and the original files available until paste finishes. The latest four local offers are retained for up to 30 minutes. Changed, missing, expired, or oversized files fail with a notification rather than writing mismatched data. File requests time out after 10 minutes; BLE throughput and file-manager timeouts can make large transfers impractical.
- Delayed file lists use Windows `CF_HDROP`, X11 selection requests, or Wayland `wlr-data-control` (KDE Plasma and compatible compositors). Unsupported Wayland compositors report an error rather than downloading eagerly.
- Contents are requested when another application asks to read the native file-list format, normally during paste. Clipboard managers or file previews can also request that format before a user presses Ctrl+V. BLEClip avoids reading its own delayed file list and supplies KDE's exclusion hint, but cannot distinguish a third-party clipboard read from paste.
- File offers/requests extend the v3 application payload types. Update all peers to this build for on-demand file copy/paste. Text and image message formats are unchanged.

### Windows BLE peripheral-role fallback (HRESULT 0x8007013C)

Some Bluetooth adapters support the Windows BLE **central/client** role but not
the connectable **peripheral/GATT server** role. This produces HRESULT
`0x8007013C` ("The device does not support the command feature") during
GATT advertising. The Windows `BluetoothAdapter.IsPeripheralRoleSupported` API
reports this separately from central support.

BLEClip v0.4.1 checks the Windows Bluetooth adapter when starting `peer` or
`tray`, including the double-click tray launcher. When peripheral
support is unavailable, it **automatically disables advertising** while still
scanning/connecting as central. Once connected to a GATT server, clipboard
data can travel in **both directions**.

```powershell
.\\bleclip.exe diagnose
.\\bleclip.exe peer --key-file .\\bleclip.key
# Optional explicit central-only workaround:
.\\bleclip.exe peer --key-file .\\bleclip.key --no-advertise --sync-files
```

- `bleclip diagnose` reports the Windows adapter's LE, Central, and
  Peripheral-role support. It does not require a clipboard key.
- A Linux peer with BLE GATT advertising support can serve as the peripheral.
- If **both Windows devices cannot advertise**, two such machines cannot
  directly connect to each other with GATT-only BLEClip. Use an
  advertising-capable peer/adapter or a different transport.
- The peripheral-only `serve` command returns an actionable error
  rather than looping if Windows reports the peripheral role unsupported.
- If an adapter claims support but GATT advertising still fails with the
  same HRESULT, BLEClip stops advertising retries while the central
  scanner remains active.
- This fallback does **not** change the shared-key authentication, encryption,
  or the directions in which clipboard text, images, and files synchronize.

BLE central/peripheral are radio connection roles, not cloud-server roles.

### Build prerequisites

Arch Linux:

```bash
sudo pacman -S --needed base-devel rust pkgconf dbus bluez bluez-utils libx11 libxcb wayland
sudo systemctl enable --now bluetooth
cargo build --release
```

Ubuntu/Debian:

```bash
sudo apt install build-essential pkg-config libdbus-1-dev libudev-dev libx11-dev libxcb1-dev libwayland-dev
sudo systemctl enable --now bluetooth
cargo build --release
```

Windows: install the Rust MSVC toolchain and Microsoft C++ Build Tools. Bluetooth advertising may not be supported by some Windows drivers. Run under your desktop user, not as Administrator/root.

On Linux, `arboard` supports X11 and Wayland data-control when available. Some Wayland compositors, clipboard managers, and file managers handle clipboard files/images differently. Keep the BLEClip process running so the Linux selection stays owned.

## Transport, reliability, and mesh details

1. Nearby peers discover a dedicated **v3** BLE service UUID and establish a GATT link.
2. The original group-PSK authenticated ephemeral X25519 handshake derives unique per-link keys. Every application packet uses XChaCha20-Poly1305; advertisements contain no clipboard payload.
3. The sender announces `{UUID, origin, hops, type, total size, SHA-256}`, then sends numbered **1,024-byte plaintext chunks**, each separately encrypted and framed over 20-byte GATT writes/reads (minimum standard ATT payload).
4. Receiver rejects missing/out-of-order/truncated/tampered chunks and verifies the whole SHA-256 digest. After a complete transfer it sends an authenticated ACK. Sender retries up to three times if ACK is not received on an otherwise open link.
5. A router applies the clipboard update and relays the **completed** payload to other authorized peers. Its event UUID remains constant over each hop, with up to eight hops and deduplication to stop loops. Copies are shared cheaply using `Arc<[u8]>`.
6. Each GATT link can process one inbound and one outbound transfer at a time. Each link retains the latest waiting clipboard item and up to four separate file-transfer messages; additional file-transfer messages can be dropped on overload. `broadcast` queues are bounded.

**ACK means the peer reassembled and authenticated the bytes, not that another desktop app has pasted the item.** There is no durable store-and-forward for peers that disconnect, no transfer continuation after reconnect, and no guarantee of exactly-once file placement after process restarts. Relays decrypt and re-encrypt content because all devices with the shared group key are mutually trusted; this is *per-link* encryption, not a zero-knowledge mesh.

**Performance warning:** the GATT fallback uses 20-byte fragments and polled reads and can be extremely slow for megabyte-sized payloads. Linux peers can use the optional LE L2CAP channel described above. Neither path is suitable for multi-gigabyte transfers; a BLE-discovered encrypted LAN or Wi-Fi transport is not implemented.

**Protocol breaking change:** v3 uses distinct service UUIDs and crypto handshake labels and is incompatible with v0.2. All computers must upgrade.

## Security decisions

- File sync is **off by default** to prevent unexpected file disclosure and incoming disk writes.
- Receivers accept up to 16 regular files with a total payload cap of 64 MiB; filenames are sanitized, cannot contain path traversal, and Windows device names are escaped.
- Received files are stored in a unique per-event directory, first written to a staging directory, and then atomically renamed on the same filesystem. Existing destination directories are not overwritten; failed staging is removed.
- Linux staging directories use mode `0700` and files `0600`; other platforms use desktop user filesystem permissions.
- PNG decoder applies dimensions and memory limits. Unrecognized payloads and corrupt hashes are rejected.
- Every authorized peer can inject clipboard contents or file data. Protect the PSK and do not join untrusted groups.

## Test commands

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Unit tests cover cryptographic authentication/replay, framed BLE chunks, large transfer assembly/ACK, digest tampering, duplicate retry, two simultaneous independently encrypted sessions, multi-peer relay loops, 16 subscribers, safe filename handling, and PNG image conversion. GitHub Actions builds Windows and Linux; actual two- or three-computer hardware tests remain necessary.
