# Security status — BLEClip v0.3

**Experimental, not audited.** Do not treat BLEClip as a production security boundary until it compiles on your platform, passes physical BLE tests, and has had a security review.

- All devices use one shared PSK. Possession of that key permits any device to impersonate a group member, decrypt relayed content, and inject malicious clipboard items. The project does not implement individual peer approval, key rotation, per-device revoke lists, or signed sender identity.
- All messages are authenticated and encrypted independently on each BLE link. Mesh relays see plaintext to forward it and may modify it; it is not end-to-end encrypted across a mesh of distrustful nodes. Advertisement metadata is public.
- Text and screenshots copied while BLEClip runs can include secrets, passwords, account data or tokens. Consider disabling automatic clipboard sharing when handling sensitive content.
- File sharing is enabled by default in tray mode; CLI peer modes require `--sync-files`. File copying announces names and sizes to authorized peers; file contents are sent when a peer requests the file-list data (normally paste). Explicit **Send file…** actions transfer immediately. Incoming files are saved under Downloads/BLEClip in separate per-transfer directories and are not executed. Third-party clipboard managers can request data early. Authorized peers may request advertised files during the 30-minute offer lifetime; repeated requests may consume bandwidth or disk space.
- Files and PNG images have explicit caps but resource consumption may still be significant for large groups. The program is not resilient to every denial-of-service scenario.
- Per-hop ACK validates reassembly, not persistence at the final destination. Queue drops, BLE outages, application crashes, compositor limitations, and disconnects can cause lost clipboard updates. No offline resume.
- Do not put `bleclip.key` in a public repository. It is excluded by `.gitignore`; `keygen` refuses to overwrite existing keys.

Please report issues privately through GitHub's private vulnerability reporting if enabled.

## System tray pause semantics

The tray toggle stops BLE peer tasks and closes in-memory pending transfer queues when paused. It does not erase a clipboard item already received, delete a saved file, or revoke another device's previously copied content. Once sharing resumes, clipboard monitoring starts from the then-current clipboard contents and sends subsequent changes only. A UI icon indicates the user's sharing preference, not verified successful BLE connectivity.


## Windows peripheral mode fallback

When Windows cannot host a connectable GATT server, BLEClip disables only
the unsupported advertising role and continues scanning for advertising
peers. This does not change the authentication or cryptographic requirements
and does not enable LAN or internet transport. At least one device must
advertise for the BLE link to form.


## Tray connection status and discovery cadence

The tray menu lists remote node ID prefixes only after an authenticated BLE
identity exchange; detecting a radio advertisement is not proof of a trusted
peer. A peer with multiple links is counted once. Inbound connection entries
can remain visible briefly after an unannounced radio disconnect until
inactivity cleanup. Discovery retries at 15-second intervals to avoid
tight reconnection loops.
