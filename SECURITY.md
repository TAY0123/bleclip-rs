# Security status — BLEClip v0.3

**Experimental, not audited.** Do not treat BLEClip as a production security boundary until it compiles on your platform, passes physical BLE tests, and has had a security review.

- All devices use one shared PSK. Possession of that key permits any device to impersonate a group member, decrypt relayed content, and inject malicious clipboard items. The project does not implement individual peer approval, key rotation, per-device revoke lists, or signed sender identity.
- All messages are authenticated and encrypted independently on each BLE link. Mesh relays see plaintext to forward it and may modify it; it is not end-to-end encrypted across a mesh of distrustful nodes. Advertisement metadata is public.
- Text and screenshots copied while BLEClip runs can include secrets, passwords, account data or tokens. Consider disabling automatic clipboard sharing when handling sensitive content.
- `--sync-files` is intentionally opt-in. Incoming files are saved into separate per-transfer directories; they are not executed. File copy or paste may disclose local files to every authorized peer or cause disk usage.
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
