//! Windows Shell_NotifyIcon and Linux StatusNotifierItem (KDE Plasma / Wayland).
//! Pausing terminates BLE sessions rather than merely hiding clipboard events.
use crate::{
    status::{ConnectionSnapshot, Connections},
    PeerOptions,
};
use anyhow::{Context, Result};
use std::{sync::Arc, thread, time::Duration};
use tokio::{runtime::Builder, sync::watch};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
    Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrayState {
    pub enabled: bool,
    pub quit: bool,
}

impl TrayState {
    fn toggle(self) -> Self {
        if self.quit {
            self
        } else {
            Self {
                enabled: !self.enabled,
                quit: false,
            }
        }
    }
}

fn icon_pixels(enabled: bool) -> Vec<u8> {
    const SIDE: usize = 32;
    let mut rgba = vec![0; SIDE * SIDE * 4];
    let color = if enabled {
        [36, 151, 95]
    } else {
        [118, 122, 132]
    };
    for y in 0..SIDE {
        for x in 0..SIDE {
            let dx = x as isize - 15;
            let dy = y as isize - 15;
            if dx * dx + dy * dy > 14 * 14 {
                continue;
            }
            let outline = (9..=22).contains(&x)
                && (10..=24).contains(&y)
                && (x == 9 || x == 22 || y == 10 || y == 24);
            let clip = (13..=18).contains(&x) && (8..=11).contains(&y);
            let slash =
                !enabled && (x as isize + y as isize - 30).abs() <= 2 && (8..=24).contains(&x);
            let rgb = if outline || clip || slash {
                [255, 255, 255]
            } else {
                color
            };
            let offset = (y * SIDE + x) * 4;
            rgba[offset..offset + 3].copy_from_slice(&rgb);
            rgba[offset + 3] = 255;
        }
    }
    rgba
}

fn make_icon(enabled: bool) -> Result<Icon> {
    Icon::from_rgba(icon_pixels(enabled), 32, 32)
        .context("failed to create clipboard-sharing tray icon")
}

fn redraw(tray: &TrayIcon, toggle_menu: &MenuItem, state: TrayState) -> Result<()> {
    tray.set_icon(Some(make_icon(state.enabled)?))?;
    let action = if state.enabled {
        "Pause sharing"
    } else {
        "Resume sharing"
    };
    toggle_menu.set_text(action);
    let tooltip = if state.enabled {
        "BLEClip - Sharing ON"
    } else {
        "BLEClip - Sharing PAUSED"
    };
    tray.set_tooltip(Some(tooltip))?;
    Ok(())
}

fn toggle(sharing: &watch::Sender<TrayState>, tray: &TrayIcon, item: &MenuItem) -> Result<()> {
    let state = (*sharing.borrow()).toggle();
    sharing.send_replace(state);
    redraw(tray, item, state)?;
    println!(
        "BLEClip clipboard sharing {}",
        if state.enabled { "enabled" } else { "paused" }
    );
    Ok(())
}

#[cfg(windows)]
fn pump_native_events() -> bool {
    // Shell_NotifyIcon callbacks are delivered to a Win32 window from tray-icon.
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE, WM_QUIT,
    };
    unsafe {
        let mut message: MSG = std::mem::zeroed();
        while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
            if message.message == WM_QUIT {
                return true;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    false
}

#[cfg(not(windows))]
fn pump_native_events() -> bool {
    // KSNI maintains its D-Bus service on a worker thread (no GTK/X11 loop).
    false
}

/// The menu changes only when sharing or the authenticated link snapshot changes.
/// Cap visible rows, since a large BLE mesh must not create an enormous tray menu.
const MAX_PEER_MENU_ROWS: usize = 12;

fn connection_label(state: TrayState, snapshot: &ConnectionSnapshot) -> String {
    if !state.enabled || state.quit {
        return "Connection: paused".to_string();
    }
    if !snapshot.peers.is_empty() {
        let count = snapshot.peers.len();
        return format!(
            "Connection: {count} authenticated peer{}",
            if count == 1 { "" } else { "s" }
        );
    }
    if snapshot.scanning {
        "Connection: disconnected (searching)".to_string()
    } else if snapshot.advertising {
        "Connection: waiting for inbound peers".to_string()
    } else {
        "Connection: initializing BLE".to_string()
    }
}

fn scan_label(state: TrayState, snapshot: &ConnectionSnapshot) -> &'static str {
    if !state.enabled || state.quit {
        "Discovery: paused"
    } else if snapshot.scanning {
        "Discovery: startup + every 15 seconds"
    } else if snapshot.advertising {
        "Discovery: incoming connections only"
    } else {
        "Discovery: initializing"
    }
}

fn refresh_connections(
    tray: &TrayIcon,
    connection_item: &MenuItem,
    scan_item: &MenuItem,
    peers_submenu: &Submenu,
    rows: &mut Vec<MenuItem>,
    state: TrayState,
    snapshot: &ConnectionSnapshot,
) -> Result<()> {
    let summary = connection_label(state, snapshot);
    connection_item.set_text(&summary);
    scan_item.set_text(scan_label(state, snapshot));
    peers_submenu.set_text(format!(
        "Connected peers ({})",
        if state.enabled {
            snapshot.peers.len()
        } else {
            0
        }
    ));

    for item in rows.drain(..) {
        peers_submenu.remove(&item)?;
    }
    if !state.enabled || snapshot.peers.is_empty() {
        rows.push(MenuItem::new("No authenticated peers", false, None));
    } else {
        for peer in snapshot.peers.iter().take(MAX_PEER_MENU_ROWS) {
            rows.push(MenuItem::new(peer.label(), false, None));
        }
        if snapshot.peers.len() > MAX_PEER_MENU_ROWS {
            rows.push(MenuItem::new(
                format!("... and {} more", snapshot.peers.len() - MAX_PEER_MENU_ROWS),
                false,
                None,
            ));
        }
    }
    for item in rows.iter() {
        peers_submenu.append(item)?;
    }
    tray.set_tooltip(Some(format!("BLEClip - {summary}")))?;
    Ok(())
}

async fn worker(
    config: PeerOptions,
    mut control: watch::Receiver<TrayState>,
    connections: Arc<Connections>,
) {
    loop {
        let state = *control.borrow_and_update();
        if state.quit {
            break;
        }
        if !state.enabled {
            connections.reset();
            if control.changed().await.is_err() {
                break;
            }
            continue;
        }
        if let Err(error) = crate::run_peer(
            config.clone(),
            Some(control.clone()),
            Arc::clone(&connections),
        )
        .await
        {
            eprintln!("BLEClip peer unavailable: {error:#}; retrying while sharing is enabled");
        }
        // Pending encrypted frames are discarded when the BLE tasks are stopped.
        if control.borrow().quit {
            break;
        }
        if control.borrow().enabled {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                _ = control.changed() => {}
            }
        }
    }
}

/// The tray stays on the UI thread; the peer runs on a dedicated Tokio runtime.
pub(crate) fn run(mut config: PeerOptions) -> Result<()> {
    config.sync_files = true;
    let menu = Menu::new();
    let connection_item = MenuItem::new("Connection: initializing BLE", false, None);
    let scan_item = MenuItem::new("Discovery: startup + every 15 seconds", false, None);
    let peers_submenu = Submenu::new("Connected peers (0)", true);
    let mut rows: Vec<MenuItem> = Vec::new();
    let toggle_menu = MenuItem::new("Pause sharing", true, None);
    let send_file = MenuItem::new("Send file…", true, None);
    menu.append(&send_file)?;
    let quit_menu = MenuItem::new("Quit BLEClip", true, None);
    menu.append(&connection_item)?;
    menu.append(&scan_item)?;
    menu.append(&peers_submenu)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&toggle_menu)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&quit_menu)?;

    let tray = TrayIconBuilder::new()
        .with_icon(make_icon(true)?)
        .with_tooltip("BLEClip - Sharing ON")
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_menu_on_right_click(true)
        .build()
        .context("system tray is unavailable; use bleclip peer for headless operation")?;
    let tray_id = tray.id().clone();
    let connections = Connections::new();
    let snapshots = connections.subscribe();
    let (control_tx, control_rx) = watch::channel(TrayState {
        enabled: true,
        quit: false,
    });
    let background = thread::Builder::new()
        .name("bleclip-peer".to_string())
        .spawn(move || -> Result<()> {
            let rt = Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(worker(config, control_rx, connections));
            Ok(())
        })
        .context("unable to spawn clipboard synchronization worker")?;

    println!("BLEClip tray: left-click toggles sharing; right-click shows connected peers.");
    let ui_result = (|| -> Result<()> {
        let mut shown: Option<(TrayState, ConnectionSnapshot)> = None;
        loop {
            if pump_native_events() || background.is_finished() {
                break;
            }
            while let Ok(event) = TrayIconEvent::receiver().try_recv() {
                if let TrayIconEvent::Click {
                    id,
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    if id == tray_id {
                        toggle(&control_tx, &tray, &toggle_menu)?;
                    }
                }
            }
            let mut should_quit = false;
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if &event.id == toggle_menu.id() {
                    toggle(&control_tx, &tray, &toggle_menu)?;
                } else if &event.id == send_file.id() {
                    if control_tx.borrow().enabled {
                        thread::spawn(|| match crate::desktop::choose_files() {
                            Ok(paths) if !paths.is_empty() => {
                                if file_commands().send(paths).is_err() {
                                    crate::desktop::notify(
                                        "Cannot send files",
                                        "Sharing is paused or the Bluetooth worker is unavailable.",
                                    );
                                }
                            }
                            Ok(_) => {}
                            Err(err) => {
                                crate::desktop::notify("Cannot send file", &format!("{err:#}"))
                            }
                        });
                    }
                } else if &event.id == quit_menu.id() {
                    should_quit = true;
                }
            }
            if should_quit {
                break;
            }
            let current = (*control_tx.borrow(), snapshots.borrow().clone());
            if shown.as_ref() != Some(&current) {
                refresh_connections(
                    &tray,
                    &connection_item,
                    &scan_item,
                    &peers_submenu,
                    &mut rows,
                    current.0,
                    &current.1,
                )?;
                shown = Some(current);
            }
            thread::sleep(Duration::from_millis(70));
        }
        Ok(())
    })();

    // Also stop advertising and BLE transfer tasks when the tray UI exits.
    control_tx.send_replace(TrayState {
        enabled: false,
        quit: true,
    });
    let joined = background
        .join()
        .map_err(|_| anyhow::anyhow!("BLE worker panicked"))?;
    ui_result?;
    joined
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn toggling_is_reversible_and_quit_is_sticky() {
        let on = TrayState {
            enabled: true,
            quit: false,
        };
        assert_eq!(
            on.toggle(),
            TrayState {
                enabled: false,
                quit: false
            }
        );
        assert_eq!(on.toggle().toggle(), on);
        let quit = TrayState {
            enabled: false,
            quit: true,
        };
        assert_eq!(quit.toggle(), quit);
    }
    #[test]
    fn connection_menu_reports_scanning_and_authenticated_count() {
        let enabled = TrayState {
            enabled: true,
            quit: false,
        };
        let paused = enabled.toggle();
        let scanning = ConnectionSnapshot {
            scanning: true,
            advertising: false,
            peers: vec![],
        };
        assert!(connection_label(enabled, &scanning).contains("disconnected"));
        assert!(scan_label(enabled, &scanning).contains("15 seconds"));
        assert!(connection_label(paused, &scanning).contains("paused"));
        let peer = crate::status::PeerView {
            id: uuid::Uuid::nil(),
            inbound: 1,
            outbound: 1,
        };
        let online = ConnectionSnapshot {
            peers: vec![peer],
            ..scanning
        };
        assert!(connection_label(enabled, &online).contains("1 authenticated peer"));
    }
    #[test]
    fn status_icon_pixels_change_with_state() {
        assert_ne!(icon_pixels(true), icon_pixels(false));
        assert_eq!(icon_pixels(true).len(), 32 * 32 * 4);
    }
}

#[cfg(all(windows, feature = "tray-gui"))]
pub(crate) fn show_error(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let title: Vec<u16> = "BLEClip".encode_utf16().chain(std::iter::once(0)).collect();
    let text: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_ICONERROR | MB_OK,
        );
    }
}

/// UI selections are delivered only to a currently running clipboard owner.
pub(crate) fn file_commands() -> &'static tokio::sync::broadcast::Sender<Vec<std::path::PathBuf>> {
    static COMMANDS: std::sync::OnceLock<tokio::sync::broadcast::Sender<Vec<std::path::PathBuf>>> =
        std::sync::OnceLock::new();
    COMMANDS.get_or_init(|| tokio::sync::broadcast::channel(8).0)
}
