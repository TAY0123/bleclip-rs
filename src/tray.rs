//! Windows Shell_NotifyIcon and Linux StatusNotifierItem (KDE Plasma / Wayland).
//! Pausing terminates BLE sessions rather than merely hiding clipboard events.
use crate::PeerOptions;
use anyhow::{Context, Result};
use std::{thread, time::Duration};
use tokio::{runtime::Builder, sync::watch};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
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

async fn worker(config: PeerOptions, mut control: watch::Receiver<TrayState>) {
    loop {
        let state = *control.borrow_and_update();
        if state.quit {
            break;
        }
        if !state.enabled {
            if control.changed().await.is_err() {
                break;
            }
            continue;
        }
        if let Err(error) = crate::run_peer(config.clone(), Some(control.clone())).await {
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
pub(crate) fn run(config: PeerOptions) -> Result<()> {
    let menu = Menu::new();
    let toggle_menu = MenuItem::new("Pause sharing", true, None);
    let quit_menu = MenuItem::new("Quit BLEClip", true, None);
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
    let (control_tx, control_rx) = watch::channel(TrayState {
        enabled: true,
        quit: false,
    });
    let background = thread::Builder::new()
        .name("bleclip-peer".to_string())
        .spawn(move || -> Result<()> {
            let rt = Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(worker(config, control_rx));
            Ok(())
        })
        .context("unable to spawn clipboard synchronization worker")?;

    println!("BLEClip tray: left-click toggles sharing; right-click opens menu.");
    let ui_result = (|| -> Result<()> {
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
                } else if &event.id == quit_menu.id() {
                    should_quit = true;
                }
            }
            if should_quit {
                break;
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
