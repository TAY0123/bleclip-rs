use super::*;
use std::{fs::File, io::Write, os::fd::AsRawFd};
use wayland_client::{
    protocol::{wl_registry, wl_seat},
    Connection, Dispatch, QueueHandle,
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1 as device, zwlr_data_control_manager_v1 as manager,
    zwlr_data_control_offer_v1 as offer, zwlr_data_control_source_v1 as source,
};

const URI_ESCAPE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'#')
    .add(b'%')
    .add(b'?')
    .add(b'"');
fn uri_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| {
            format!(
                "file://{}\n",
                percent_encoding::percent_encode(p.as_os_str().as_encoded_bytes(), URI_ESCAPE)
            )
        })
        .collect()
}
struct State {
    manager: Option<manager::ZwlrDataControlManagerV1>,
    seat: Option<wl_seat::WlSeat>,
    fetch: Fetch,
    cached: Option<String>,
    alive: Arc<AtomicBool>,
}
impl Dispatch<wl_registry::WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            match interface.as_str() {
                "zwlr_data_control_manager_v1" => {
                    state.manager = Some(registry.bind(name, version.min(2), qh, ()))
                }
                "wl_seat" if state.seat.is_none() => {
                    state.seat = Some(registry.bind(name, version.min(2), qh, ()))
                }
                _ => {}
            }
        }
    }
}
wayland_client::delegate_noop!(State: ignore wl_seat::WlSeat);
wayland_client::delegate_noop!(State: ignore manager::ZwlrDataControlManagerV1);
wayland_client::delegate_noop!(State: ignore offer::ZwlrDataControlOfferV1);
impl Dispatch<device::ZwlrDataControlDeviceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &device::ZwlrDataControlDeviceV1,
        event: device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let device::Event::Finished = event {
            state.alive.store(false, Ordering::SeqCst);
        }
    }
    wayland_client::event_created_child!(State, device::ZwlrDataControlDeviceV1, [0 => (offer::ZwlrDataControlOfferV1, ())]);
}
impl Dispatch<source::ZwlrDataControlSourceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &source::ZwlrDataControlSourceV1,
        event: source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            source::Event::Cancelled => state.alive.store(false, Ordering::SeqCst),
            source::Event::Send { mime_type, fd } => {
                let mut pipe = File::from(fd);
                if mime_type == "text/uri-list" || mime_type == "x-special/gnome-copied-files" {
                    if state.cached.is_none() {
                        match (state.fetch)() {
                            Ok(paths) => state.cached = Some(uri_list(&paths)),
                            Err(err) => {
                                crate::desktop::notify("File paste failed", &format!("{err:#}"));
                                return;
                            }
                        }
                    }
                    if let Some(value) = &state.cached {
                        if mime_type == "x-special/gnome-copied-files" {
                            let _ = pipe.write_all(b"copy\n");
                        }
                        let _ = pipe.write_all(value.as_bytes());
                    }
                } else if mime_type == "x-kde-passwordManagerHint" {
                    let _ = pipe.write_all(b"secret");
                }
            }
            _ => {}
        }
    }
}

pub fn run(
    fetch: Fetch,
    alive: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<()> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return wayland(fetch, alive, ready);
    }
    x11(fetch, alive, ready)
}
fn wayland(
    fetch: Fetch,
    alive: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<()> {
    let connection = Connection::connect_to_env()?;
    let mut queue = connection.new_event_queue();
    let qh = queue.handle();
    let _registry = connection.display().get_registry(&qh, ());
    let mut state = State {
        manager: None,
        seat: None,
        fetch,
        cached: None,
        alive: alive.clone(),
    };
    queue.roundtrip(&mut state)?;
    let manager = state
        .manager
        .as_ref()
        .context("Wayland compositor needs wlr-data-control for delayed file paste")?;
    let seat = state.seat.as_ref().context("no Wayland seat")?;
    let device = manager.get_data_device(seat, &qh, ());
    let source = manager.create_data_source(&qh, ());
    source.offer("text/uri-list".into());
    source.offer("x-special/gnome-copied-files".into());
    // Ask KDE's clipboard manager not to eagerly materialize the file list.
    source.offer("x-kde-passwordManagerHint".into());
    device.set_selection(Some(&source));
    connection.flush()?;
    let _ = ready.send(Ok(()));
    while alive.load(Ordering::SeqCst) {
        queue.dispatch_pending(&mut state)?;
        connection.flush()?;
        if let Some(guard) = queue.prepare_read() {
            let mut fd = libc::pollfd {
                fd: guard.connection_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut fd, 1, 100) } > 0 {
                guard.read()?;
            }
        }
    }
    source.destroy();
    device.destroy();
    let _ = connection.flush();
    Ok(())
}

fn x11(
    fetch: Fetch,
    alive: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<()> {
    use x11rb::{
        connection::Connection as _,
        protocol::{xproto::*, Event},
        wrapper::ConnectionExt as _,
        COPY_DEPTH_FROM_PARENT, CURRENT_TIME, NONE,
    };
    let (conn, screen) = x11rb::connect(None)?;
    let window = conn.generate_id()?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        window,
        conn.setup().roots[screen].root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new(),
    )?
    .check()?;
    let atom = |name: &[u8]| -> Result<u32> { Ok(conn.intern_atom(false, name)?.reply()?.atom) };
    let selection = atom(b"CLIPBOARD")?;
    let targets = atom(b"TARGETS")?;
    let uri = atom(b"text/uri-list")?;
    let gnome = atom(b"x-special/gnome-copied-files")?;
    let exclusion = atom(b"x-kde-passwordManagerHint")?;
    conn.set_selection_owner(window, selection, CURRENT_TIME)?
        .check()?;
    anyhow::ensure!(
        conn.get_selection_owner(selection)?.reply()?.owner == window,
        "cannot own X11 clipboard"
    );
    let _ = ready.send(Ok(()));
    let mut cached = None;
    while alive.load(Ordering::SeqCst) {
        if let Some(event) = conn.poll_for_event()? {
            match event {
                Event::SelectionClear(_) => break,
                Event::SelectionRequest(req) => {
                    let prop = if req.property == NONE {
                        req.target
                    } else {
                        req.property
                    };
                    let mut result_prop = prop;
                    if req.target == targets {
                        conn.change_property32(
                            PropMode::REPLACE,
                            req.requestor,
                            prop,
                            AtomEnum::ATOM,
                            &[targets, uri, gnome, exclusion],
                        )?;
                    } else if req.target == exclusion {
                        conn.change_property8(
                            PropMode::REPLACE,
                            req.requestor,
                            prop,
                            exclusion,
                            b"secret",
                        )?;
                    } else if req.target == uri || req.target == gnome {
                        if cached.is_none() {
                            match fetch() {
                                Ok(paths) => cached = Some(uri_list(&paths)),
                                Err(err) => {
                                    crate::desktop::notify(
                                        "File paste failed",
                                        &format!("{err:#}"),
                                    );
                                }
                            }
                        }
                        if let Some(value) = &cached {
                            let value = if req.target == gnome {
                                format!("copy\n{value}")
                            } else {
                                value.clone()
                            };
                            conn.change_property8(
                                PropMode::REPLACE,
                                req.requestor,
                                prop,
                                req.target,
                                value.as_bytes(),
                            )?;
                        } else {
                            result_prop = NONE;
                        }
                    } else {
                        result_prop = NONE;
                    }
                    let event = SelectionNotifyEvent {
                        response_type: SELECTION_NOTIFY_EVENT,
                        sequence: 0,
                        time: req.time,
                        requestor: req.requestor,
                        selection: req.selection,
                        target: req.target,
                        property: result_prop,
                    };
                    conn.send_event(false, req.requestor, EventMask::NO_EVENT, event)?;
                    conn.flush()?;
                }
                _ => {}
            }
        } else {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    conn.destroy_window(window)?;
    conn.flush()?;
    Ok(())
}
