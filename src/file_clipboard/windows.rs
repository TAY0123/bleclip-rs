use super::*;
use std::cell::RefCell;
use windows_sys::Win32::{
    Foundation::*,
    System::{DataExchange::*, LibraryLoader::GetModuleHandleW, Memory::*},
    UI::WindowsAndMessaging::*,
};

struct State {
    fetch: Fetch,
    alive: Arc<AtomicBool>,
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
const CF_HDROP: u32 = 15;
unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_RENDERFORMAT if w as u32 == CF_HDROP => {
            STATE.with(|state| {
                if let Some(state) = state.borrow().as_ref() {
                    match (state.fetch)().and_then(|paths| render(&paths)) {
                        Ok(()) => {}
                        Err(err) => {
                            crate::desktop::notify("File paste failed", &format!("{err:#}"))
                        }
                    }
                }
            });
            0
        }
        WM_DESTROYCLIPBOARD => {
            STATE.with(|state| {
                if let Some(state) = state.borrow().as_ref() {
                    state.alive.store(false, Ordering::SeqCst);
                }
            });
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, w, l) },
    }
}
fn render(paths: &[PathBuf]) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let mut list = Vec::<u16>::new();
    for path in paths {
        list.extend(path.as_os_str().encode_wide());
        list.push(0);
    }
    list.push(0);
    // DROPFILES: offset, POINT, fNC, fWide, then a double-NUL UTF-16 list.
    let size = 20 + list.len() * 2;
    unsafe {
        let memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size);
        anyhow::ensure!(!memory.is_null(), "allocating clipboard file list");
        let ptr = GlobalLock(memory) as *mut u8;
        if ptr.is_null() {
            GlobalFree(memory);
            anyhow::bail!("locking clipboard memory");
        }
        std::ptr::copy_nonoverlapping(20u32.to_le_bytes().as_ptr(), ptr, 4);
        std::ptr::copy_nonoverlapping(1u32.to_le_bytes().as_ptr(), ptr.add(16), 4);
        std::ptr::copy_nonoverlapping(list.as_ptr() as *const u8, ptr.add(20), list.len() * 2);
        GlobalUnlock(memory);
        if SetClipboardData(CF_HDROP, memory).is_null() {
            GlobalFree(memory);
            anyhow::bail!("rendering clipboard file list");
        }
    }
    Ok(())
}
pub fn run(
    fetch: Fetch,
    alive: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<()> {
    unsafe {
        let class: Vec<u16> = "BLEClipDelayedFiles"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let instance = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        anyhow::ensure!(!hwnd.is_null(), "creating clipboard owner window");
        let setup = (|| -> Result<()> {
            let mut opened = false;
            for _ in 0..20 {
                if OpenClipboard(hwnd) != 0 {
                    opened = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            anyhow::ensure!(opened, "clipboard is busy");
            let emptied = EmptyClipboard();
            if emptied != 0 {
                // A NULL handle is the documented delayed-rendering registration.
                SetClipboardData(CF_HDROP, std::ptr::null_mut());
            }
            CloseClipboard();
            anyhow::ensure!(emptied != 0, "cannot empty clipboard");
            STATE.with(|state| {
                *state.borrow_mut() = Some(State {
                    fetch,
                    alive: alive.clone(),
                })
            });
            Ok(())
        })();
        if let Err(err) = setup {
            let _ = ready.send(Err(format!("{err:#}")));
            DestroyWindow(hwnd);
            return Err(err);
        }
        let _ = ready.send(Ok(()));
        while alive.load(Ordering::SeqCst) {
            let mut message: MSG = std::mem::zeroed();
            while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            if GetClipboardOwner() != hwnd {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        DestroyWindow(hwnd);
        STATE.with(|state| *state.borrow_mut() = None);
    }
    Ok(())
}
