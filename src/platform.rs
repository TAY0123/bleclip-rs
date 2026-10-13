//! BLE role capability policy and Windows GATT peripheral support detection.
use anyhow::{bail, Result};

/// Radio role support as reported by Windows, not a guarantee that GATT
/// advertising can successfully start with every driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BleCapabilities {
    pub low_energy: bool,
    pub central: bool,
    pub peripheral: bool,
}

#[cfg(windows)]
pub(crate) async fn capabilities() -> Result<Option<BleCapabilities>> {
    use windows::Devices::Bluetooth::BluetoothAdapter;
    let adapter = BluetoothAdapter::GetDefaultAsync()?.await?;
    Ok(Some(BleCapabilities {
        low_energy: adapter.IsLowEnergySupported()?,
        central: adapter.IsCentralRoleSupported()?,
        peripheral: adapter.IsPeripheralRoleSupported()?,
    }))
}

#[cfg(not(windows))]
pub(crate) async fn capabilities() -> Result<Option<BleCapabilities>> {
    // BlueZ peripheral capabilities are typically adapter- and driver-specific.
    // Preserve the existing Linux advertise + scan behavior.
    Ok(None)
}

/// Select BLE roles without changing the direction of clipboard synchronization.
///
/// Peripheral support is needed for advertising connectable GATT services but
/// is *not* needed for sending and receiving over a central/client connection.
pub(crate) fn select_roles(
    requested_advertise: bool,
    requested_scan: bool,
    capability: Option<BleCapabilities>,
) -> Result<(bool, bool)> {
    let mut advertise = requested_advertise;
    if let Some(cap) = capability {
        if advertise && (!cap.low_energy || !cap.peripheral) {
            if !requested_scan {
                bail!(
                    "Bluetooth adapter does not support the BLE peripheral role (Windows HRESULT 0x8007013C).                      Peer mode needs --no-advertise and another computer advertising;                      peripheral-only serve mode requires a different Bluetooth adapter."
                );
            }
            advertise = false;
        }
    }
    if !advertise && !requested_scan {
        bail!("peer needs at least one usable Bluetooth LE role");
    }
    Ok((advertise, requested_scan))
}

/// Some Windows drivers advertise peripheral support but still reject starting
/// a connectable GATT service. Avoid endless retry logs for this hard failure.
pub(crate) fn is_unsupported_peripheral_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("0x8007013c")
        || lower.contains("device does not support the command feature")
        || lower.contains("device doesn't support the command feature")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn capabilities(peripheral: bool) -> BleCapabilities {
        BleCapabilities {
            low_energy: true,
            central: true,
            peripheral,
        }
    }

    #[test]
    fn peripheral_unavailable_falls_back_to_central() {
        assert_eq!(
            select_roles(true, true, Some(capabilities(false))).unwrap(),
            (false, true)
        );
        assert_eq!(
            select_roles(true, true, Some(capabilities(true))).unwrap(),
            (true, true)
        );
        assert_eq!(
            select_roles(false, true, Some(capabilities(false))).unwrap(),
            (false, true)
        );
    }

    #[test]
    fn unsupported_peripheral_only_errors_actionably() {
        let err = select_roles(true, false, Some(capabilities(false))).unwrap_err();
        assert!(err.to_string().contains("0x8007013C"));
        assert!(err.to_string().contains("--no-advertise"));
        assert!(select_roles(false, false, None).is_err());
    }

    #[test]
    fn unsupported_hresult_is_identified() {
        assert!(is_unsupported_peripheral_error("WinRT Error 0x8007013C"));
        assert!(is_unsupported_peripheral_error(
            "The device does not support the command feature"
        ));
        assert!(!is_unsupported_peripheral_error(
            "BLE adapter not powered on"
        ));
    }
}
