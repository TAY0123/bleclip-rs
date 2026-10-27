//! Linux LE credit-based L2CAP sockets, supplied by BlueZ's Rust bindings.
use super::Endpoint;
use anyhow::{ensure, Result};
use bluer::{
    l2cap::{Security, SecurityLevel, Socket, SocketAddr, Stream, StreamListener},
    Address, AddressType,
};

pub async fn listen() -> Result<(StreamListener, Endpoint)> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    ensure!(
        adapter.is_powered().await?,
        "Bluetooth adapter is powered off"
    );
    let address = adapter.address().await?;
    let address_type = adapter.address_type().await?;
    ensure!(
        matches!(address_type, AddressType::LePublic | AddressType::LeRandom),
        "adapter has no LE address"
    );
    let socket = Socket::<Stream>::new_stream()?;
    // The application protocol authenticates/encrypts independently, as GATT
    // does. Do not trigger OS pairing solely to enable the bulk channel.
    socket.set_security(Security {
        level: SecurityLevel::Low,
        key_size: 0,
    })?;
    socket.bind(SocketAddr::new(address, address_type, 0))?;
    socket.set_recv_mtu(8192)?;
    let local = socket.local_addr()?;
    ensure!(
        (0x80..=0xff).contains(&local.psm),
        "kernel did not allocate a dynamic LE PSM"
    );
    let listener = socket.listen(16)?;
    Ok((
        listener,
        Endpoint {
            address: address.0,
            address_type: match address_type {
                AddressType::LeRandom => 2,
                _ => 1,
            },
            psm: local.psm,
            token: [0; 32],
        },
    ))
}

pub async fn connect(endpoint: &Endpoint) -> Result<Stream> {
    let socket = Socket::<Stream>::new_stream()?;
    socket.set_security(Security {
        level: SecurityLevel::Low,
        key_size: 0,
    })?;
    socket.bind(SocketAddr::any_le())?;
    socket.set_recv_mtu(8192)?;
    let address_type = if endpoint.address_type == 2 {
        AddressType::LeRandom
    } else {
        AddressType::LePublic
    };
    Ok(socket
        .connect(SocketAddr::new(
            Address(endpoint.address),
            address_type,
            endpoint.psm,
        ))
        .await?)
}
