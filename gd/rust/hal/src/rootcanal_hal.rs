//! Rootcanal HAL
//! This connects to "rootcanal" which provides a simulated
//! Bluetooth chip as well as a simulated environment.

use crate::internal::Hal;
use crate::{HalExports, Result, H4_HEADER_SIZE};
use bt_packet::{HciCommand, HciEvent, HciPacketHeaderSize, HciPacketType, RawPacket};
use bytes::{BufMut, Bytes, BytesMut};
use gddi::{module, provides, Stoppable};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

module! {
    rootcanal_hal_module,
    providers {
        HalExports => provide_rootcanal_hal,
    }
}

#[provides]
async fn provide_rootcanal_hal(config: RootcanalConfig, rt: Arc<Runtime>) -> HalExports {
    let (hal_exports, hal) = Hal::new();
    let (reader, writer) = TcpStream::connect(&config.to_socket_addr().unwrap())
        .await
        .expect("unable to create stream to rootcanal")
        .into_split();

    rt.spawn(dispatch_incoming(hal.evt_tx, hal.acl_tx, reader));
    rt.spawn(dispatch_outgoing(hal.cmd_rx, hal.acl_rx, writer));

    hal_exports
}

/// Rootcanal configuration
#[derive(Clone, Debug, Default, Stoppable)]
pub struct RootcanalConfig {
    address: String,
    port: u16,
}

impl RootcanalConfig {
    /// Create a rootcanal config
    pub fn new(address: &str, port: u16) -> Self {
        Self {
            address: String::from(address),
            port,
        }
    }

    fn to_socket_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::from_str(&self.address)?, self.port))
    }
}

/// Send HCI events received from the HAL to the HCI layer
async fn dispatch_incoming<R>(
    evt_tx: UnboundedSender<HciEvent>,
    acl_tx: UnboundedSender<RawPacket>,
    reader: R,
) -> Result<()>
where
    R: AsyncReadExt + Unpin,
{
    let mut reader = BufReader::new(reader);
    loop {
        let mut buffer = BytesMut::with_capacity(1024);
        buffer.resize(H4_HEADER_SIZE, 0);
        reader.read_exact(&mut buffer).await?;
        if buffer[0] == HciPacketType::Event as u8 {
            buffer.resize(HciPacketHeaderSize::Event as usize, 0);
            reader.read_exact(&mut buffer).await?;
            let len: usize = buffer[1].into();
            let mut payload = buffer.split_off(HciPacketHeaderSize::Event as usize);
            payload.resize(len, 0);
            reader.read_exact(&mut payload).await?;
            buffer.unsplit(payload);
            evt_tx.send(buffer.freeze()).unwrap();
        } else if buffer[0] == HciPacketType::Acl as u8 {
            buffer.resize(HciPacketHeaderSize::Acl as usize, 0);
            reader.read_exact(&mut buffer).await?;
            let len: usize = (buffer[2] as u16 + ((buffer[3] as u16) << 8)).into();
            let mut payload = buffer.split_off(HciPacketHeaderSize::Event as usize);
            payload.resize(len, 0);
            reader.read_exact(&mut payload).await?;
            buffer.unsplit(payload);
            acl_tx.send(buffer.freeze()).unwrap();
        }
    }
}

/// Send commands received from the HCI later to rootcanal
async fn dispatch_outgoing<W>(
    mut cmd_rx: UnboundedReceiver<HciCommand>,
    mut acl_rx: UnboundedReceiver<RawPacket>,
    mut writer: W,
) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    loop {
        select! {
            Some(cmd) = cmd_rx.recv() => write_with_type(&mut writer, HciPacketType::Command, cmd).await?,
            Some(acl) = acl_rx.recv() => write_with_type(&mut writer, HciPacketType::Acl, acl).await?,
            else => break,
        }
    }

    Ok(())
}

async fn write_with_type<W>(writer: &mut W, t: HciPacketType, b: Bytes) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut data = BytesMut::with_capacity(b.len() + 1);
    data.put_u8(t as u8);
    data.extend(b);
    writer.write_all(&data[..]).await?;

    Ok(())
}
