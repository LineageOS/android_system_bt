//! Rootcanal HAL
//! This connects to "rootcanal" which provides a simulated
//! Bluetooth chip as well as a simulated environment.

use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use tokio::runtime::Runtime;

use futures::stream::StreamExt;
use tokio::sync::mpsc;

use bt_packet::{HciCommand, HciEvent, HciPacketHeaderSize, HciPacketType};

use std::sync::Arc;

use crate::{Hal, HalExports, Result, H4_HEADER_SIZE};

/// Rootcanal configuration
#[derive(Clone, Debug, Default)]
pub struct RootcanalConfig {
    port: u16,
    server_address: String,
}

impl RootcanalConfig {
    /// Create a rootcanal config
    pub fn new(port: u16, server_address: &str) -> Self {
        Self { port, server_address: String::from(server_address) }
    }
}

/// Rootcanal HAL
#[derive(Default)]
pub struct RootcanalHal;

impl RootcanalHal {
    /// Send HCI events received from the HAL to the HCI layer
    async fn dispatch_incoming<R>(evt_tx: mpsc::UnboundedSender<HciEvent>, reader: R) -> Result<()>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut reader = BufReader::new(reader);
        let header_size = H4_HEADER_SIZE + HciPacketHeaderSize::Event as usize;
        loop {
            let mut header = BytesMut::with_capacity(1024);
            header.resize(header_size, 0);
            reader.read_exact(&mut header).await?;
            let param_len: usize = header[2].into();
            let mut payload = header.split_off(header_size);
            payload.resize(param_len, 0);
            reader.read_exact(&mut payload).await?;
            let h4_type = header.split_to(H4_HEADER_SIZE);
            header.unsplit(payload);
            if h4_type[0] == HciPacketType::Event as u8 {
                evt_tx.send(header.freeze()).unwrap();
            }
        }
    }

    /// Send commands received from the HCI later to rootcanal
    async fn dispatch_outgoing<W>(
        mut cmd_rx: mpsc::UnboundedReceiver<HciCommand>,
        mut writer: W,
    ) -> Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        while let Some(next_cmd) = cmd_rx.next().await {
            let mut command = BytesMut::with_capacity(next_cmd.len() + 1);
            command.put_u8(HciPacketType::Command as u8);
            command.extend(next_cmd);
            writer.write_all(&command[..]).await?;
        }
        Ok(())
    }

    /// Connect to rootcanal and spawn tasks that handle incoming and outgoing packets
    pub async fn start(config: RootcanalConfig, rt: Arc<Runtime>) -> Result<HalExports> {
        let (hal_exports, hal) = Hal::new();
        let ipaddr = IpAddr::from_str(&config.server_address)?;
        let socket_addr = SocketAddr::new(ipaddr, config.port);
        let stream = TcpStream::connect(&socket_addr).await?;
        let (reader, writer) = stream.into_split();

        rt.spawn(Self::dispatch_incoming(hal.evt_tx, reader));
        rt.spawn(Self::dispatch_outgoing(hal.cmd_rx, writer));
        Ok(hal_exports)
    }
}
