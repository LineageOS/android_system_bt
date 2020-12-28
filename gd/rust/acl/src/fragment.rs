//! Handles fragmentation & reassembly of ACL packets into whole L2CAP payloads

use bt_packets::hci::{AclChild, AclPacket, BroadcastFlag, PacketBoundaryFlag};
use bytes::{Buf, Bytes, BytesMut};
use log::{error, info, warn};
use tokio::sync::mpsc::Sender;

const L2CAP_BASIC_FRAME_HEADER_LEN: usize = 4;

pub struct Reassembler {
    buffer: Option<BytesMut>,
    remaining: usize,
    out: Sender<Bytes>,
}

impl Reassembler {
    /// Create a new reassembler
    pub fn new(out: Sender<Bytes>) -> Self {
        Self { buffer: None, remaining: 0, out }
    }

    /// Injest the packet and send out if fully reassembled
    pub async fn on_packet(&mut self, packet: AclPacket) {
        let payload = match packet.specialize() {
            AclChild::Payload(payload) => payload,
            AclChild::None => {
                info!("dropping ACL packet with empty payload");
                return;
            }
        };

        if let BroadcastFlag::ActivePeripheralBroadcast = packet.get_broadcast_flag() {
            // we do not accept broadcast packets
            return;
        }

        match packet.get_packet_boundary_flag() {
            PacketBoundaryFlag::FirstNonAutomaticallyFlushable => error!("not allowed to send FIRST_NON_AUTOMATICALLY_FLUSHABLE to host except loopback mode"),
            PacketBoundaryFlag::FirstAutomaticallyFlushable => {
                if self.buffer.take().is_some() {
                    error!("got a start packet without finishing previous reassembly - dropping previous");
                }

                let full_size = get_l2cap_pdu_size(&payload);
                self.remaining = full_size - (payload.len() - L2CAP_BASIC_FRAME_HEADER_LEN);
                if self.remaining > 0 {
                    let mut buffer = BytesMut::with_capacity(full_size);
                    buffer.extend_from_slice(&payload[..]);
                    self.buffer = Some(buffer);
                } else {
                    self.out.send(payload).await.unwrap();
                }
            },
            PacketBoundaryFlag::ContinuingFragment => {
                match self.buffer.take() {
                    None => warn!("got continuation packet without pending reassembly"),
                    Some(_) if self.remaining < payload.len() => warn!("remote sent unexpected L2CAP PDU - dropping entire packet"),
                    Some(mut buffer) => {
                        self.remaining -= payload.len();
                        buffer.extend_from_slice(&payload[..]);
                        if self.remaining == 0 {
                            self.out.send(buffer.freeze()).await.unwrap();
                        } else {
                            self.buffer = Some(buffer);
                        }
                    }
                }
            },
        }
    }
}

fn get_l2cap_pdu_size(first_packet: &Bytes) -> usize {
    if first_packet.len() <= L2CAP_BASIC_FRAME_HEADER_LEN {
        error!("invalid l2cap starting packet");

        0
    } else {
        (&first_packet[..]).get_u16_le() as usize
    }
}
