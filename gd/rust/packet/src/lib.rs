//! HCI packet representation
//! This is temporary and will be replaced by a shim that uses
//! existing C++ packet code through CXX

use bytes::Bytes;
use num_derive::{FromPrimitive, ToPrimitive};

/// Packet types
#[derive(FromPrimitive, ToPrimitive)]
pub enum HciPacketType {
    /// HCI command packet
    Command = 0x01,
    /// ACL data packet
    Acl = 0x02,
    /// SCO data packet
    Sco = 0x03,
    /// HCI event packet
    Event = 0x04,
}

/// Header size (in bytes) for each packet type
#[derive(FromPrimitive, ToPrimitive)]
pub enum HciPacketHeaderSize {
    /// HCI Event packet header size
    Event = 2,
    /// SCO packet header size
    Sco = 3,
    /// ACL packet header size
    Acl = 4,
}

/// Raw packet
pub type RawPacket = Bytes;

/// HCI command packet
pub type HciCommand = Bytes;

/// Gets the 16-bit opcode for an HCI command
pub fn get_cmd_opcode(cmd: &HciCommand) -> Option<u16> {
    let b0 = ((cmd[0] as u16) << 8) as u16;
    let b1 = (cmd[1] as u16) as u16;
    Some(b0 | b1)
}

/// HCI event packet
pub type HciEvent = Bytes;

/// Gets the HCI command opcode corresponding to an event
pub fn get_evt_opcode(event: &HciEvent) -> Option<u16> {
    let b0 = ((event[3] as u16) << 8) as u16;
    let b1 = (event[4] as u16) as u16;
    Some(b0 | b1)
}

/// Gets the event code for an HCI event
pub fn get_evt_code(event: &HciEvent) -> Option<u8> {
    Some(event[0])
}

/// Packet bytes for each packet type
#[derive(Debug)]
pub enum HciPacket {
    /// HCI command
    Command(HciCommand),
    /// ACL packet
    Acl(RawPacket),
    /// SCO packet
    Sco(RawPacket),
    /// HCI event
    Event(HciEvent),
}
