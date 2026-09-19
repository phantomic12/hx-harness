//! A minimal SFTP (version 3) client, carried over a russh SSH channel.
//!
//! ## Why this module exists
//!
//! `SshHost` has to move bytes to and from a remote machine, and its first answer for that was to
//! shell out (`base64 < path` over an `exec` channel). That is binary-safe but it is not *file
//! transfer*: the remote's whole file is buffered through a command's stdout, it needs a shell and a
//! `base64` binary on the far side, and it is only available on POSIX hosts. This module is the
//! alternative that gets the file *directly*: an SFTP subsystem session over a dedicated SSH channel,
//! where the file is a stream of bytes and copying it is a handshake instead of spawning a program.
//!
//! ## Why roll our own instead of a crate
//!
//! The workspace keeps its dependency set deliberately small (see `ROADMAP.md`), and russh ships the two
//! primitives an SFTP client needs without shipping an SFTP implementation: [`request_subsystem`] to ask
//! the server to start its `sftp` server on a channel, and the channel's byte-oriented `Data` message
//! to carry the protocol. Both are in the pinned russh 0.63 (vendored at
//! `~/.cargo/registry/.../russh-0.63.3/src/channels/mod.rs`: `Channel::request_subsystem` at
//! line 550 and `ChannelMsg::Data { data: Bytes }` at line 27). russh's own `sftp_client`
//! example reaches for a *separate* `russh-sftp` crate that is not in this workspace's lock; laying
//! that in just to gain a client for a protocol this crate only needs four operations from is exactly the
//! dependency the roadmap warns against. SFTP v3 is a small, stable, documented wire protocol, so this
//! module implements the handful of packets it needs and refuses everything it does not.
//!
//! ## What this implements, and what it deliberately does not
//!
//! Implemented, and only because [`Host`] calls for them: version negotiation, open/close, read by
//! offset, write by offset, directory open/read, and rename. That is `read_file`, `write_file`,
//! `list_dir` and `rename` for `SshHost`.
//!
//! Not implemented, on purpose: `SSH_FXP_*` packets whose responses this caller would throw away
//! (symlinks, chmod, stat of a single file, setstat). Adding one means adding its request type and its
//! response matcher — the shape is identical to the operations below, so there is nothing new to learn when
//! one is needed. The one deliberate asymmetry is that the version handshake listens for a *version* reply,
//! not a status, because a version packet is what the server sends first.
//!
//! ## One channel per operation
//!
//! A subsystem session is cheap to open and the [`Host`] trait hands every call `&self`, while a russh
//! channel needs `&mut self` to read. Opening a fresh channel per file operation — exactly as
//! `exec_direct` opens a fresh channel per command — sidesteps the borrow without a lock, and means a
//! request and its reply can never interleave with a sibling's.
//!
//! ## Why this strictly checks, and what it reports
//!
//! Because this client is the thing that measures `has_sftp`, a server that *refuses* the subsystem
//! request is an honest `Some(false)`, not a hang or a confusing error. [`SftpSession::open`] fails
//! fast on a refusal so the caller can distinguish "no sftp server" from "the sftp server is broken" —
//! the difference between a measured `Some(false)` and a reportable error.
//!
//! [`Host`]: crate::host::Host
//! [`request_subsystem`]: russh::Channel::request_subsystem

use crate::host::RemoteEntry;
use hx_core::error::{HxError, Result};

/// The SFTP protocol version this client speaks and accepts.
const PROTO_VERSION: u32 = 3;

// SSH_FXP_* message types, as OpenSSH's sftp-server sends and receives them.
const INIT: u8 = 1;
const VERSION: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const OPENDIR: u8 = 11;
const READDIR: u8 = 12;
const RENAME: u8 = 18;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;
const NAME: u8 = 104;

// Open pflags (SSH_FXF_*).
const PFXF_READ: u32 = 0x0000_0001;
const PFXF_WRITE: u32 = 0x0000_0002;
const PFXF_CREAT: u32 = 0x0000_0008;
const PFXF_TRUNC: u32 = 0x0000_0010;

// ATTRS flags (SSH_FILEXFER_ATTR_*): which attribute fields follow the flags word.
const ATTR_SIZE: u32 = 0x0000_0001;
const ATTR_UIDGID: u32 = 0x0000_0002;
const ATTR_PERMISSIONS: u32 = 0x0000_0004;
const ATTR_ACMODTIME: u32 = 0x0000_0008;

/// The three answers a subsystem probe can give.
///
/// This is what lets [`HostCaps::has_sftp`] become a measurement instead of a guess: the probe opens the
/// `sftp` subsystem and completes the version handshake, or it does not. A server that refuses is
/// [`Unavailable`] — that is measured. A probe that never completes (transport error, channel closed before a
/// reply) is [`Unknown`], because the transport itself fell over and reporting a fact it never gathered would
/// be the old lie in a new coat.
///
/// [`HostCaps::has_sftp`]: crate::host::HostCaps::has_sftp
/// [`Unavailable`]: SftpAvailability::Unavailable
/// [`Unknown`]: SftpAvailability::Unknown
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SftpAvailability {
    /// The server opened an `sftp` subsystem and answered the version handshake.
    Available,
    /// The server refused the subsystem, or answered the handshake with a status.
    Unavailable,
    /// The probe could not be completed (transport error, channel closed), so nothing is known.
    Unknown,
}

impl SftpAvailability {
    /// Collapse to the `bool` a capability field wants.
    pub fn as_bool(self) -> Option<bool> {
        match self {
            SftpAvailability::Available => Some(true),
            SftpAvailability::Unavailable => Some(false),
            SftpAvailability::Unknown => None,
        }
    }
}

/// A byte cursor over the stream a russh channel delivers.
///
/// russh hands `ChannelMsg::Data` in chunks that know nothing about SFTP packet boundaries — a packet may be
/// split across several chunks, and one chunk may hold several. This buffers the stream and hands out one
/// complete, length-prefixed packet at a time.
#[derive(Default)]
struct ReadBuf {
    bytes: Vec<u8>,
}

impl ReadBuf {
    /// Append a freshly-arrived chunk.
    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
    }

    /// Take one complete SFTP packet (its 4-byte length header plus body), or `None` if the buffer
    /// does not hold a whole packet yet.
    fn take_packet(&mut self) -> Option<Vec<u8>> {
        if self.bytes.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]])
            as usize;
        if self.bytes.len() < 4 + len {
            return None;
        }
        let rest = self.bytes[4 + len..].to_vec();
        let packet = self.bytes[..4 + len].to_vec();
        self.bytes = rest;
        Some(packet)
    }
}

/// One open SFTP subsystem session on a dedicated SSH channel.
///
/// Owns the channel and its read buffer, so `&mut self` is held for the duration of a call and a fresh
/// session is opened per file operation (see the module note).
pub struct SftpSession {
    channel: russh::Channel<russh::client::Msg>,
    read: ReadBuf,
    next_id: u32,
}

/// A request packet being built for the wire: type, request id, then fields. `finish` adds the length
/// prefix, which is the framing SFTP shares with the SSH packet format.
#[derive(Default)]
struct Packet {
    body: Vec<u8>,
}

impl Packet {
    fn new(msg_type: u8, id: u32) -> Self {
        let mut body = Vec::with_capacity(32);
        body.push(msg_type);
        body.extend_from_slice(&id.to_be_bytes());
        Self { body }
    }

    /// A consuming builder: each field returns `Self` so the chain owns the packet all the way to
    /// `finish`, and no borrow of a temporary ever escapes.
    fn u32(mut self, v: u32) -> Self {
        self.body.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn u64(mut self, v: u64) -> Self {
        self.body.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn string(mut self, s: &[u8]) -> Self {
        self.body.extend_from_slice(&(s.len() as u32).to_be_bytes());
        self.body.extend_from_slice(s);
        self
    }

    /// An empty attribute set — the zero-length `attrs` field OPEN wants when no attributes are being set.
    fn empty_attrs(mut self) -> Self {
        self.body.extend_from_slice(&0u32.to_be_bytes());
        self
    }

    /// Complete the packet with its length prefix.
    fn finish(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 4);
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// One received SFTP packet, with field accessors for the replies this crate understands.
struct Reply {
    packet: Vec<u8>,
}

impl Reply {
    fn type_id(&self) -> Option<u8> {
        self.packet.get(4).copied()
    }

    fn request_id(&self) -> Option<u32> {
        if self.packet.len() >= 9 {
            Some(u32::from_be_bytes([
                self.packet[5],
                self.packet[6],
                self.packet[7],
                self.packet[8],
            ]))
        } else {
            None
        }
    }

    /// The first length-prefixed string field (after the 4-byte length header, type and request id).
    fn string(&self) -> &[u8] {
        string_at(&self.packet, 9).0
    }

    /// The first `u32`, used by STATUS as its error code.
    fn status_code(&self) -> u32 {
        if self.packet.len() >= 13 {
            u32::from_be_bytes([
                self.packet[9],
                self.packet[10],
                self.packet[11],
                self.packet[12],
            ])
        } else {
            0
        }
    }

    /// A STATUS's (code, message) pair.
    fn status(&self) -> (u32, String) {
        let msg = if self.packet.len() >= 17 {
            string_at(&self.packet, 13).0
        } else {
            &[]
        };
        (
            self.status_code(),
            String::from_utf8_lossy(msg).into_owned(),
        )
    }
}

/// Read a length-prefixed string at `pos`, returning its bytes and the position after it.
fn string_at(bytes: &[u8], pos: usize) -> (&[u8], usize) {
    if bytes.len() < pos + 4 {
        return (&[], bytes.len());
    }
    let len =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    let start = pos + 4;
    let end = (start + len).min(bytes.len());
    (&bytes[start..end], end)
}

/// What a handle is being opened for, so an error can say "for read" vs "for write".
#[derive(Clone, Copy)]
enum OpenedFor {
    Read,
    Write,
}

impl SftpSession {
    /// Open a subsystem on `channel` and complete the version handshake.
    ///
    /// `available` records the outcome of the *subsystem request* and the handshake, so `has_sftp` can
    /// be reported truthfully even when no usable session comes back.
    pub async fn open(
        channel: russh::Channel<russh::client::Msg>,
        available: &mut SftpAvailability,
    ) -> Result<Self> {
        let mut session = Self {
            channel,
            read: ReadBuf::default(),
            next_id: 1,
        };

        session
            .channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| {
                *available = SftpAvailability::Unavailable;
                HxError::Remote(format!("the host declined to start an sftp subsystem: {e}"))
            })?;

        // INIT declares our version; the server's first reply is a VERSION packet, not a status. A server
        // with no sftp server at all closes the channel right here, so both a STATUS and a channel-close
        // are the server *declining* — measured `Unavailable`, not an unknown.
        let init = Packet::new(INIT, 0).u32(PROTO_VERSION).finish();
        session
            .channel
            .data_bytes(init)
            .await
            .map_err(|e| HxError::Remote(format!("could not begin the sftp handshake: {e}")))?;

        let reply = match session.wait_packet().await {
            Ok(reply) => reply,
            // The channel closed before a VERSION: the server has no sftp subsystem. The transport
            // itself is fine — this is measured, so it is `Unavailable` (a `Some(false)`), not the
            // `Unknown` a genuine transport failure would earn.
            Err(e) => {
                *available = SftpAvailability::Unavailable;
                return Err(e);
            }
        };
        match reply.type_id() {
            Some(VERSION) => {
                *available = SftpAvailability::Available;
            }
            Some(STATUS) => {
                let (code, msg) = reply.status();
                *available = SftpAvailability::Unavailable;
                return Err(HxError::Remote(sftp_status_error(code, &msg)));
            }
            other => {
                *available = SftpAvailability::Unavailable;
                return Err(HxError::Remote(format!(
                    "the sftp server answered the handshake with an unexpected packet ({other:?})"
                )));
            }
        }

        Ok(session)
    }

    /// Read a whole remote file into memory.
    pub async fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let handle = self.open_handle(path, PFXF_READ, OpenedFor::Read).await?;

        let mut out = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let id = self.next_id();
            let req = Packet::new(READ, id).string(&handle).u64(offset).u32(32768);
            self.send(&req.finish()).await?;

            let reply = self.wait_reply(id).await?;
            match reply.type_id() {
                Some(DATA) => {
                    let data = reply.string();
                    out.extend_from_slice(data);
                    offset += data.len() as u64;
                }
                // A STATUS with EOF (code 1) is the normal way a read finishes past the end of the
                // file; any other status is a real error.
                Some(STATUS) if reply.status_code() == 1 => break,
                Some(STATUS) => {
                    let (code, msg) = reply.status();
                    return Err(HxError::Remote(sftp_status_error(code, &msg)));
                }
                other => return Err(unexpected_packet("read", other)),
            }
        }

        self.close_handle(&handle).await?;
        Ok(out)
    }

    /// Create (or truncate) a remote file and write `contents` into it.
    pub async fn write_file(&mut self, path: &str, contents: &[u8]) -> Result<()> {
        let handle = self
            .open_handle(path, PFXF_WRITE | PFXF_CREAT | PFXF_TRUNC, OpenedFor::Write)
            .await?;

        let mut offset: u64 = 0;
        for chunk in contents.chunks(32768) {
            let id = self.next_id();
            let req = Packet::new(WRITE, id)
                .string(&handle)
                .u64(offset)
                .string(chunk);
            self.send(&req.finish()).await?;

            let reply = self.wait_reply(id).await?;
            match reply.type_id() {
                Some(STATUS) if reply.status_code() == 0 => {}
                Some(STATUS) => {
                    let (code, msg) = reply.status();
                    return Err(HxError::Remote(sftp_status_error(code, &msg)));
                }
                other => return Err(unexpected_packet("write", other)),
            }
            offset += chunk.len() as u64;
        }

        self.close_handle(&handle).await?;
        Ok(())
    }

    /// List a directory's entries.
    pub async fn list_dir(&mut self, path: &str) -> Result<Vec<RemoteEntry>> {
        let id = self.next_id();
        let req = Packet::new(OPENDIR, id).string(path.as_bytes());
        self.send(&req.finish()).await?;

        let reply = self.wait_reply(id).await?;
        let handle = match reply.type_id() {
            Some(HANDLE) => reply.string().to_vec(),
            Some(STATUS) => {
                let (code, msg) = reply.status();
                return Err(HxError::Remote(sftp_status_error(code, &msg)));
            }
            other => return Err(unexpected_packet("opendir", other)),
        };

        let base = path.trim_end_matches('/');
        let mut out = Vec::new();
        loop {
            let id = self.next_id();
            let req = Packet::new(READDIR, id).string(&handle);
            self.send(&req.finish()).await?;

            let reply = self.wait_reply(id).await?;
            match reply.type_id() {
                // A batch of directory entries.
                Some(NAME) => out.extend(parse_name_packet(&reply.packet, base)),
                // A STATUS with EOF (code 1) ends the directory; any other status is a real error.
                Some(STATUS) if reply.status_code() == 1 => break,
                Some(STATUS) => {
                    let (code, msg) = reply.status();
                    return Err(HxError::Remote(sftp_status_error(code, &msg)));
                }
                other => return Err(unexpected_packet("readdir", other)),
            }
        }

        self.close_handle(&handle).await?;
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Move or rename a remote path.
    ///
    /// Unlike the shelled-out list, there is no explicit destination test here: the server performs the
    /// rename as one atomic operation and reports a failure status (code 4) when the target exists.
    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let id = self.next_id();
        let req = Packet::new(RENAME, id)
            .string(from.as_bytes())
            .string(to.as_bytes());
        self.send(&req.finish()).await?;

        let reply = self.wait_reply(id).await?;
        match reply.type_id() {
            Some(STATUS) if reply.status_code() == 0 => Ok(()),
            Some(STATUS) => {
                let (code, msg) = reply.status();
                Err(HxError::Remote(sftp_status_error(code, &msg)))
            }
            other => Err(unexpected_packet("rename", other)),
        }
    }

    async fn open_handle(&mut self, path: &str, flags: u32, for_op: OpenedFor) -> Result<Vec<u8>> {
        let id = self.next_id();
        let req = Packet::new(OPEN, id)
            .string(path.as_bytes())
            .u32(flags)
            .empty_attrs();
        self.send(&req.finish()).await?;

        let reply = self.wait_reply(id).await?;
        match reply.type_id() {
            Some(HANDLE) => Ok(reply.string().to_vec()),
            Some(STATUS) => {
                let (code, msg) = reply.status();
                let verb = match for_op {
                    OpenedFor::Read => "read",
                    OpenedFor::Write => "write",
                };
                Err(HxError::Remote(format!(
                    "could not open {path} for {verb}: {}",
                    sftp_status_error(code, &msg)
                )))
            }
            other => Err(unexpected_packet("open", other)),
        }
    }

    async fn close_handle(&mut self, handle: &[u8]) -> Result<()> {
        let id = self.next_id();
        let req = Packet::new(CLOSE, id).string(handle);
        self.send(&req.finish()).await?;

        let reply = self.wait_reply(id).await?;
        match reply.type_id() {
            Some(STATUS) if reply.status_code() == 0 => Ok(()),
            Some(STATUS) => {
                let (code, msg) = reply.status();
                Err(HxError::Remote(sftp_status_error(code, &msg)))
            }
            other => Err(unexpected_packet("close", other)),
        }
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    async fn send(&self, packet: &[u8]) -> Result<()> {
        self.channel
            .data_bytes(packet.to_vec())
            .await
            .map_err(|e| HxError::Remote(format!("could not write to the sftp channel: {e}")))
    }

    /// Read packets until the one carrying `id` arrives. Earlier packets for other request ids are kept in
    /// the buffer — this client sends one request at a time, so they should not occur, but dropping one
    /// would corrupt the stream if they ever did.
    async fn wait_reply(&mut self, id: u32) -> Result<Reply> {
        loop {
            let reply = self.wait_packet().await?;
            if reply.request_id() == Some(id) {
                return Ok(reply);
            }
            let bytes = reply.packet;
            self.read.push(&bytes);
        }
    }

    /// Read one complete packet from the stream, blocking on the channel until one is available.
    async fn wait_packet(&mut self) -> Result<Reply> {
        loop {
            if let Some(packet) = self.read.take_packet() {
                return Ok(Reply { packet });
            }
            // The channel's byte stream. `Data` is the only carrier that matters here; `Close`/`Eof`
            // mean the server gave up, which for a handshake is a refusal and for an operation is an
            // error.
            let msg = self.channel.wait().await.ok_or_else(|| {
                HxError::Remote("the sftp channel closed before the reply arrived".to_string())
            })?;
            match msg {
                russh::ChannelMsg::Data { data } => self.read.push(data.as_ref()),
                // Two control messages ride the same read half and carry no SFTP bytes: a server
                // `WindowAdjusted` as it refills its receive window, and the `Success` reply that
                // confirms the subsystem request itself (russh delivers it here even though the
                // `request_subsystem` future also sees it). Both are expected and must be skipped.
                // Anything else — `Eof`, `Close`, a request — means the subsystem conversation is
                // over, and is reported as such.
                russh::ChannelMsg::WindowAdjusted { .. } => continue,
                russh::ChannelMsg::Success => continue,
                _ => {
                    return Err(HxError::Remote(
                        "the sftp channel ended unexpectedly".to_string(),
                    ))
                }
            }
        }
    }
}

/// Parse a NAME packet (a batch of directory entries) into `RemoteEntry` values.
///
/// Each entry is `(string filename, string longname, ATTRS)`. The longname is the server's ls-style
/// rendering and is skipped — it is derivable, not portable, and this caller wants the machine-readable name
/// and attributes. Of the attributes, only `size` and the directory type bit are used.
fn parse_name_packet(packet: &[u8], base: &str) -> Vec<RemoteEntry> {
    let base = base.trim_end_matches('/');
    let mut pos = 9; // length(4) + type(1) + id(4)
    if packet.len() < pos + 4 {
        return Vec::new();
    }
    let count = u32::from_be_bytes([
        packet[pos],
        packet[pos + 1],
        packet[pos + 2],
        packet[pos + 3],
    ]) as usize;
    pos += 4;

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // filename
        let (name, next) = string_at(packet, pos);
        let name = String::from_utf8_lossy(name).into_owned();
        pos = next;
        // longname — skipped, see the doc.
        let (_, next) = string_at(packet, pos);
        pos = next;

        // ATTRS: flags u32, then per set flag one field: size (u64), uidgid (2×u32), perms
        // (u32 — the type bits live here), acmodtime (2×u32).
        let mut is_dir = false;
        let mut size = 0u64;
        if packet.len() >= pos + 4 {
            let flags = u32::from_be_bytes([
                packet[pos],
                packet[pos + 1],
                packet[pos + 2],
                packet[pos + 3],
            ]);
            pos += 4;
            if flags & ATTR_SIZE != 0 && packet.len() >= pos + 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&packet[pos..pos + 8]);
                size = u64::from_be_bytes(b);
                pos += 8;
            }
            if flags & ATTR_UIDGID != 0 {
                pos = (pos + 8).min(packet.len());
            }
            if flags & ATTR_PERMISSIONS != 0 && packet.len() >= pos + 4 {
                let perms = u32::from_be_bytes([
                    packet[pos],
                    packet[pos + 1],
                    packet[pos + 2],
                    packet[pos + 3],
                ]);
                // S_IFDIR is 0o040000 (bit 13 of the mode).
                is_dir = perms & 0o040000 != 0;
                pos += 4;
            }
            if flags & ATTR_ACMODTIME != 0 {
                pos = (pos + 8).min(packet.len());
            }
        }

        let path = if base.is_empty() {
            format!("/{name}")
        } else {
            format!("{base}/{name}")
        };
        out.push(RemoteEntry {
            name,
            path,
            is_dir,
            size,
        });
    }
    out
}

/// Turn an SFTP STATUS code and message into the crate's error wording.
fn sftp_status_error(code: u32, msg: &str) -> String {
    // The codes are the SSH_FX_* ones: 0 ok, 1 EOF, 2 no such file, 3 permission denied,
    // 4 failure, 5 bad message, 6 no connection, 7 connection lost, 8 op unsupported.
    let kind = match code {
        2 => "no such file or directory",
        3 => "permission denied",
        4 => "operation failed",
        8 => "operation not supported by the server",
        _ => "sftp error",
    };
    let mut out = format!("{kind} (code {code})");
    if !msg.is_empty() {
        out.push_str(&format!(": {msg}"));
    }
    out
}

fn unexpected_packet(op: &str, type_id: Option<u8>) -> HxError {
    HxError::Remote(format!(
        "the sftp server sent an unexpected packet ({type_id:?}) while processing {op}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: usize = 4; // the packet's length header

    #[test]
    fn read_buf_assembles_a_packet_split_across_chunks() {
        // russh delivers channel bytes in chunks that know nothing about SFTP packet boundaries. The buffer
        // must reassemble a packet split across chunks.
        let packet = Packet::new(DATA, 7).string(b"hello").finish();
        assert_eq!(packet.len(), H + 1 + 4 + 4 + 5);

        let mut buf = ReadBuf::default();
        buf.push(&packet[..3]); // partial length field
        assert!(
            buf.take_packet().is_none(),
            "no packet before a full length"
        );
        buf.push(&packet[3..8]); // rest of length + type + part of the id
        assert!(
            buf.take_packet().is_none(),
            "no packet before the full body"
        );
        buf.push(&packet[8..]);
        let got = buf.take_packet().expect("the packet now completes");
        assert_eq!(got, packet);
        assert!(buf.take_packet().is_none(), "nothing left");
    }

    #[test]
    fn read_buf_keeps_a_trailing_partial_packet_for_the_next_read() {
        let a = Packet::new(DATA, 1).string(b"aa").finish();
        let mut buf = ReadBuf::default();
        buf.push(&a);
        buf.push(&a[..4]); // a second packet's length header only
        assert_eq!(buf.take_packet().expect("first packet"), a);
        // The buffered half must be kept for the next read rather than discarded.
        assert!(buf.take_packet().is_none());
    }

    #[test]
    fn a_packet_frames_its_length_and_type() {
        // The 4-byte length prefix is the framing that lets the receiver know where one packet ends and the
        // next begins; getting it wrong would desynchronise the whole conversation.
        let packet = Packet::new(OPEN, 3).string(b"/tmp/x").finish();
        let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
        assert_eq!(
            len,
            packet.len() - H,
            "the length covers everything after itself"
        );
        assert_eq!(packet[4], OPEN);
    }

    #[test]
    fn reply_fields_parse_a_status() {
        let packet = Packet::new(STATUS, 9)
            .u32(2)
            .string(b"no such file")
            .finish();
        let reply = Reply { packet };
        assert_eq!(reply.type_id(), Some(STATUS));
        assert_eq!(reply.request_id(), Some(9));
        assert_eq!(reply.status_code(), 2);
        let (code, msg) = reply.status();
        assert_eq!(code, 2);
        assert_eq!(msg, "no such file");
    }

    #[test]
    fn status_errors_name_the_code() {
        assert!(sftp_status_error(2, "x").contains("no such file"));
        assert!(sftp_status_error(4, "").contains("operation failed"));
        assert!(sftp_status_error(8, "").contains("not supported"));
    }

    #[test]
    fn availability_collapses_the_way_a_capability_field_wants() {
        assert_eq!(SftpAvailability::Available.as_bool(), Some(true));
        assert_eq!(SftpAvailability::Unavailable.as_bool(), Some(false));
        assert_eq!(SftpAvailability::Unknown.as_bool(), None);
    }

    #[test]
    fn a_name_packet_parses_entries_with_their_size_and_kind() {
        // A real NAME packet: two entries — one regular file with size and perms present, one directory.
        let mut body = vec![NAME];
        body.extend_from_slice(&9u32.to_be_bytes()); // request id
        body.extend_from_slice(&2u32.to_be_bytes()); // count

        // entry 1: file "a.txt", longname is the server's ls line, ATTRS {size=1024, S_IFREG|0644}
        let file_long = b"-rw-r--r-- 1 u g 1024 Jan 1 a.txt";
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(b"a.txt");
        body.extend_from_slice(&(file_long.len() as u32).to_be_bytes());
        body.extend_from_slice(file_long);
        body.extend_from_slice(&(ATTR_SIZE | ATTR_PERMISSIONS).to_be_bytes());
        body.extend_from_slice(&1024u64.to_be_bytes());
        body.extend_from_slice(&0o100644u32.to_be_bytes());

        // entry 2: dir "sub", longname the ls line, ATTRS {S_IFDIR|0755}
        let dir_long = b"drwxr-xr-x 2 u g 0 Jan 1 sub";
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(b"sub");
        body.extend_from_slice(&(dir_long.len() as u32).to_be_bytes());
        body.extend_from_slice(dir_long);
        body.extend_from_slice(&ATTR_PERMISSIONS.to_be_bytes());
        body.extend_from_slice(&0o040755u32.to_be_bytes());

        let mut packet = Vec::new();
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

        let entries = parse_name_packet(&packet, "/tmp");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(
            entries[0].size, 1024,
            "the size comes from the attributes, not a guess"
        );
        assert!(!entries[0].is_dir);
        assert_eq!(entries[0].path, "/tmp/a.txt");
        assert!(entries[1].is_dir, "the directory type bit decides is_dir");
        assert_eq!(entries[1].name, "sub");
    }
}
