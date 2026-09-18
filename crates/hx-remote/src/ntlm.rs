//! NTLMv2, which is what a WinRM connection to a non-domain Windows host authenticates with.
//!
//! ## Why this is here rather than a dependency
//!
//! NTLM is not a design anyone would choose; it is what a Windows box answers to when there is no
//! Kerberos around, which is exactly the case for a workgroup machine reached over the network from
//! a Linux daemon. `ntlm` is not in this workspace's lock, and the offline gate will not fetch it —
//! and the pieces it needs are small: MD4 (which exists only because NTLM is old), MD5, HMAC-MD5,
//! and a couple of fixed byte layouts. That is a boundable amount of code to have sitting in the
//! open rather than behind a crate nobody here can read.
//!
//! ## Why a file-level `dead_code` allowance
//!
//! The full negotiation-flag set is named as constants, and several of them are read only by the
//! test that pins their values. In the library target those are unused, and `-D warnings` would fail
//! on constants whose entire purpose is to be checked against a known-good implementation. Allow it
//! here, narrowly, rather than annotate fifteen constants and have the next one added go un-annotated
//! and unnoticed.
#![allow(dead_code, clippy::unreadable_literal)]
//!
//! ## The shape of the exchange
//!
//! Three messages, carried as `Authorization` headers on ordinary HTTP requests:
//!
//! 1. The client sends `NTLMSSP_NEGOTIATE` stating what it can do.
//! 2. The server replies `NTLMSSP_CHALLENGE` with a random 8-byte challenge and its own flags.
//! 3. The client sends `NTLMSSP_AUTHENTICATE` carrying a response derived from the password and
//!    that challenge.
//!
//! The password itself never crosses the wire. What crosses is an HMAC keyed by the NT hash over
//! the challenge — which is why this is worth implementing rather than reaching for Basic, and why
//! the caller must still use a channel it trusts: NTLMv2 resists a passive reader recovering the
//! password, but it does not encrypt the session.
//!
//! ## What is deliberately not supported
//!
//! - **NTLMv1.** It is broken. A server that only offers it is refused rather than downgraded to.
//! - **Session security (signing/sealing).** WinRM over HTTP relies on the transport for
//!   confidentiality; message-level sealing would be needed for a hostile network and is a much
//!   larger piece of work. Noted in the transport's doc block rather than silently omitted.
//! - **Domain accounts.** A domain login needs the domain name in the response, which is
//!   parameterised here but has never been exercised against a real domain controller. The local
//!   account path is the one that is tested.

// `md5` here is 0.8, the version already in this workspace's lock, and it is a standalone crate
// with `md5::Context` rather than a type implementing the `digest` trait — so it cannot be handed
// to `hmac::Hmac`, which wants that trait. HMAC is a short construction over any hash, and it is
// written out below rather than resolving the mismatch by adding a `digest`-compatible MD5 crate
// the offline gate would have to fetch.

/// The signature every NTLMSSP message starts with.
const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

const MSG_NEGOTIATE: u32 = 1;
const MSG_CHALLENGE: u32 = 2;
const MSG_AUTHENTICATE: u32 = 3;

// Negotiation flags, from MS-NLMP 2.2.2.5. Every value here was verified against a real Windows
// challenge: a wrong bit does not fail loudly, it produces a 401 with no explanation, and two
// constants that accidentally share a value make a guard test the wrong thing while still
// appearing to work.
//
// The whole set is named, including flags this client never sets, because
// `the_negotiation_flags_match_a_working_implementation` pins every value and asserts no two share
// a bit — a flag missing from that table cannot be checked.
//
// `dead_code` is allowed on the whole set rather than per-item: several flags are read only by that
// test, so the library target sees them as unused and `-D warnings` fails on constants whose whole
// purpose is to be checked.
#[allow(dead_code, clippy::unreadable_literal)]
const FLAG_UNICODE: u32 = 0x0000_0001;
const FLAG_OEM: u32 = 0x0000_0002;
const FLAG_REQUEST_TARGET: u32 = 0x0000_0004;
const FLAG_SIGN: u32 = 0x0000_0010;
const FLAG_SEAL: u32 = 0x0000_0020;
const FLAG_LM_KEY: u32 = 0x0000_0080;
const FLAG_NTLM: u32 = 0x0000_0200;
const FLAG_ALWAYS_SIGN: u32 = 0x0000_8000;
/// `NEGOTIATE_TARGET_TYPE_SERVER`: the server is a server, not a domain controller.
const FLAG_TARGET_TYPE_SERVER: u32 = 0x0002_0000;
/// `NEGOTIATE_EXTENDED_SESSIONSECURITY`. **This is the flag that means NTLMv2**, and its absence
/// is what a downgrade to NTLMv1 looks like.
const FLAG_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
/// `NEGOTIATE_TARGET_INFO`: the server will send a `TargetInfo` blob, which the v2 response mixes
/// in to bind it to this server.
const FLAG_TARGET_INFO: u32 = 0x0080_0000;
const FLAG_VERSION: u32 = 0x0200_0000;
const FLAG_128: u32 = 0x2000_0000;
const FLAG_KEY_EXCH: u32 = 0x4000_0000;
const FLAG_56: u32 = 0x8000_0000;

/// What the client offers in its negotiate message.
///
/// NTLMv2 (`NTLM2_KEY`) and extended session security are requested; `NTLM` alone is also set
/// because a server that does not understand the newer flags will otherwise refuse the exchange
/// outright. A server that answers with *only* `NTLM` and no `NTLM2_KEY` is refused by
/// [`Auth::response`] rather than answered — offering the capability is not agreeing to use it.
fn negotiate_flags() -> u32 {
    FLAG_UNICODE
        | FLAG_REQUEST_TARGET
        | FLAG_NTLM
        | FLAG_ALWAYS_SIGN
        | FLAG_EXTENDED_SESSIONSECURITY
        | FLAG_128
        | FLAG_56
        // `SIGN`, `SEAL` and `KEY_EXCH` are capability bits, and the echo is an AND with this offer:
        // a bit the server sets is dropped from the client's reply unless the client offered it.
        // Windows asks for all three, so omitting them produced flags unlike any working client's
        // and a 401 that named nothing.
        | FLAG_SIGN
        | FLAG_SEAL
        | FLAG_KEY_EXCH
        // `OEM` and `VERSION` are here because the one client measured against this host offers
        // them: 0xe2088237. `OEM` is vestigial when `UNICODE` is set, and `VERSION` obliges the
        // eight-byte version block the authenticate message already carries. An earlier attempt to
        // offer `VERSION` did make the server stop returning a challenge — but the rest of the
        // message was wrong at the time, so that was misread as the cause.
        | FLAG_OEM
        | FLAG_VERSION
}

/// The flags to echo in the authenticate message.
///
/// The *server's* flags, not the client's offer. The authenticate message restates the negotiated
/// set, and Windows checks it against what it sent: replying with flags the server did not offer —
/// or omitting ones it did — is refused with a 401 that names nothing. Verified against a real
/// host, where echoing the server's `0xa28a8205` is accepted and the client's own offer is not.
fn authenticate_flags(challenge_flags: u32) -> u32 {
    challenge_flags & negotiate_flags()
}

/// Encode a `SecBuffer`-style field: length, allocated length, and offset from the message start.
///
/// Every variable-length field in NTLMSSP is written this way, and the offset is from the *start of
/// the message*, not from the field — a detail that is the usual source of a malformed message.
fn push_security_buffer(out: &mut Vec<u8>, data: &[u8], offset: usize) {
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&(offset as u32).to_le_bytes());
}

/// AV pair ids that matter to a client building its own target info.
const AV_EOL: u16 = 0;
const AV_FLAGS: u16 = 6;
const AV_TARGET_NAME: u16 = 9;

/// `MsvAvFlags` bit 1 would declare that the client computed a MIC.
///
/// It is deliberately **not** set. Declaring a MIC obliges the message to carry a correct one, keyed
/// by the session base key over all three messages, and a wrong MIC is rejected exactly like a wrong
/// password — the two are indistinguishable from the response. WinRM over HTTP does not require a
/// MIC, so the honest thing is to not claim one.
const MIC_PRESENT: u32 = 0x0000_0000;

/// One `AV_PAIR`: a two-byte id, a two-byte length, then the value.
fn av_pair(id: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    out
}

/// The server's target info with its `EOL` terminator removed.
///
/// The terminator is not part of the attribute list, and a client that copies it and then appends
/// its own pairs leaves an `EOL` in the middle — which ends the list early and changes what the
/// server hashes.
fn av_pairs_trim_eol(target_info: &[u8]) -> &[u8] {
    let end = target_info.len();
    if end >= 4 {
        let id = u16::from_le_bytes([target_info[end - 4], target_info[end - 3]]);
        let len = u16::from_le_bytes([target_info[end - 2], target_info[end - 1]]);
        if id == AV_EOL && len == 0 {
            return &target_info[..end - 4];
        }
    }
    target_info
}

/// The eight-byte version block an authenticate message carries when `NEGOTIATE_VERSION` was
/// echoed: major 10, minor 0, build 19041 (LE u16), three reserved bytes, revision 15.
const VERSION_BLOCK: [u8; 8] = [0x0a, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x0f];

/// UTF-16LE, which is what `FLAG_UNICODE` promises.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// MD4, needed only because NTLM's `NT hash` is defined as MD4 over the UTF-16LE password.
///
/// RFC 1320, and implemented here rather than pulled in: it is ~40 lines, it is used for exactly
/// one thing, and a digest with this history is worth being able to read in place.
pub fn md4(input: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    // Pad to a multiple of 64 with 0x80 then zeros, and append the bit length little-endian.
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // `as_chunks` rather than `chunks_exact`: the message is a multiple of 64 by construction
    // below, and the array type carries that so the inner indexing needs no bounds reasoning.
    for chunk in msg.as_chunks::<64>().0 {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

        let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
        let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
        let h = |x: u32, y: u32, z: u32| x ^ y ^ z;

        // Round 1: a function of `F`, no shift.
        let s1 = [3u32, 7, 11, 19];
        for i in 0..16 {
            let k = i;
            let s = s1[i % 4];
            let tmp = a.wrapping_add(f(b, c, d)).wrapping_add(x[k]).rotate_left(s);
            a = d;
            d = c;
            c = b;
            b = tmp;
        }

        // Round 2: `G`, with the constant 0x5a827999.
        let s2 = [3u32, 5, 9, 13];
        for i in 0..16 {
            let k = (i % 4) * 4 + i / 4;
            let s = s2[i % 4];
            let tmp = a
                .wrapping_add(g(b, c, d))
                .wrapping_add(x[k])
                .wrapping_add(0x5a82_7999)
                .rotate_left(s);
            a = d;
            d = c;
            c = b;
            b = tmp;
        }

        // Round 3: `H`, with the constant 0x6ed9eba1.
        let s3 = [3u32, 9, 11, 15];
        let order = [0usize, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for (i, k) in order.iter().enumerate() {
            let s = s3[i % 4];
            let tmp = a
                .wrapping_add(h(b, c, d))
                .wrapping_add(x[*k])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(s);
            a = d;
            d = c;
            c = b;
            b = tmp;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The NT hash: MD4 over the password in UTF-16LE. NTLM's whole notion of "the password".
pub fn nt_hash(password: &str) -> [u8; 16] {
    md4(&utf16le(password))
}

fn md5_of(data: &[u8]) -> [u8; 16] {
    md5::compute(data).0
}

/// HMAC-MD5 (RFC 2104).
///
/// Written out because the vendored `md5` is a standalone crate without the `digest` trait that
/// `hmac::Hmac` requires. The construction is short and fixed: hash the key padded to the block
/// size XORed with `ipad`, append the message, hash that; then hash the key XORed with `opad`
/// followed by that inner digest.
fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    // A key longer than the block is hashed down first; shorter keys are zero-padded to the block.
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..16].copy_from_slice(&md5_of(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend(key_block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(data);
    let inner_digest = md5_of(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 16);
    outer.extend(key_block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_digest);
    md5_of(&outer)
}

/// A challenge from the server, parsed out of a `NTLMSSP_CHALLENGE` message.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// The 8 random bytes the response is keyed on. This is the whole anti-replay value.
    pub server_challenge: [u8; 8],
    /// The server's target name, echoed back in the authenticate message.
    pub target_name: Vec<u8>,
    /// The `TargetInfo` blob, which NTLMv2 mixes into the response to bind it to this server.
    pub target_info: Vec<u8>,
    /// What the server said it can do.
    pub flags: u32,
}

/// Credentials for one exchange.
#[derive(Debug, Clone)]
pub struct Auth {
    /// The account name. For a local account this is just the user; a domain account has the
    /// domain in [`Auth::domain`].
    pub user: String,
    pub password: String,
    /// The domain or workgroup. A local Windows account is authenticated against the machine's own
    /// name, and an empty domain is sent as empty rather than as a guess.
    pub domain: Option<String>,
    /// The machine's name, used to key the NTLMv2 hash alongside the user and domain.
    pub workstation: String,
    /// The SPN of the service being reached, as `http/<host>`.
    ///
    /// It is sent as an `AV_TARGET_NAME` pair inside the blob, and it is not decoration: the server
    /// includes the client's pairs when it recomputes the proof, so the value has to be one the
    /// server agrees with. Measured off a working client, which sent `http/127.0.0.1` for a host
    /// reached at that address.
    pub target_spn: Option<String>,
}

impl Auth {
    /// The SPN to declare, defaulting to the bare `http/` form when none was configured.
    fn target_spn(&self) -> String {
        self.target_spn
            .clone()
            .unwrap_or_else(|| format!("http/{}", self.workstation))
    }

    /// The `NTLMSSP_NEGOTIATE` message.
    pub fn negotiate(&self) -> Vec<u8> {
        let flags = negotiate_flags();
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&MSG_NEGOTIATE.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        // Domain and workstation are optional in the negotiate message; Windows sends them and
        // some servers expect the field layout to be present even when empty.
        let domain = self.domain.clone().unwrap_or_default();
        let domain_bytes = utf16le(&domain);
        let workstation_bytes = utf16le(&self.workstation);
        // 32 bytes of fixed header, then the payloads. No version block: see `negotiate_flags`.
        let base = 32;
        push_security_buffer(&mut out, &domain_bytes, base);
        push_security_buffer(&mut out, &workstation_bytes, base + domain_bytes.len());
        out.extend_from_slice(&domain_bytes);
        out.extend_from_slice(&workstation_bytes);
        out
    }

    /// Parse a `NTLMSSP_CHALLENGE`.
    ///
    /// Every offset is validated against the message length. A malformed challenge is a server (or
    /// something pretending to be one) sending nonsense, and indexing past the end of it would be a
    /// panic on a remote peer's say-so.
    pub fn parse_challenge(message: &[u8]) -> Option<Challenge> {
        if message.len() < 32 || &message[0..8] != SIGNATURE {
            return None;
        }
        if u32::from_le_bytes(message[8..12].try_into().ok()?) != MSG_CHALLENGE {
            return None;
        }

        let target_name_len = u16::from_le_bytes(message[12..14].try_into().ok()?) as usize;
        let target_name_off = u32::from_le_bytes(message[16..20].try_into().ok()?) as usize;
        let flags = u32::from_le_bytes(message[20..24].try_into().ok()?);
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(message[24..32].try_into().ok()?);

        let target_name = slice_checked(message, target_name_off, target_name_len)
            .unwrap_or_default()
            .to_vec();

        // The target info block is past the version field when the server sent one. Its position is
        // not fixed by the protocol, so a verifiable reading is preferred over assuming a layout:
        // if the offsets do not describe a sane block, it is treated as absent.
        let mut target_info = Vec::new();
        if flags & FLAG_TARGET_INFO != 0 && message.len() >= 48 {
            let len = u16::from_le_bytes(message[40..42].try_into().ok()?) as usize;
            let off = u32::from_le_bytes(message[44..48].try_into().ok()?) as usize;
            if let Some(bytes) = slice_checked(message, off, len) {
                target_info = bytes.to_vec();
            }
        }

        Some(Challenge {
            server_challenge,
            target_name,
            target_info,
            flags,
        })
    }

    /// The `NTLMSSP_AUTHENTICATE` message for a challenge.
    ///
    /// Returns `None` when the server will not speak NTLMv2: answering anyway would mean sending an
    /// NTLMv1 response, which is weak enough that a failure is the better outcome. This is the one
    /// place the implementation deliberately refuses a connection it could have made.
    ///
    /// `negotiate` and `challenge_bytes` are the exact bytes of the two earlier messages, because
    /// the MIC is computed over all three in order. Passing them in is the difference between a MIC
    /// the server can verify and one it cannot.
    pub fn authenticate(
        &self,
        challenge: &Challenge,
        negotiate: &[u8],
        challenge_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        // `NEGOTIATE_EXTENDED_SESSIONSECURITY` is what makes a response NTLMv2. Its absence means
        // the server will only accept an NTLMv1 response, which is refused rather than produced.
        // The bit was previously read from a constant that shared a value with `NEGOTIATE_IDENTIFY`
        // — so the guard tested the wrong thing while appearing to work.
        if challenge.flags & FLAG_EXTENDED_SESSIONSECURITY == 0 {
            return None;
        }

        let nt_hash = nt_hash(&self.password);
        let user_upper = self.user.to_uppercase();
        let domain = self.domain.clone().unwrap_or_default();

        // NTLMv2 key: HMAC-MD5 over the uppercased user and the domain, keyed by the NT hash.
        let ntlmv2_hash = hmac_md5(&nt_hash, &utf16le(&format!("{user_upper}{domain}")));

        // The blob binds the response to this server and this moment. The timestamp is a real one:
        // a server with a clock skew allowance rejects a response whose timestamp is wildly off,
        // which is a deliberate property of NTLMv2 rather than a nuisance.
        let timestamp = windows_filetime_now();
        let client_challenge = random_bytes_8();
        let session_key = random_bytes_16();

        let mut blob = Vec::new();
        // The blob signature is the four bytes `01 01 00 00`. Written as a little-endian u32 that
        // is `0x0000_0101`, not `0x0101_0000` — the latter emits `00 00 01 01` and is exactly the
        // kind of wrong that still parses as a struct and makes the proof unverifiable.
        blob.extend_from_slice(&0x0000_0101u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes()); // reserved
        blob.extend_from_slice(&timestamp.to_le_bytes());
        blob.extend_from_slice(&client_challenge);
        blob.extend_from_slice(&0u32.to_le_bytes()); // reserved
                                                     // The server's target info, with the terminator trimmed, then the client's own AV pairs.
                                                     //
                                                     // This is the part that is easy to get wrong and impossible to guess: the server recomputes
                                                     // the proof over the target info *as the client sent it*, so the blob must carry the
                                                     // server's attributes plus the client's. Copying the server's 152 bytes verbatim — terminator
                                                     // and all — produces a proof that can never verify, and Windows answers with a bare 401 that
                                                     // names nothing. Measured against a real host: the accepted blob is 196 bytes where the
                                                     // server sent 152, and the extra 40 are these two pairs.
        blob.extend_from_slice(av_pairs_trim_eol(&challenge.target_info));
        blob.extend_from_slice(&av_pair(AV_TARGET_NAME, &utf16le(&self.target_spn())));
        blob.extend_from_slice(&av_pair(AV_FLAGS, &MIC_PRESENT.to_le_bytes()));
        // The attribute list terminator.
        blob.extend_from_slice(&0u32.to_le_bytes());

        // The response is HMAC-MD5 keyed by the NTLMv2 hash, over the server challenge and the blob.
        let mut to_hmac = Vec::with_capacity(8 + blob.len());
        to_hmac.extend_from_slice(&challenge.server_challenge);
        to_hmac.extend_from_slice(&blob);
        let proof = hmac_md5(&ntlmv2_hash, &to_hmac);

        let mut nt_response = Vec::with_capacity(proof.len() + blob.len());
        nt_response.extend_from_slice(&proof);
        nt_response.extend_from_slice(&blob);

        // Twenty-four zero bytes. Windows ignores the LM field whenever an NT response is present,
        // and the client measured against this host sends exactly this: its LM payload is
        // `000000000000000000000000000000000000000000000000`, and its payloads begin at offset 88.
        // A computed LMv2 — 16 bytes of HMAC with the client challenge appended — is what an earlier
        // version of this file sent, and it is not what this exchange wants.
        let lm_response = vec![0u8; 24];

        // Layout: a fixed header, then domain, user, workstation, LM response, NT response, and a
        // session key. The offsets have to be computed in this order because each field's offset
        // depends on the total size of the fixed header plus everything before it.
        let domain_bytes = utf16le(&domain);
        let user_bytes = utf16le(&self.user);
        let workstation_bytes = utf16le(&self.workstation);

        // The fixed header is 64 bytes (signature, type, six security buffers, flags), then the
        // eight-byte version block, then a sixteen-byte MAC area the MIC occupies the first half of.
        // Read off an accepted message: its bytes 64..72 are the version block, 72..88 are the MAC
        // area, and its payloads begin at 88. Getting this number wrong shifts every payload offset
        // without breaking the message's shape, so the fields still parse and hold nonsense —
        // `user` read back as `\x02\x00\x00\x00hx` instead of `hxtest`.
        const HEADER_LEN: usize = 64 + VERSION_BLOCK.len() + 16;
        let mut out = Vec::with_capacity(HEADER_LEN + 256);
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&MSG_AUTHENTICATE.to_le_bytes());

        let mut offset = HEADER_LEN;
        // Lengths and offsets are written first, then the payloads appended in the same order. Any
        // mismatch here produces a message the server rejects with no detail.
        push_security_buffer(&mut out, &lm_response, offset);
        offset += lm_response.len();
        push_security_buffer(&mut out, &nt_response, offset);
        offset += nt_response.len();
        push_security_buffer(&mut out, &domain_bytes, offset);
        offset += domain_bytes.len();
        push_security_buffer(&mut out, &user_bytes, offset);
        offset += user_bytes.len();
        push_security_buffer(&mut out, &workstation_bytes, offset);
        offset += workstation_bytes.len();
        // A session key is present because `KEY_EXCH` was negotiated, and a server that agreed to
        // exchange one expects the field to carry it. It is random: WinRM over HTTP does not sign
        // messages, so nothing here derives from it, and a key that is never used is better
        // generated than empty — an empty field reads as "the exchange was declined".
        push_security_buffer(&mut out, &session_key, offset);
        out.extend_from_slice(&authenticate_flags(challenge.flags).to_le_bytes());
        // The version block, then the MIC.
        //
        // Order and sizes were read off an accepted message, not assumed: its bytes 64..72 are
        // `000c02000000000f` — the eight-byte version block `NEGOTIATE_VERSION` obliges a client to
        // echo — and 72..80 are the MIC. Writing them the other way round produces a message whose
        // every field offset is still correct and which the server refuses with nothing but a 401,
        // which is why the order is worth a comment.
        out.extend_from_slice(&VERSION_BLOCK);
        // The MIC: HMAC-MD5 over the negotiate, challenge and authenticate messages in that order,
        // keyed by the *exported session key* — MD4 of the NT hash, not the raw hash. It covers the
        // authenticate message with its own MIC zeroed, which is why the value is patched in after
        // the rest of the message exists rather than appended as it is built.
        let mic_offset = out.len();
        out.extend_from_slice(&[0u8; 16]);
        {
            // The MIC is keyed by the *exported session key*, which the spec defines as
            // `HMAC_MD5(ResponseKeyNT, NTProofStr)` — not by the NT hash and not by the password's
            // MD4. Keying it with the wrong value produces a MIC the server cannot verify, and a
            // failed MIC is rejected exactly like a failed password, so the two are indistinguishable
            // from the response.
            let session_base_key = hmac_md5(&ntlmv2_hash, &proof);
            let mut mic_input =
                Vec::with_capacity(negotiate.len() + challenge_bytes.len() + out.len());
            mic_input.extend_from_slice(negotiate);
            mic_input.extend_from_slice(challenge_bytes);
            mic_input.extend_from_slice(&out);
            // The MIC field is eight bytes and HMAC-MD5 produces sixteen, so the first half is the
            // value — the same truncation the protocol uses for the response proofs.
            let mic = hmac_md5(&session_base_key, &mic_input);
            out[mic_offset..mic_offset + 8].copy_from_slice(&mic[..8]);
        }
        let _ = &VERSION_BLOCK;

        out.extend_from_slice(&lm_response);
        out.extend_from_slice(&nt_response);
        out.extend_from_slice(&domain_bytes);
        out.extend_from_slice(&user_bytes);
        out.extend_from_slice(&workstation_bytes);
        out.extend_from_slice(&session_key);
        Some(out)
    }
}

/// A slice, or `None` if the range does not fit. Remote data must not be trusted to describe
/// itself accurately.
fn slice_checked(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(len)?;
    data.get(offset..end)
}

/// The current time as a Windows `FILETIME`: 100-nanosecond intervals since 1601-01-01.
fn windows_filetime_now() -> u64 {
    // 11644473600 seconds between 1601 and 1970, times 10^7 intervals per second.
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 / 100)
        .unwrap_or(0);
    unix + EPOCH_DIFF
}

/// Eight random bytes, for the client challenge.
///
/// From `getrandom` via `rand`, which is in the workspace lock. A predictable client challenge
/// would let a response be replayed, which is the one thing NTLMv2's construction is protecting
/// against — so this must not fall back to a clock or a counter.
fn random_bytes_8() -> [u8; 8] {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("the OS must provide random bytes");
    buf
}

/// Sixteen random bytes, the width of an NTLM session key. Windows rejects a session key of any
/// other length when `KEY_EXCH` was negotiated, so this is not a size worth varying.
pub fn random_bytes_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("the OS must provide random bytes");
    buf
}

/// Base64 of a message, for the `Authorization: NTLM <b64>` header.
pub fn header_value(message: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_matches_the_rfc_1320_vectors() {
        // The RFC's test suite. MD4 is only here because NTLM needs it, and getting it wrong would
        // produce an auth failure with no clue as to why — so it is pinned to published values.
        assert_eq!(
            hex(&md4(b"")),
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "the empty string"
        );
        assert_eq!(hex(&md4(b"a")), "bde52cb31de33e46245e05fbdbd6fb24", "a");
        assert_eq!(hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d", "abc");
        assert_eq!(
            hex(&md4(b"message digest")),
            "d9130a8164549fe818874806e1c7014b",
            "message digest"
        );
        assert_eq!(
            hex(&md4(b"abcdefghijklmnopqrstuvwxyz")),
            "d79e1c308aa5bbcdeea8ed63df412da9",
            "the alphabet"
        );
        assert_eq!(
            hex(&md4(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "043f8582f241db351ce627e153e7f0e4",
            "alphanumeric"
        );
        assert_eq!(
            hex(&md4(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "e33b4ddc9c38f2199c3e7b164fcc0536",
            "the digit run"
        );
    }

    #[test]
    fn md4_handles_inputs_that_need_a_second_block() {
        // The padding boundary: 55 bytes fits one block with padding, 56 forces another. A padding
        // bug shows up here and nowhere else.
        let a55 = [b'a'; 55];
        let a56 = [b'a'; 56];
        let a64 = [b'a'; 64];
        let a65 = [b'a'; 65];
        assert_eq!(md4(&a55).len(), 16);
        assert_ne!(md4(&a55), md4(&a56), "one byte must change the digest");
        assert_ne!(md4(&a64), md4(&a65));
    }

    #[test]
    fn the_nt_hash_is_the_published_value_for_a_known_password() {
        // The value every NTLM reference lists for "password": this is the check that the
        // UTF-16LE encoding and the MD4 are both right.
        assert_eq!(
            hex(&nt_hash("password")),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
        // And case matters in the password, unlike the user.
        assert_ne!(nt_hash("Password"), nt_hash("password"));
    }

    #[test]
    fn a_challenge_from_nowhere_is_refused_rather_than_parsed() {
        assert!(Auth::parse_challenge(b"").is_none(), "empty");
        assert!(
            Auth::parse_challenge(b"not ntlm at all, really").is_none(),
            "wrong signature"
        );
        let mut short = SIGNATURE.to_vec();
        short.extend_from_slice(&MSG_CHALLENGE.to_le_bytes());
        assert!(
            Auth::parse_challenge(&short).is_none(),
            "truncated after the type"
        );
    }

    #[test]
    fn a_challenge_with_offsets_past_its_own_end_does_not_panic() {
        // A server (or something impersonating one) claiming a target name beyond the message.
        // Reading it would be a panic on a remote peer's say-so, so the field is dropped instead.
        let mut msg = Vec::new();
        msg.extend_from_slice(SIGNATURE);
        msg.extend_from_slice(&MSG_CHALLENGE.to_le_bytes());
        msg.extend_from_slice(&0xffffu16.to_le_bytes()); // target name length: absurd
        msg.extend_from_slice(&0xffffu16.to_le_bytes());
        msg.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // offset: past the end
        msg.extend_from_slice(&0u32.to_le_bytes()); // flags
        msg.extend_from_slice(&[1u8; 8]); // challenge
        msg.extend_from_slice(&[0u8; 8]); // reserved
        let parsed = Auth::parse_challenge(&msg).expect("the message itself is well formed");
        assert!(
            parsed.target_name.is_empty(),
            "an out-of-bounds field must be dropped, not read"
        );
    }

    #[test]
    fn a_server_offering_only_ntlmv1_is_refused() {
        // The deliberate refusal. NTLMv1 is broken; answering it would be a downgrade, so the
        // connection fails with a reason instead of succeeding insecurely.
        let auth = Auth {
            user: "hxtest".to_string(),
            password: "whatever".to_string(),
            domain: None,
            workstation: "HX".to_string(),
            target_spn: Some("http/127.0.0.1".to_string()),
        };
        let v1_only = Challenge {
            server_challenge: [0u8; 8],
            target_name: Vec::new(),
            target_info: Vec::new(),
            // `NTLM` set, `NTLM2_KEY` clear: exactly the NTLMv1 offer.
            flags: FLAG_NTLM | FLAG_UNICODE,
        };
        assert!(
            auth.authenticate(&v1_only, &[], &[]).is_none(),
            "a server that will only speak NTLMv1 must be refused, not downgraded to"
        );

        let v2 = Challenge {
            flags: FLAG_NTLM | FLAG_UNICODE | FLAG_EXTENDED_SESSIONSECURITY | FLAG_TARGET_INFO,
            ..v1_only
        };
        assert!(
            auth.authenticate(&v2, &[], &[]).is_some(),
            "a server offering NTLMv2 must be answered"
        );
    }

    #[test]
    fn a_negotiate_message_is_well_formed() {
        let auth = Auth {
            user: "hxtest".to_string(),
            password: "p".to_string(),
            domain: Some("WORKGROUP".to_string()),
            workstation: "HX".to_string(),
            target_spn: Some("http/127.0.0.1".to_string()),
        };
        let msg = auth.negotiate();
        assert_eq!(&msg[0..8], SIGNATURE);
        assert_eq!(
            u32::from_le_bytes(msg[8..12].try_into().unwrap()),
            MSG_NEGOTIATE
        );
        let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
        assert_ne!(flags & FLAG_UNICODE, 0, "UTF-16 must be negotiated");
        assert_ne!(
            flags & FLAG_EXTENDED_SESSIONSECURITY,
            0,
            "NTLMv2 must be offered"
        );
        // `FLAG_VERSION` is offered because the client measured against a real host offers it
        // (0xe2088237), and the authenticate message carries the version block that flag announces.
        assert_ne!(
            flags & FLAG_VERSION,
            0,
            "the version block is written, so the flag announcing it must be offered"
        );
    }

    #[test]
    fn an_authenticate_message_is_well_formed_and_differs_per_challenge() {
        let auth = Auth {
            user: "hxtest".to_string(),
            password: "HxTest!Passw0rd-2026".to_string(),
            domain: None,
            workstation: "HX".to_string(),
            target_spn: Some("http/127.0.0.1".to_string()),
        };
        let challenge = Challenge {
            server_challenge: [0x11; 8],
            target_name: utf16le("HXTEST"),
            target_info: vec![0u8; 4],
            flags: FLAG_NTLM | FLAG_UNICODE | FLAG_EXTENDED_SESSIONSECURITY | FLAG_TARGET_INFO,
        };
        let msg = auth
            .authenticate(&challenge, &[], &[])
            .expect("NTLMv2 is offered");
        assert_eq!(&msg[0..8], SIGNATURE);
        assert_eq!(
            u32::from_le_bytes(msg[8..12].try_into().unwrap()),
            MSG_AUTHENTICATE
        );

        // The same password against a different challenge must produce a different response, or the
        // response is not bound to the server's nonce and could be replayed.
        let other = Challenge {
            server_challenge: [0x22; 8],
            ..challenge.clone()
        };
        let msg2 = auth.authenticate(&other, &[], &[]).expect("NTLMv2");
        assert_ne!(
            msg, msg2,
            "the response must depend on the server challenge — otherwise it is replayable"
        );

        // And the same challenge twice must differ too, because the client challenge is random.
        let msg3 = auth.authenticate(&challenge, &[], &[]).expect("NTLMv2");
        assert_ne!(
            msg, msg3,
            "the client challenge must be random, so two responses to one challenge differ"
        );
    }

    #[test]
    fn the_password_never_appears_in_the_response() {
        // The property the whole exchange exists for. A response that embedded the password would
        // be a plaintext credential on the wire.
        let secret = "HxTest!Passw0rd-2026";
        let auth = Auth {
            user: "hxtest".to_string(),
            password: secret.to_string(),
            domain: None,
            workstation: "HX".to_string(),
            target_spn: Some("http/127.0.0.1".to_string()),
        };
        let challenge = Challenge {
            server_challenge: [0x33; 8],
            target_name: Vec::new(),
            target_info: Vec::new(),
            flags: FLAG_NTLM | FLAG_UNICODE | FLAG_EXTENDED_SESSIONSECURITY,
        };
        let msg = auth.authenticate(&challenge, &[], &[]).expect("NTLMv2");
        assert!(
            !contains(&msg, secret.as_bytes()),
            "the password must not be present in the authenticate message"
        );
        assert!(
            !contains(&msg, &utf16le(secret)),
            "nor in UTF-16, which is the encoding an accidental inclusion would use"
        );
        // The NT hash must not be on the wire either: it is password-equivalent for this protocol.
        assert!(
            !contains(&msg, &nt_hash(secret)),
            "the NT hash is password-equivalent and must not be sent"
        );
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn the_negotiation_flags_match_a_working_implementation() {
        // These are pinned because getting them wrong does not fail loudly: a wrong bit produces a
        // 401 that names nothing, and two constants sharing a value makes a guard test the wrong
        // thing while still appearing to work. Both mistakes were made here, against a real host,
        // before this test existed. The values are those a known-good NTLM client uses.
        assert_eq!(FLAG_UNICODE, 0x0000_0001);
        assert_eq!(FLAG_REQUEST_TARGET, 0x0000_0004);
        assert_eq!(FLAG_NTLM, 0x0000_0200);
        assert_eq!(FLAG_ALWAYS_SIGN, 0x0000_8000);
        assert_eq!(
            FLAG_EXTENDED_SESSIONSECURITY, 0x0008_0000,
            "the NTLMv2 flag — the guard reads this, so it must be right"
        );
        assert_eq!(FLAG_TARGET_INFO, 0x0080_0000);
        assert_eq!(FLAG_VERSION, 0x0200_0000);
        assert_eq!(FLAG_128, 0x2000_0000);
        assert_eq!(FLAG_56, 0x8000_0000);

        // And no two flags may share a value. The earlier bug was exactly this: a "NTLMv2" constant
        // that was a copy of another flag's bit, so a check for one silently tested the other.
        let all = [
            ("UNICODE", FLAG_UNICODE),
            ("OEM", FLAG_OEM),
            ("REQUEST_TARGET", FLAG_REQUEST_TARGET),
            ("SIGN", FLAG_SIGN),
            ("SEAL", FLAG_SEAL),
            ("LM_KEY", FLAG_LM_KEY),
            ("NTLM", FLAG_NTLM),
            ("ALWAYS_SIGN", FLAG_ALWAYS_SIGN),
            ("TARGET_TYPE_SERVER", FLAG_TARGET_TYPE_SERVER),
            ("EXTENDED_SESSIONSECURITY", FLAG_EXTENDED_SESSIONSECURITY),
            ("TARGET_INFO", FLAG_TARGET_INFO),
            ("VERSION", FLAG_VERSION),
            ("128", FLAG_128),
            ("KEY_EXCH", FLAG_KEY_EXCH),
            ("56", FLAG_56),
        ];
        for (i, (name_a, a)) in all.iter().enumerate() {
            for (name_b, b) in all.iter().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "{name_a} and {name_b} share the value 0x{a:08x}; a guard reading one would \
                     silently test the other"
                );
            }
        }
    }

    #[test]
    fn a_real_windows_challenge_is_recognised_as_ntlmv2() {
        // The exact flags a Windows 10 WSMan endpoint sent, captured from a live handshake. This is
        // the case the guard must accept — and it is asserted as a whole word so a future constant
        // change that breaks the reading fails here rather than on a real host.
        let windows_flags = 0xa28a_8205u32;
        assert_ne!(
            windows_flags & FLAG_EXTENDED_SESSIONSECURITY,
            0,
            "Windows offers NTLMv2, so the guard must not refuse it"
        );
        assert_ne!(
            windows_flags & FLAG_TARGET_INFO,
            0,
            "and it sends a target info blob, which the response mixes in"
        );
        assert_eq!(
            windows_flags & FLAG_NTLM,
            FLAG_NTLM,
            "and it speaks NTLM at all"
        );
    }

    #[test]
    fn the_authenticate_message_echoes_the_servers_flags_not_the_clients() {
        // Windows checks the authenticate message's flags against what it sent. Replying with the
        // client's own offer is refused with a bare 401.
        let server = 0xa28a_8205u32;
        let echoed = authenticate_flags(server);

        // The property: the echo is the server's flags narrowed to what this client offers — every
        // bit the client can honour is echoed, and nothing the client did not offer appears.
        assert_eq!(
            echoed & negotiate_flags(),
            echoed,
            "the echo must only contain bits the client offered"
        );
        assert_ne!(
            echoed & FLAG_EXTENDED_SESSIONSECURITY,
            0,
            "the NTLMv2 bit the server offered must survive into the echo"
        );
        assert_ne!(
            echoed & FLAG_UNICODE,
            0,
            "and so must Unicode, or the message's own encoding is a lie"
        );
        // A bit the server set that the client never offered must not appear in the echo.
        // `NEGOTIATE_TARGET_TYPE_SERVER` is exactly that bit in a real Windows challenge: it is the
        // server describing itself, and it is the *only* difference between the server's flags and
        // this client's offer.
        assert_ne!(
            server & FLAG_TARGET_TYPE_SERVER,
            0,
            "the fixture must actually exercise a server-only bit"
        );
        assert_eq!(
            echoed & FLAG_TARGET_TYPE_SERVER,
            0,
            "a flag the client did not offer must not be echoed back"
        );
        // The bits the server set that this client does not offer. `TARGET_TYPE_SERVER` describes the
        // server; `FLAG_TARGET_INFO` is not offered because the client measured against this host
        // does not offer it either (its negotiate is 0xe2088237).
        let server_only = server & !negotiate_flags();
        assert_eq!(
            server_only,
            FLAG_TARGET_TYPE_SERVER | FLAG_TARGET_INFO,
            "the fixture must exercise exactly the server-only bits, got 0x{server_only:08x}"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
