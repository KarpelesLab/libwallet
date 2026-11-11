//! CatCard's wire layouts: the 64-byte report framing, the opcodes and
//! statuses, `Identify`, and the host-wallet structures (paths, the sign blob,
//! the address reply, the sign results).
//!
//! Written from the firmware's `docs/USB.md` / `docs/PHONE-APP.md` and checked
//! against the byte vectors its own tests and reference tools pin
//! (`tools/hostwallet.py --selftest`). Integers are little-endian throughout;
//! every reader is strict: a truncated structure or a trailing byte is refused.

/// USB vendor id (Karpeles Lab Inc.).
pub const VENDOR_ID: u16 = 0x39F2;
/// USB product id of the CatCard firmware.
pub const PRODUCT_ID: u16 = 0x0401;
/// HID usage page of the vendor interface (the keyboard and FIDO interfaces
/// the device may also present have their own).
pub const USAGE_PAGE: u16 = 0xFF00;

/// One HID report, each way. The device declares no report id.
pub const REPORT_LEN: usize = 64;
const KIND_START: u8 = 0x01;
const KIND_CONT: u8 = 0x02;
const START_PAYLOAD: usize = REPORT_LEN - 8;
const CONT_PAYLOAD: usize = REPORT_LEN - 2;

/// The protocol version this host speaks (`Identify`).
pub const PROTOCOL_VERSION: u16 = 2;

/// Request opcodes.
pub mod op {
    pub const IDENTIFY: u16 = 0x0002;
    /// A command or reply sealed for the paired channel.
    pub const NCRY_MSG: u16 = 0x0041;
    pub const PAIR_COMMIT: u16 = 0x0042;
    pub const PAIR_REVEAL: u16 = 0x0043;
    /// Sealed only.
    pub const PAIR_CONFIRM: u16 = 0x0044;
    pub const PAIR_ABORT: u16 = 0x0045;
    // Host-wallet commands: inside a paired channel only.
    pub const HOST_ADDRESSES: u16 = 0x0050;
    pub const HOST_SIGN_BEGIN: u16 = 0x0051;
    pub const HOST_SIGN_DATA: u16 = 0x0052;
    pub const HOST_SIGN_COMMIT: u16 = 0x0053;
    pub const HOST_RESULT: u16 = 0x0054;
    pub const HOST_ABORT: u16 = 0x0055;
}

/// Reply statuses.
pub mod status {
    pub const OK: u16 = 0x0000;
    pub const UNKNOWN_OPCODE: u16 = 0x0001;
    pub const NOT_NOW: u16 = 0x0002;
    pub const BAD_REQUEST: u16 = 0x0003;
    pub const DECLINED: u16 = 0x0004;
    pub const REFUSED: u16 = 0x0005;
    pub const BUSY: u16 = 0x0006;

    pub fn name(s: u16) -> String {
        match s {
            OK => "Ok".into(),
            UNKNOWN_OPCODE => "UnknownOpcode".into(),
            NOT_NOW => "NotNow".into(),
            BAD_REQUEST => "BadRequest".into(),
            DECLINED => "Declined".into(),
            REFUSED => "Refused".into(),
            BUSY => "Busy".into(),
            other => format!("status {other:#06x}"),
        }
    }
}

/// `Identify` state bits.
pub mod state {
    /// The PIN has been entered.
    pub const UNLOCKED: u8 = 1 << 0;
    /// No PIN has been set yet.
    pub const BLANK: u8 = 1 << 1;
}

/// `Identify` capability bits.
pub mod caps {
    /// Bench builds only: the host can press keys.
    pub const KEY_INJECTION: u8 = 1 << 0;
    /// Bench builds only: the host can read and write memory.
    pub const DEBUG_MEM: u8 = 1 << 2;
    /// Bench builds only: the host can type the PIN.
    pub const UNLOCK_PIN: u8 = 1 << 3;
    /// The host-wallet commands.
    pub const HOST_WALLET: u8 = 1 << 6;
    /// The paired encrypted channel.
    pub const PAIRING: u8 = 1 << 7;
}

/// The one-byte chain of the host-wallet structures.
pub mod chain {
    pub const BITCOIN: u8 = 1;
    pub const ETHEREUM: u8 = 2;
    pub const SOLANA: u8 = 3;

    pub fn name(c: u8) -> String {
        match c {
            BITCOIN => "Bitcoin".into(),
            ETHEREUM => "Ethereum".into(),
            SOLANA => "Solana".into(),
            4 => "Litecoin".into(),
            5 => "Dogecoin".into(),
            6 => "Bitcoin Cash".into(),
            7 => "Monacoin".into(),
            8 => "Electra Protocol".into(),
            9 => "Tron".into(),
            10 => "Namecoin".into(),
            other => format!("chain {other}"),
        }
    }
}

/// How an address entry's address is written.
pub mod format {
    pub const P2PKH: u8 = 1;
    pub const P2SH_P2WPKH: u8 = 2;
    pub const P2WPKH: u8 = 3;
    pub const P2TR: u8 = 4;
    pub const EVM: u8 = 5;
    pub const SOLANA: u8 = 7;
}

/// The first byte of every host-wallet result.
pub mod kind {
    pub const ADDRESSES: u8 = 1;
    pub const BITCOIN: u8 = 2;
    pub const EVM: u8 = 3;
    pub const SOLANA: u8 = 4;
}

/// Entry shapes of the address reply.
pub mod shape {
    /// A UTXO chain: an account extended key, and the first receive address.
    pub const UTXO: u8 = 1;
    /// An account chain: one address, its key and its path.
    pub const ACCOUNT: u8 = 2;
}

pub const HARDENED: u32 = 0x8000_0000;
/// Deepest path a request or a reply carries.
pub const MAX_DEPTH: usize = 8;
/// Most keys one sign request may list.
pub const MAX_KEYS: usize = 32;
/// Most plaintext one sealed record carries, opcode included.
pub const PLAIN_MAX: usize = 1024;
/// Most transaction bytes one `HostSignData` carries.
pub const DATA_MAX: usize = PLAIN_MAX - 2 - 4;
/// Most result bytes one `HostResult` page carries.
pub const PAGE_MAX: usize = 448;

// ── Framing ──────────────────────────────────────────────────────────────────

/// The reports of one message: a `START` (`kind, seq, u16 opcode, u32 total,
/// payload`) and as many `CONT` (`kind, seq, payload`) as the payload needs.
pub fn frames(opcode: u16, payload: &[u8]) -> Vec<[u8; REPORT_LEN]> {
    let mut out = Vec::with_capacity(1 + payload.len() / CONT_PAYLOAD);
    let mut f = [0u8; REPORT_LEN];
    let n = payload.len().min(START_PAYLOAD);
    f[0] = KIND_START;
    f[2..4].copy_from_slice(&opcode.to_le_bytes());
    f[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    f[8..8 + n].copy_from_slice(&payload[..n]);
    out.push(f);
    let mut at = n;
    let mut seq = 0u8;
    while at < payload.len() {
        seq = seq.wrapping_add(1);
        let n = (payload.len() - at).min(CONT_PAYLOAD);
        let mut f = [0u8; REPORT_LEN];
        f[0] = KIND_CONT;
        f[1] = seq;
        f[2..2 + n].copy_from_slice(&payload[at..at + n]);
        out.push(f);
        at += n;
    }
    out
}

/// Longest reply this host will gather: every reply the firmware gives is a
/// sealed record of at most 512 bytes; anything far past that is not ours.
const REPLY_MAX: usize = 64 * 1024;

/// Puts a reply's reports back together.
#[derive(Default)]
pub struct Reassembler {
    head: Option<(u16, usize)>,
    body: Vec<u8>,
    next_seq: u8,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one report; `Some((status, payload))` once the message is whole.
    /// An all-zero report (or one of another kind) is not part of a message —
    /// some hosts hand those over when the device has nothing to say — and is
    /// skipped until a message has started.
    pub fn push(&mut self, report: &[u8]) -> Result<Option<(u16, Vec<u8>)>, String> {
        // A report id of zero may or may not be stripped by the platform.
        let report = if report.len() == REPORT_LEN + 1 && report[0] == 0 { &report[1..] } else { report };
        if report.len() < 8 {
            return Err(format!("short report ({} bytes)", report.len()));
        }
        match (report[0], self.head) {
            (KIND_START, None) => {
                let status = u16::from_le_bytes([report[2], report[3]]);
                let total = u32::from_le_bytes([report[4], report[5], report[6], report[7]]) as usize;
                if total > REPLY_MAX {
                    return Err(format!("reply of {total} bytes announced"));
                }
                let n = total.min(START_PAYLOAD).min(report.len() - 8);
                self.body = report[8..8 + n].to_vec();
                self.head = Some((status, total));
                self.next_seq = report[1].wrapping_add(1);
            }
            (KIND_START, Some(_)) => return Err("a new reply started inside another".into()),
            (KIND_CONT, Some((_, total))) => {
                if report[1] != self.next_seq {
                    return Err(format!("reply frame out of sequence (expected {}, got {})", self.next_seq, report[1]));
                }
                self.next_seq = self.next_seq.wrapping_add(1);
                let n = (total - self.body.len()).min(CONT_PAYLOAD).min(report.len() - 2);
                self.body.extend_from_slice(&report[2..2 + n]);
            }
            (KIND_CONT, None) => return Err("a continuation frame with no reply open".into()),
            (_, None) => return Ok(None),
            (kind, Some(_)) => return Err(format!("unexpected frame kind {kind} inside a reply")),
        }
        match self.head {
            Some((status, total)) if self.body.len() >= total => {
                self.head = None;
                Ok(Some((status, std::mem::take(&mut self.body))))
            }
            _ => Ok(None),
        }
    }
}

/// A whole message as one byte string: `[u16 opcode][u32 total][payload]` —
/// the `START` frame without its kind and sequence bytes, and exactly the data
/// of the smart-card reader's one APDU. A reply has the status in place of the
/// opcode. This is what the host bridge carries.
pub fn message(opcode: u16, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(6 + payload.len());
    m.extend_from_slice(&opcode.to_le_bytes());
    m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    m.extend_from_slice(payload);
    m
}

/// Read a [`message`]: `(opcode or status, payload)`.
pub fn parse_message(m: &[u8]) -> Result<(u16, &[u8]), String> {
    if m.len() < 6 {
        return Err("message shorter than its six-byte header".into());
    }
    let total = u32::from_le_bytes([m[2], m[3], m[4], m[5]]) as usize;
    if m.len() - 6 != total {
        return Err(format!("message announces {total} bytes and carries {}", m.len() - 6));
    }
    Ok((u16::from_le_bytes([m[0], m[1]]), &m[6..]))
}

// ── Identify ─────────────────────────────────────────────────────────────────

/// What `Identify` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub protocol: u16,
    pub state: u8,
    pub caps: u8,
    pub board: String,
    pub version: String,
}

impl Identity {
    /// `[u16 protocol][u8 state][u8 caps][u8 n][board][u8 m][version]`.
    pub fn decode(body: &[u8]) -> Result<Self, String> {
        let mut c = Cursor::new(body);
        let protocol = u16::from_le_bytes(c.take(2)?.try_into().unwrap());
        let state = c.u8()?;
        let caps = c.u8()?;
        let board = String::from_utf8_lossy(c.short()?).into_owned();
        let version = String::from_utf8_lossy(c.short()?).into_owned();
        Ok(Identity { protocol, state, caps, board, version })
    }

    pub fn unlocked(&self) -> bool {
        self.state & state::UNLOCKED != 0
    }

    /// A development image whose host can press keys, type the PIN or read
    /// memory: nothing an owner should be using.
    pub fn bench(&self) -> bool {
        self.caps & (caps::KEY_INJECTION | caps::DEBUG_MEM | caps::UNLOCK_PIN) != 0
    }
}

// ── A strict reader ──────────────────────────────────────────────────────────

pub(crate) struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Cursor { b, at: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len()).ok_or("truncated")?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    /// `[u8 depth][depth × u32]`, depth 1 to [`MAX_DEPTH`].
    pub(crate) fn path(&mut self) -> Result<Vec<u32>, String> {
        let depth = self.u8()? as usize;
        if depth == 0 || depth > MAX_DEPTH {
            return Err("bad path depth".into());
        }
        (0..depth).map(|_| self.u32()).collect()
    }

    /// `[u8 len][bytes]`.
    pub(crate) fn short(&mut self) -> Result<&'a [u8], String> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    pub(crate) fn done(&self) -> Result<(), String> {
        if self.at == self.b.len() {
            Ok(())
        } else {
            Err("trailing bytes".into())
        }
    }
}

// ── Paths ────────────────────────────────────────────────────────────────────

/// `m/84'/0'/0'/0/3` (or with `h`) → steps, the hardened bit set.
pub fn parse_path(text: &str) -> Result<Vec<u32>, String> {
    let mut parts = text.trim().split('/').peekable();
    if matches!(parts.peek(), Some(&"m") | Some(&"M")) {
        parts.next();
    }
    let mut steps = Vec::new();
    for p in parts {
        let (num, hard) = match p.strip_suffix(['\'', 'h', 'H']) {
            Some(n) => (n, true),
            None => (p, false),
        };
        let n: u32 = num.parse().ok().filter(|n| *n < HARDENED).ok_or_else(|| format!("bad path step {p:?}"))?;
        steps.push(if hard { n | HARDENED } else { n });
    }
    if steps.is_empty() || steps.len() > MAX_DEPTH {
        return Err(format!("path depth must be 1-{MAX_DEPTH}"));
    }
    Ok(steps)
}

/// Steps → `m/84'/0'/0'`.
pub fn path_text(steps: &[u32]) -> String {
    let mut s = String::from("m");
    for c in steps {
        s.push_str(&if c & HARDENED != 0 { format!("/{}'", c & !HARDENED) } else { format!("/{c}") });
    }
    s
}

fn put_path(out: &mut Vec<u8>, steps: &[u32]) {
    out.push(steps.len() as u8);
    for s in steps {
        out.extend_from_slice(&s.to_le_bytes());
    }
}

// ── Requests ─────────────────────────────────────────────────────────────────

/// The uploaded sign request:
/// `[u8 version = 1][u8 chain][u8 n][n × path][u32 tx length][tx]`.
pub fn sign_blob(chain: u8, keys: &[Vec<u32>], tx: &[u8]) -> Result<Vec<u8>, String> {
    if keys.is_empty() || keys.len() > MAX_KEYS {
        return Err(format!("a sign request lists 1-{MAX_KEYS} keys, not {}", keys.len()));
    }
    if keys.iter().any(|k| k.is_empty() || k.len() > MAX_DEPTH) {
        return Err(format!("path depth must be 1-{MAX_DEPTH}"));
    }
    if tx.is_empty() {
        return Err("empty transaction".into());
    }
    let mut out = vec![1, chain, keys.len() as u8];
    for k in keys {
        put_path(&mut out, k);
    }
    out.extend_from_slice(&u32::try_from(tx.len()).map_err(|_| "transaction too long")?.to_le_bytes());
    out.extend_from_slice(tx);
    Ok(out)
}

// ── The address reply ────────────────────────────────────────────────────────

/// One entry of the address reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub shape: u8,
    pub chain: u8,
    pub format: u8,
    /// `m/purpose'/coin'/account'`: what the person shared, and what a sign
    /// request's keys must sit under.
    pub account_path: Vec<u32>,
    /// Where `address` and `pubkey` are.
    pub address_path: Vec<u32>,
    /// The account's extended public key (UTXO chains; empty otherwise).
    pub xpub: String,
    pub address: String,
    /// Compressed secp256k1 (33 bytes) or ed25519 (32).
    pub pubkey: Vec<u8>,
}

/// The address reply:
/// `[u8 kind = 1][u8 version = 1][4 master fingerprint][u32 account][u8 count]`
/// then `count` entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addresses {
    pub fingerprint: [u8; 4],
    pub account: u32,
    pub entries: Vec<Entry>,
}

impl Addresses {
    pub fn decode(r: &[u8]) -> Result<Self, String> {
        let mut c = Cursor::new(r);
        if c.u8()? != kind::ADDRESSES {
            return Err("not an address reply".into());
        }
        if c.u8()? != 1 {
            return Err("address reply of an unknown version".into());
        }
        let fingerprint: [u8; 4] = c.take(4)?.try_into().unwrap();
        let account = c.u32()?;
        let count = c.u8()?;
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let shape = c.u8()?;
            if shape != shape::UTXO && shape != shape::ACCOUNT {
                return Err("bad entry shape".into());
            }
            let chain = c.u8()?;
            let format = c.u8()?;
            let account_path = c.path()?;
            let address_path = c.path()?;
            let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| "entry text is not UTF-8".to_owned());
            let xpub = if shape == shape::UTXO { text(c.short()?)? } else { String::new() };
            let address = text(c.short()?)?;
            let pubkey = c.short()?.to_vec();
            entries.push(Entry { shape, chain, format, account_path, address_path, xpub, address, pubkey });
        }
        c.done()?;
        Ok(Addresses { fingerprint, account, entries })
    }
}

// ── Sign results ─────────────────────────────────────────────────────────────

/// `[u8 kind = 2][u8 psbt version, 0 or 2][u32 len][signed PSBT][u32 len][network tx]`
/// → `(psbt version, psbt, tx)`. The transaction is empty unless every input
/// was complete and the device finalised.
pub fn read_bitcoin(r: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let mut c = Cursor::new(r);
    if c.u8()? != kind::BITCOIN {
        return Err("not a Bitcoin result".into());
    }
    let version = c.u8()?;
    if version != 0 && version != 2 {
        return Err("bad PSBT version".into());
    }
    let n = c.u32()? as usize;
    let psbt = c.take(n)?;
    let n = c.u32()? as usize;
    let tx = c.take(n)?;
    c.done()?;
    Ok((version, psbt, tx))
}

/// `[u8 kind = 3][u32 len][signed raw transaction]`.
pub fn read_evm(r: &[u8]) -> Result<&[u8], String> {
    let mut c = Cursor::new(r);
    if c.u8()? != kind::EVM {
        return Err("not an EVM result".into());
    }
    let n = c.u32()? as usize;
    let tx = c.take(n)?;
    c.done()?;
    Ok(tx)
}

/// `[u8 kind = 4][u8 n][n × ([u8 signer slot][64-byte signature])][u32 len][transaction]`
/// → `(signatures by slot, transaction)`.
#[allow(clippy::type_complexity)]
pub fn read_solana(r: &[u8]) -> Result<(Vec<(u8, [u8; 64])>, &[u8]), String> {
    let mut c = Cursor::new(r);
    if c.u8()? != kind::SOLANA {
        return Err("not a Solana result".into());
    }
    let count = c.u8()?;
    let mut sigs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let slot = c.u8()?;
        sigs.push((slot, c.take(64)?.try_into().unwrap()));
    }
    let n = c.u32()? as usize;
    let tx = c.take(n)?;
    c.done()?;
    Ok((sigs, tx))
}
