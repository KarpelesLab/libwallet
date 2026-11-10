//! Frame-at-a-time reassembly of a scanned payload.
//!
//! A host scanning an animated QR gets one frame per camera hit, in whatever
//! order the signer's display and the camera happen to line up. It creates a
//! [`Context`], feeds every frame to [`Context::feed`], shows the returned
//! [`Progress`], and reads the payload once `complete` is true. Frame kind is
//! detected from the first frame (`ur:` → BC-UR, `B$` → BBQr, anything else →
//! a single raw text payload such as an xpub or base64 PSBT), duplicates are
//! ignored, and a frame from a different payload is rejected.
//!
//! The context is a plain, serializable list of frames: decoding re-runs from
//! scratch on each feed (frame counts are small), so it can live in the Env
//! cache across FFI calls without keeping decoder objects alive in memory.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{Env, Error, Result};

/// Which transport the frames belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Ur,
    Bbqr,
    /// A single non-QR-protocol string (xpub, descriptor, base64 PSBT, JSON…).
    Raw,
}

/// Classify one frame.
pub fn classify(frame: &str) -> Kind {
    let t = frame.trim();
    // `get`, not a byte-range index: a scanned frame may be any UTF-8 and
    // byte 3 need not be a char boundary.
    if t.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("ur:")) {
        Kind::Ur
    } else if t.len() >= 8 && t.starts_with("B$") {
        Kind::Bbqr
    } else {
        Kind::Raw
    }
}

/// Most distinct frames a context keeps. BBQr tops out at 1295 parts and the UR
/// decoder at 4096 fragments; a fountain stream needs a few more frames than
/// fragments, never unboundedly many.
pub const MAX_FRAMES: usize = 8192;
/// Longest single frame accepted: a one-part UR (two bytewords characters per
/// byte) of the largest payload we reassemble, plus its header.
pub const MAX_FRAME_LEN: usize = 2 * super::MAX_PAYLOAD_LEN + 1024;
/// Most frame text a context keeps in total (it is re-serialized into the Env
/// cache on every feed).
pub const MAX_TOTAL_LEN: usize = 4 * super::MAX_PAYLOAD_LEN;

/// The reassembly state: the distinct frames seen so far.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Context {
    pub kind: Option<Kind>,
    pub frames: Vec<String>,
    /// Set once the payload is complete: later frames are no longer stored.
    #[serde(default)]
    pub complete: bool,
}

/// The reassembled payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A UR: its type (lowercase, e.g. `crypto-psbt`) and CBOR body.
    Ur { ur_type: String, cbor: Vec<u8> },
    /// A BBQr file: its type letter and bytes.
    Bbqr { file_type: char, data: Vec<u8> },
    /// A raw string.
    Raw(String),
}

/// What the host shows after each frame.
#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub kind: Option<Kind>,
    /// Payload fragments recovered so far (UR: decoded fragments, which lags
    /// the frame count until fountain mixes resolve; BBQr: distinct parts).
    pub received: usize,
    /// Distinct frames fed so far.
    pub frames: usize,
    /// Frames needed (UR: fragment count — a fountain decoder may need a few
    /// more than this when early frames were missed; BBQr: part count). 0 until
    /// the first frame is parsed.
    pub expected: usize,
    /// 0–100. For a UR this is received fragments over fragment count, capped.
    pub percent: u8,
    pub complete: bool,
    /// UR type once known (from any frame).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ur_type: Option<String>,
    /// BBQr file type letter once known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    /// The payload, only when `complete`: `{"ur_type","cbor"(hex),"decoded"}`,
    /// `{"file_type","data"(base64),"text"?}` or `{"text"}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one scanned frame. Returns the current progress. Errors on a frame
    /// that cannot belong to this payload (different kind, malformed, or a
    /// different file/UR than the frames already received).
    pub fn feed(&mut self, frame: &str) -> Result<Progress> {
        let frame = frame.trim();
        if frame.is_empty() {
            return Err(Error::Env("empty frame".into()));
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(Error::Env(format!("frame too long ({} bytes)", frame.len())));
        }
        let kind = classify(frame);
        if let Some(k) = self.kind {
            if k != kind {
                return Err(Error::Env(format!("frame is {kind:?} but this context is collecting {k:?}")));
            }
        }
        // Validate the frame on its own before keeping it, so a stray scan
        // never poisons the context. `duplicate`: nothing new to store.
        let mut duplicate = false;
        match kind {
            Kind::Ur => {
                if !frame.is_ascii() {
                    return Err(Error::Env("bad UR frame: not ASCII".into()));
                }
                outscript::bcur::Ur::parse(frame).map_err(|e| Error::Env(format!("bad UR frame: {e}")))?;
            }
            Kind::Bbqr => {
                if !frame.is_ascii() {
                    return Err(Error::Env("bad BBQr frame: not ASCII".into()));
                }
                // Decode the body too (a part with a valid header but an
                // undecodable body would only fail at the final join, with no
                // way to replace it), and refuse a second, different part for
                // an index we already hold rather than letting the last one win.
                let (h, body) = super::bbqr_decode_part(frame).map_err(|e| Error::Env(format!("bad BBQr frame: {e}")))?;
                for f in &self.frames {
                    let Ok((h0, _)) = outscript::bbqr::Header::parse(f) else { continue };
                    if h0.index != h.index {
                        continue;
                    }
                    if h0.num_parts != h.num_parts || h0.file_type != h.file_type || h0.encoding != h.encoding {
                        return Err(Error::Env("BBQr frame belongs to a different file".into()));
                    }
                    if super::bbqr_decode_part(f)?.1 != body {
                        return Err(Error::Env(format!("BBQr part {} was already received with different content", h.index)));
                    }
                    duplicate = true;
                }
            }
            Kind::Raw => {
                if !self.frames.is_empty() && self.frames[0] != frame {
                    return Err(Error::Env("raw payload already received; create a new context".into()));
                }
            }
        }
        // Compare URs case-insensitively (QR frames are uppercase).
        let normalized = if kind == Kind::Ur { frame.to_ascii_lowercase() } else { frame.to_owned() };
        // Nothing to add: a frame we already hold, or anything scanned after
        // the payload completed (a signer keeps looping its animation).
        if self.complete || duplicate || self.frames.contains(&normalized) {
            return self.progress();
        }
        if self.frames.len() >= MAX_FRAMES {
            return Err(Error::Env(format!("too many frames ({MAX_FRAMES}) without completing; create a new context")));
        }
        if self.frames.iter().map(String::len).sum::<usize>() + normalized.len() > MAX_TOTAL_LEN {
            return Err(Error::Env("scanned frames exceed the size limit; create a new context".into()));
        }
        // One decode pass with the new frame: rejects a frame from another
        // UR/BBQr before storing it, and yields the progress to return.
        let (prog, _) = self.decode_inner(Some(kind), Some(&normalized))?;
        self.kind = Some(kind);
        self.complete = prog.complete;
        self.frames.push(normalized);
        Ok(prog)
    }

    /// Current progress (re-decodes from the stored frames).
    pub fn progress(&self) -> Result<Progress> {
        let (p, _) = self.decode_inner(self.kind, None)?;
        Ok(p)
    }

    /// The payload, if complete.
    pub fn payload(&self) -> Result<Option<Payload>> {
        Ok(self.decode_inner(self.kind, None)?.1)
    }

    fn decode_inner(&self, kind: Option<Kind>, extra: Option<&String>) -> Result<(Progress, Option<Payload>)> {
        let mut frames: Vec<&String> = self.frames.iter().collect();
        if let Some(e) = extra {
            frames.push(e);
        }
        let mut prog = Progress {
            kind,
            received: frames.len(),
            frames: frames.len(),
            expected: 0,
            percent: 0,
            complete: false,
            ur_type: None,
            file_type: None,
            payload: None,
        };
        let Some(kind) = kind else { return Ok((prog, None)) };
        match kind {
            Kind::Ur => {
                let mut dec = outscript::bcur::Decoder::with_limits(super::MAX_PAYLOAD_LEN, 4096);
                let mut done = false;
                for f in &frames {
                    done = dec.receive(f).map_err(|e| Error::Env(format!("UR frame rejected: {e}")))?;
                }
                prog.ur_type = dec.ur_type().map(str::to_owned);
                // Single-part URs report 1/1; multi-part the fragment count.
                prog.expected = dec.fragment_count().max(if frames.is_empty() { 0 } else { 1 });
                prog.received = if dec.fragment_count() > 0 { dec.received_fragment_count().min(dec.fragment_count()) } else { frames.len() };
                prog.complete = done;
                prog.percent = pct(prog.received, prog.expected, done);
                if done {
                    let cbor = dec.message().unwrap_or(&[]).to_vec();
                    let ur_type = prog.ur_type.clone().unwrap_or_default();
                    prog.payload = Some(serde_json::json!({
                        "ur_type": ur_type,
                        "cbor": super::hex(&cbor),
                        "decoded": super::registry::describe(&ur_type, &cbor),
                    }));
                    return Ok((prog, Some(Payload::Ur { ur_type, cbor })));
                }
                Ok((prog, None))
            }
            Kind::Bbqr => {
                let mut first: Option<outscript::bbqr::Header> = None;
                let mut seen = std::collections::BTreeSet::new();
                for f in &frames {
                    let (h, _) = outscript::bbqr::Header::parse(f).map_err(|e| Error::Env(format!("bad BBQr frame: {e}")))?;
                    match &first {
                        None => first = Some(h),
                        Some(f0) => {
                            if f0.num_parts != h.num_parts || f0.file_type != h.file_type || f0.encoding != h.encoding {
                                return Err(Error::Env("BBQr frame belongs to a different file".into()));
                            }
                        }
                    }
                    seen.insert(h.index);
                }
                if let Some(h) = &first {
                    prog.expected = h.num_parts as usize;
                    prog.file_type = Some(h.file_type.as_char().to_string());
                }
                prog.received = seen.len();
                prog.complete = prog.expected > 0 && prog.received >= prog.expected;
                prog.percent = pct(prog.received, prog.expected, prog.complete);
                if prog.complete {
                    let owned: Vec<String> = frames.iter().map(|s| (*s).clone()).collect();
                    let (ft, data) = super::bbqr_join(&owned)?;
                    let text = std::str::from_utf8(&data).ok().filter(|_| matches!(ft.as_char(), 'J' | 'U')).map(str::to_owned);
                    use base64::Engine;
                    prog.payload = Some(serde_json::json!({
                        "file_type": ft.as_char().to_string(),
                        "data": base64::engine::general_purpose::STANDARD.encode(&data),
                        "text": text,
                    }));
                    return Ok((prog, Some(Payload::Bbqr { file_type: ft.as_char(), data })));
                }
                Ok((prog, None))
            }
            Kind::Raw => {
                prog.expected = 1;
                prog.received = frames.len().min(1);
                prog.complete = !frames.is_empty();
                prog.percent = if prog.complete { 100 } else { 0 };
                if prog.complete {
                    let text = frames[0].clone();
                    prog.payload = Some(serde_json::json!({ "text": text }));
                    return Ok((prog, Some(Payload::Raw(text))));
                }
                Ok((prog, None))
            }
        }
    }
}

fn pct(received: usize, expected: usize, complete: bool) -> u8 {
    if complete {
        return 100;
    }
    if expected == 0 {
        return 0;
    }
    ((received * 100 / expected).min(99)) as u8
}

/// Decode a full set of frames in one go (all frames already in hand).
pub fn decode_all(frames: &[String]) -> Result<(Progress, Option<Payload>)> {
    let mut ctx = Context::new();
    let mut last = None;
    for f in frames {
        last = Some(ctx.feed(f)?);
    }
    let payload = ctx.payload()?;
    Ok((last.unwrap_or_else(|| ctx.progress().unwrap()), payload))
}

// ── Persistence in the Env cache (across FFI calls) ─────────────────────────

const TTL: Duration = Duration::from_secs(3600);

fn key(id: &str) -> String {
    format!("airgap:decoder:{id}")
}

/// Create a stored context; returns its id.
pub fn store_new(env: &Env) -> Result<String> {
    let id = xuid::Xuid::new("agdec").to_string();
    store_save(env, &id, &Context::new())?;
    Ok(id)
}

pub fn store_load(env: &Env, id: &str) -> Result<Context> {
    let raw = env.cache_load(&key(id))?.ok_or_else(|| Error::Env(format!("decoder context {id} not found (expired?)")))?;
    serde_json::from_slice(&raw).map_err(|e| Error::Env(format!("decoder context: {e}")))
}

pub fn store_save(env: &Env, id: &str, ctx: &Context) -> Result<()> {
    let raw = serde_json::to_vec(ctx).map_err(|e| Error::Env(e.to_string()))?;
    env.cache_store(&key(id), &raw, TTL)
}

pub fn store_delete(env: &Env, id: &str) -> Result<()> {
    env.cache_delete(&[&key(id)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ur_context_reports_progress_and_completes_out_of_order() {
        let big: Vec<u8> = (0..600u32).map(|i| (i % 253) as u8).collect();
        let cbor = outscript::bcur::bytes_to_cbor(&big);
        let parts = super::super::ur_parts("bytes", &cbor, Some(100), Some(0)).unwrap();
        assert!(parts.len() > 2);

        let mut ctx = Context::new();
        // Feed in reverse order, with a duplicate.
        let mut last = None;
        for (i, p) in parts.iter().rev().enumerate() {
            let prog = ctx.feed(p).unwrap();
            assert_eq!(prog.kind, Some(Kind::Ur));
            assert_eq!(prog.ur_type.as_deref(), Some("bytes"));
            assert_eq!(prog.expected, parts.len());
            if i + 1 < parts.len() {
                assert!(!prog.complete);
                assert!(prog.percent < 100);
            }
            last = Some(prog);
            let dup = ctx.feed(p).unwrap();
            assert_eq!(dup.frames, ctx.frames.len());
        }
        let last = last.unwrap();
        assert!(last.complete);
        assert_eq!(last.percent, 100);
        match ctx.payload().unwrap().unwrap() {
            Payload::Ur { ur_type, cbor: c } => {
                assert_eq!(ur_type, "bytes");
                assert_eq!(outscript::bcur::cbor_to_bytes(&c).unwrap(), &big[..]);
            }
            other => panic!("{other:?}"),
        }
        // A frame of a different kind is refused.
        assert!(ctx.feed("B$2P0100AAAAAAAA").is_err());
    }

    #[test]
    fn bbqr_context_counts_distinct_parts() {
        use outscript::bbqr::FileType;
        let data = b"{\"xfp\":\"0F056943\"}".to_vec();
        let parts = super::super::bbqr_parts(&data, FileType::JSON, Some(24), false).unwrap();
        assert!(parts.len() >= 2, "{parts:?}");
        let mut ctx = Context::new();
        let p = ctx.feed(&parts[1]).unwrap();
        assert_eq!((p.received, p.expected, p.complete), (1, parts.len(), false));
        assert_eq!(p.file_type.as_deref(), Some("J"));
        let p = ctx.feed(&parts[1]).unwrap(); // duplicate
        assert_eq!(p.received, 1);
        let mut done = p;
        for q in parts.iter().filter(|q| **q != parts[1]) {
            done = ctx.feed(q).unwrap();
        }
        assert!(done.complete);
        assert_eq!(done.payload.unwrap()["text"], String::from_utf8(data).unwrap());
    }

    #[test]
    fn non_ascii_frames_do_not_panic() {
        // Multi-byte characters straddling the 3-byte `ur:` probe (AG-04).
        for f in ["\u{20ac}", "ab\u{e9}cdef", "\u{1f600}\u{1f600}", "ur\u{e9}:bytes/aa", "UR:\u{e9}", "B$\u{e9}P0100AAAAAAAA", "B$2P0100\u{20ac}\u{20ac}"] {
            let _ = classify(f);
            let _ = Context::new().feed(f);
            let _ = decode_all(&[f.to_owned()]);
        }
        assert_eq!(classify("\u{20ac}"), Kind::Raw);
        assert!(Context::new().feed("ur:\u{e9}\u{e9}/\u{e9}").is_err());
        assert!(Context::new().feed("B$2P0100\u{20ac}\u{20ac}").is_err());
    }

    #[test]
    fn bbqr_conflicting_or_undecodable_parts_are_rejected_on_feed() {
        use outscript::bbqr::FileType;
        let data: Vec<u8> = (0..60u8).collect();
        let parts = super::super::bbqr_parts(&data, FileType::PSBT, Some(40), false).unwrap();
        assert!(parts.len() >= 3, "{parts:?}");
        // Same header as part 0, different body.
        let forged = format!("{}{}", &parts[0][..8], &parts[1][8..]);
        assert_ne!(forged, parts[0]);
        // Valid header, body that is not base32.
        let undecodable = format!("{}{}", &parts[1][..8], "1".repeat(parts[1].len() - 8));

        // Whichever arrives first wins; the other is refused, not stored.
        let mut ctx = Context::new();
        ctx.feed(&parts[0]).unwrap();
        assert!(ctx.feed(&forged).unwrap_err().to_string().contains("different content"));
        assert!(ctx.feed(&undecodable).is_err(), "body is decoded on feed");
        assert_eq!(ctx.frames.len(), 1);
        // The same part in lowercase is a duplicate, not a conflict.
        let p = ctx.feed(&format!("{}{}", &parts[0][..8], parts[0][8..].to_ascii_lowercase())).unwrap();
        assert_eq!((p.received, ctx.frames.len()), (1, 1));
        let mut done = p;
        for q in &parts[1..] {
            done = ctx.feed(q).unwrap();
        }
        assert!(done.complete);
        assert_eq!(ctx.payload().unwrap(), Some(Payload::Bbqr { file_type: 'P', data: data.clone() }));

        // A bad first frame does not pin the context to a kind.
        let mut ctx = Context::new();
        assert!(ctx.feed(&undecodable).is_err());
        assert!(ctx.kind.is_none() && ctx.frames.is_empty());
        assert!(ctx.feed("ur:bytes/!!").is_err());
        assert!(ctx.kind.is_none());

        // bbqr_join itself refuses conflicting duplicates too.
        let mut set = parts.clone();
        set.push(forged);
        assert!(super::super::bbqr_join(&set).is_err());
        let mut set = parts.clone();
        set.push(parts[0].clone());
        assert_eq!(super::super::bbqr_join(&set).unwrap().1, data);
    }

    #[test]
    fn frames_after_completion_are_not_stored_and_frames_are_capped() {
        let big: Vec<u8> = (0..600u32).map(|i| (i % 253) as u8).collect();
        let cbor = outscript::bcur::bytes_to_cbor(&big);
        // 60 redundant fountain frames beyond the minimum.
        let parts = super::super::ur_parts("bytes", &cbor, Some(100), Some(60)).unwrap();
        let mut ctx = Context::new();
        let mut at = None;
        for (i, p) in parts.iter().enumerate() {
            let prog = ctx.feed(p).unwrap();
            if prog.complete && at.is_none() {
                at = Some((i, ctx.frames.len()));
            }
            if let Some((_, stored)) = at {
                assert!(prog.complete && prog.payload.is_some());
                assert_eq!(ctx.frames.len(), stored, "no frame is stored once complete");
            }
        }
        let (i, _) = at.expect("completes");
        assert!(i + 1 < parts.len(), "frames were fed after completion");
        assert!(ctx.complete);
        // The stored context round-trips (and an old one without the flag loads).
        let back: Context = serde_json::from_slice(&serde_json::to_vec(&ctx).unwrap()).unwrap();
        assert!(back.complete && back.payload().unwrap().is_some());
        let old: Context = serde_json::from_str(r#"{"kind":"raw","frames":["x"]}"#).unwrap();
        assert!(!old.complete && old.progress().unwrap().complete);

        // Frame count cap: an incomplete context stops growing.
        let mut ctx = Context::new();
        ctx.feed(&parts[0]).unwrap();
        ctx.frames.resize(MAX_FRAMES, parts[0].to_ascii_lowercase());
        assert!(ctx.feed(&parts[1]).unwrap_err().to_string().contains("too many frames"));
        assert_eq!(ctx.frames.len(), MAX_FRAMES);
        // Frame length cap.
        assert!(Context::new().feed(&"x".repeat(MAX_FRAME_LEN + 1)).is_err());
    }

    #[test]
    fn raw_frame_completes_immediately() {
        let mut ctx = Context::new();
        let p = ctx.feed("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs").unwrap();
        assert!(p.complete);
        assert_eq!(p.kind, Some(Kind::Raw));
        assert!(ctx.feed("something else").is_err());
    }
}
