//! Apple backend (iOS, iPadOS, macOS): Security.framework, called directly.
//!
//! Each entry owns one P-256 private key that never leaves its store: the
//! Secure Enclave when the device has one ("apple-se"), else a Keychain key
//! ("apple-keychain": the iOS simulator, Macs without an SE). The key is
//! `WhenUnlockedThisDeviceOnly` — never synced to iCloud, never in a backup —
//! and, when the policy asks for user presence, its use requires Face ID /
//! Touch ID / Optic ID or the device passcode (`kSecAccessControlUserPresence`).
//!
//! The entry's data key is ECIES-style: sealing needs only the public key (no
//! prompt) — Rust does ECDH with a fresh ephemeral key and keeps the
//! ephemeral public half; opening asks the enclave for the same ECDH result,
//! which is the step the OS gates and prompts for, and Rust derives the key
//! with HKDF. The 32-byte shared secret is the only key material the OS hands
//! back; it is wiped as soon as the key is derived.

#![allow(non_upper_case_globals, non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;

use purecrypto::ec::ecdh::EcdhPrivateKey;
use purecrypto::ec::ecdsa::EcdsaPublicKey;
use purecrypto::zeroize::Zeroizing;

use super::{Capabilities, Policy, SecureBackend};

type CFTypeRef = *const c_void;
type CFIndex = isize;
type OSStatus = i32;
type Id = *mut c_void;
type Sel = *mut c_void;

const kCFNumberSInt32Type: CFIndex = 3;
const kCFStringEncodingUTF8: u32 = 0x0800_0100;
const kSecAccessControlUserPresence: usize = 1 << 0;
const kSecAccessControlPrivateKeyUsage: usize = 1 << 30;
const errSecItemNotFound: OSStatus = -25300;
/// The app is not signed with a keychain access group (an unsigned macOS
/// binary, a test runner): the data-protection keychain refuses it.
const errSecMissingEntitlement: OSStatus = -34018;
const MISSING_ENTITLEMENT: &str = "the app is not signed with a keychain-access-groups entitlement, which the iOS/macOS data-protection keychain requires (unsigned or ad-hoc builds cannot use secure vault entries)";
const errSecUserCanceled: CFIndex = -128;
/// LAPolicyDeviceOwnerAuthentication: biometrics or passcode.
const LAPolicyDeviceOwnerAuthentication: isize = 2;
const LAPolicyDeviceOwnerAuthenticationWithBiometrics: isize = 1;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    static kCFBooleanTrue: CFTypeRef;
    fn CFDictionaryCreate(a: CFTypeRef, k: *const CFTypeRef, v: *const CFTypeRef, n: CFIndex, kcb: *const c_void, vcb: *const c_void) -> CFTypeRef;
    fn CFDataCreate(a: CFTypeRef, bytes: *const u8, len: CFIndex) -> CFTypeRef;
    fn CFDataGetBytePtr(d: CFTypeRef) -> *const u8;
    fn CFDataGetLength(d: CFTypeRef) -> CFIndex;
    fn CFNumberCreate(a: CFTypeRef, t: CFIndex, v: *const c_void) -> CFTypeRef;
    fn CFStringCreateWithBytes(a: CFTypeRef, b: *const u8, n: CFIndex, enc: u32, ext: u8) -> CFTypeRef;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, n: CFIndex, enc: u32) -> u8;
    fn CFErrorGetCode(e: CFTypeRef) -> CFIndex;
    fn CFErrorCopyDescription(e: CFTypeRef) -> CFTypeRef;
    fn CFRelease(r: CFTypeRef);
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecClass: CFTypeRef;
    static kSecClassKey: CFTypeRef;
    static kSecClassGenericPassword: CFTypeRef;
    static kSecAttrService: CFTypeRef;
    static kSecValueData: CFTypeRef;
    static kSecAttrAccessible: CFTypeRef;
    static kSecAttrKeyType: CFTypeRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFTypeRef;
    static kSecAttrKeySizeInBits: CFTypeRef;
    static kSecAttrTokenID: CFTypeRef;
    static kSecAttrTokenIDSecureEnclave: CFTypeRef;
    static kSecPrivateKeyAttrs: CFTypeRef;
    static kSecAttrIsPermanent: CFTypeRef;
    static kSecAttrApplicationTag: CFTypeRef;
    static kSecAttrAccessControl: CFTypeRef;
    static kSecAttrKeyClass: CFTypeRef;
    static kSecAttrKeyClassPrivate: CFTypeRef;
    static kSecAttrKeyClassPublic: CFTypeRef;
    static kSecReturnRef: CFTypeRef;
    static kSecUseAuthenticationContext: CFTypeRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFTypeRef;
    static kSecKeyAlgorithmECDHKeyExchangeStandard: CFTypeRef;
    #[cfg(target_os = "macos")]
    static kSecUseDataProtectionKeychain: CFTypeRef;
    fn SecAccessControlCreateWithFlags(a: CFTypeRef, prot: CFTypeRef, flags: usize, err: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCreateRandomKey(params: CFTypeRef, err: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyPublicKey(key: CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyExternalRepresentation(key: CFTypeRef, err: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCreateWithData(data: CFTypeRef, attrs: CFTypeRef, err: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyKeyExchangeResult(k: CFTypeRef, alg: CFTypeRef, peer: CFTypeRef, params: CFTypeRef, err: *mut CFTypeRef) -> CFTypeRef;
    fn SecItemCopyMatching(q: CFTypeRef, out: *mut CFTypeRef) -> OSStatus;
    fn SecItemDelete(q: CFTypeRef) -> OSStatus;
    fn SecItemAdd(attrs: CFTypeRef, out: *mut CFTypeRef) -> OSStatus;
}

#[link(name = "LocalAuthentication", kind = "framework")]
extern "C" {}

#[link(name = "objc")]
extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(p: *mut c_void);
}

/// An owned CF object (Create/Copy rule), released on drop.
struct Cf(CFTypeRef);

impl Cf {
    fn new(r: CFTypeRef) -> Option<Cf> {
        (!r.is_null()).then(|| Cf(r))
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) }
    }
}

fn data(b: &[u8]) -> Cf {
    Cf(unsafe { CFDataCreate(std::ptr::null(), b.as_ptr(), b.len() as CFIndex) })
}

fn string(s: &str) -> Cf {
    Cf(unsafe { CFStringCreateWithBytes(std::ptr::null(), s.as_ptr(), s.len() as CFIndex, kCFStringEncodingUTF8, 0) })
}

fn dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Cf {
    let (k, v): (Vec<_>, Vec<_>) = pairs.iter().copied().unzip();
    Cf(unsafe {
        CFDictionaryCreate(std::ptr::null(), k.as_ptr(), v.as_ptr(), k.len() as CFIndex, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks)
    })
}

/// Copy a CFData out. With `wipe`, the CF buffer is zeroed before release
/// (best effort: Security hands back a fresh, unshared object).
fn data_bytes(d: &Cf, wipe: bool) -> Zeroizing<Vec<u8>> {
    unsafe {
        let p = CFDataGetBytePtr(d.0);
        let n = CFDataGetLength(d.0) as usize;
        let out = Zeroizing::new(std::slice::from_raw_parts(p, n).to_vec());
        if wipe {
            for i in 0..n {
                std::ptr::write_volatile((p as *mut u8).add(i), 0);
            }
        }
        out
    }
}

/// A CFError as text; the error is released.
fn error_text(e: CFTypeRef, what: &str) -> String {
    if e.is_null() {
        return format!("{what} failed");
    }
    unsafe {
        let code = CFErrorGetCode(e);
        let desc = CFErrorCopyDescription(e);
        let mut buf = [0 as c_char; 512];
        let text = if !desc.is_null() && CFStringGetCString(desc, buf.as_mut_ptr(), buf.len() as CFIndex, kCFStringEncodingUTF8) != 0 {
            std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
        } else {
            String::new()
        };
        if !desc.is_null() {
            CFRelease(desc);
        }
        CFRelease(e);
        // -128 errSecUserCanceled; LAError userCancel/systemCancel/appCancel.
        if matches!(code, errSecUserCanceled | -2 | -4 | -9) {
            return "user cancelled".into();
        }
        if code == errSecMissingEntitlement as CFIndex {
            return format!("{what} failed: {MISSING_ENTITLEMENT}");
        }
        format!("{what} failed ({code}): {text}")
    }
}

// ── LocalAuthentication via the Objective-C runtime ──────────────────────

unsafe fn sel(name: &[u8]) -> Sel {
    sel_registerName(name.as_ptr() as *const c_char)
}

/// An `LAContext` (manually retained; released on drop).
struct LaContext(Id);

impl LaContext {
    fn new() -> Option<LaContext> {
        unsafe {
            let cls = objc_getClass(c"LAContext".as_ptr());
            if cls.is_null() {
                return None;
            }
            let send: unsafe extern "C" fn(Id, Sel) -> Id = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let obj = send(send(cls, sel(b"alloc\0")), sel(b"init\0"));
            (!obj.is_null()).then(|| LaContext(obj))
        }
    }

    fn set_reason(&self, reason: &str) {
        let s = string(reason);
        unsafe {
            let send: unsafe extern "C" fn(Id, Sel, CFTypeRef) = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            send(self.0, sel(b"setLocalizedReason:\0"), s.0);
        }
    }

    fn can_evaluate(&self, policy: isize) -> bool {
        unsafe {
            let send: unsafe extern "C" fn(Id, Sel, isize, *mut Id) -> i8 = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            send(self.0, sel(b"canEvaluatePolicy:error:\0"), policy, std::ptr::null_mut()) != 0
        }
    }

    /// LABiometryType: 0 none, 1 Touch ID, 2 Face ID, 4 Optic ID.
    fn biometry_type(&self) -> isize {
        unsafe {
            let send: unsafe extern "C" fn(Id, Sel) -> isize = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            send(self.0, sel(b"biometryType\0"))
        }
    }
}

impl Drop for LaContext {
    fn drop(&mut self) {
        unsafe {
            let send: unsafe extern "C" fn(Id, Sel) = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            send(self.0, sel(b"release\0"));
        }
    }
}

/// Run `f` inside an autorelease pool: our worker threads have none, and the
/// frameworks autorelease freely.
fn pool<R>(f: impl FnOnce() -> R) -> R {
    unsafe {
        let p = objc_autoreleasePoolPush();
        let r = f();
        objc_autoreleasePoolPop(p);
        r
    }
}

// ── The backend ──────────────────────────────────────────────────────────

pub struct Apple {
    /// The device has a usable Secure Enclave.
    enclave: bool,
    /// This binary may use the data-protection keychain at all.
    entitled: bool,
}

pub(super) fn backend() -> Option<&'static dyn SecureBackend> {
    static B: OnceLock<Apple> = OnceLock::new();
    Some(B.get_or_init(|| Apple { enclave: pool(probe_enclave), entitled: pool(probe_entitled) }) as &dyn SecureBackend)
}

/// Whether the data-protection keychain accepts this binary: add and remove a
/// throwaway item (a lookup of a missing item can't tell).
fn probe_entitled() -> bool {
    unsafe {
        let service = string("net.atonline.libwallet.vault.probe");
        let value = data(b"probe");
        let mut base = vec![(kSecClass, kSecClassGenericPassword), (kSecAttrService, service.0)];
        #[cfg(target_os = "macos")]
        base.push((kSecUseDataProtectionKeychain, kCFBooleanTrue));
        let query = dict(&base);
        SecItemDelete(query.0);
        let mut add = base.clone();
        add.push((kSecValueData, value.0));
        add.push((kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly));
        let attrs = dict(&add);
        let s = SecItemAdd(attrs.0, std::ptr::null_mut());
        SecItemDelete(query.0);
        s != errSecMissingEntitlement
    }
}

/// Whether an enclave key can be created: a throwaway, non-permanent one.
fn probe_enclave() -> bool {
    unsafe {
        let bits = 256i32;
        let n = Cf(CFNumberCreate(std::ptr::null(), kCFNumberSInt32Type, &bits as *const i32 as *const c_void));
        let acl = SecAccessControlCreateWithFlags(std::ptr::null(), kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, std::ptr::null_mut());
        let Some(acl) = Cf::new(acl) else { return false };
        let priv_attrs = dict(&[(kSecAttrAccessControl, acl.0)]);
        let params = dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
            (kSecAttrKeySizeInBits, n.0),
            (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave),
            (kSecPrivateKeyAttrs, priv_attrs.0),
        ]);
        let mut err: CFTypeRef = std::ptr::null();
        match Cf::new(SecKeyCreateRandomKey(params.0, &mut err)) {
            Some(_) => true,
            None => {
                if !err.is_null() {
                    CFRelease(err);
                }
                false
            }
        }
    }
}

fn tag(entry_id: &str) -> Cf {
    data(format!("net.atonline.libwallet.vault.{entry_id}").as_bytes())
}

/// The derived data key: HKDF-SHA256 over the ECDH x-coordinate, salted with
/// both public keys and bound to the entry id.
fn derive(shared: &[u8], eph_pub: &[u8], key_pub: &[u8], entry_id: &str) -> Zeroizing<[u8; 32]> {
    let mut salt = Vec::with_capacity(130);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(key_pub);
    let mut out = Zeroizing::new([0u8; 32]);
    purecrypto::kdf::hkdf::<purecrypto::hash::Sha256>(&salt, shared, format!("libwallet vault v1 {entry_id}").as_bytes(), &mut *out);
    out
}

impl Apple {
    fn provider_name(&self) -> &'static str {
        if self.enclave {
            "apple-se"
        } else {
            "apple-keychain"
        }
    }

    /// The query attributes every item operation shares.
    fn base_query(&self, t: &Cf) -> Vec<(CFTypeRef, CFTypeRef)> {
        let mut q = unsafe { vec![(kSecClass, kSecClassKey), (kSecAttrApplicationTag, t.0), (kSecAttrKeyClass, kSecAttrKeyClassPrivate)] };
        #[cfg(target_os = "macos")]
        unsafe {
            q.push((kSecUseDataProtectionKeychain, kCFBooleanTrue));
        }
        q
    }
}

impl SecureBackend for Apple {
    fn provider(&self) -> &str {
        self.provider_name()
    }

    fn capabilities(&self) -> Capabilities {
        if !self.entitled {
            return Capabilities { secure: false, hardware: false, biometry: "none".into(), provider: String::new(), reason: MISSING_ENTITLEMENT.into() };
        }
        pool(|| {
            let ctx = LaContext::new();
            let (biometry, can_auth) = match &ctx {
                Some(c) => {
                    let bio = c.can_evaluate(LAPolicyDeviceOwnerAuthenticationWithBiometrics);
                    let kind = match c.biometry_type() {
                        1 if bio => "touchID",
                        2 if bio => "faceID",
                        4 if bio => "opticID",
                        _ if c.can_evaluate(LAPolicyDeviceOwnerAuthentication) => "passcode",
                        _ => "none",
                    };
                    (kind, kind != "none")
                }
                None => ("none", false),
            };
            Capabilities {
                secure: true,
                hardware: self.enclave,
                biometry: biometry.into(),
                provider: self.provider_name().into(),
                reason: if can_auth { String::new() } else { "no passcode is set: entries requiring user presence cannot be used".into() },
            }
        })
    }

    fn seal_key(&self, entry_id: &str, policy: &Policy) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), String> {
        if !self.entitled {
            return Err(MISSING_ENTITLEMENT.into());
        }
        pool(|| unsafe {
            let t = tag(entry_id);
            let mut flags = 0usize;
            if self.enclave {
                flags |= kSecAccessControlPrivateKeyUsage;
            }
            if policy.user_presence {
                flags |= kSecAccessControlUserPresence;
            }
            let mut err: CFTypeRef = std::ptr::null();
            let acl = Cf::new(SecAccessControlCreateWithFlags(std::ptr::null(), kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &mut err))
                .ok_or_else(|| error_text(err, "access control"))?;
            let bits = 256i32;
            let n = Cf(CFNumberCreate(std::ptr::null(), kCFNumberSInt32Type, &bits as *const i32 as *const c_void));
            let priv_attrs = dict(&[(kSecAttrIsPermanent, kCFBooleanTrue), (kSecAttrApplicationTag, t.0), (kSecAttrAccessControl, acl.0)]);
            let mut p = vec![(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom), (kSecAttrKeySizeInBits, n.0), (kSecPrivateKeyAttrs, priv_attrs.0)];
            if self.enclave {
                p.push((kSecAttrTokenID, kSecAttrTokenIDSecureEnclave));
            }
            #[cfg(target_os = "macos")]
            p.push((kSecUseDataProtectionKeychain, kCFBooleanTrue));
            let params = dict(&p);
            let mut err: CFTypeRef = std::ptr::null();
            let key = Cf::new(SecKeyCreateRandomKey(params.0, &mut err)).ok_or_else(|| error_text(err, "creating the vault key"))?;
            let public = Cf::new(SecKeyCopyPublicKey(key.0)).ok_or("the vault key has no public key")?;
            let mut err: CFTypeRef = std::ptr::null();
            let pub_data = Cf::new(SecKeyCopyExternalRepresentation(public.0, &mut err)).ok_or_else(|| error_text(err, "exporting the public key"))?;
            let key_pub = data_bytes(&pub_data, false);
            let peer = EcdsaPublicKey::from_sec1(&key_pub).map_err(|e| format!("vault key: bad public key {e:?}"))?;
            let eph = EcdhPrivateKey::generate(&mut purecrypto::rng::OsRng);
            let eph_pub = eph.public_key().to_sec1();
            let shared = Zeroizing::new(eph.diffie_hellman(&peer).map_err(|e| format!("ecdh: {e:?}"))?);
            let dek = derive(&*shared, &eph_pub, &key_pub, entry_id);
            let mut wrapped = eph_pub.to_vec();
            wrapped.extend_from_slice(&key_pub);
            Ok((dek, wrapped))
        })
    }

    fn open_key(&self, entry_id: &str, wrapped: &[u8], reason: &str) -> Result<Zeroizing<[u8; 32]>, String> {
        if wrapped.len() != 130 {
            return Err("vault envelope: bad wrapped key".into());
        }
        let (eph_pub, key_pub) = wrapped.split_at(65);
        pool(|| unsafe {
            let ctx = LaContext::new().ok_or("LocalAuthentication is unavailable")?;
            ctx.set_reason(reason);
            let t = tag(entry_id);
            let mut q = self.base_query(&t);
            q.push((kSecReturnRef, kCFBooleanTrue));
            q.push((kSecUseAuthenticationContext, ctx.0 as CFTypeRef));
            let query = dict(&q);
            let mut out: CFTypeRef = std::ptr::null();
            match SecItemCopyMatching(query.0, &mut out) {
                0 => {}
                errSecItemNotFound => {
                    return Err("this vault entry's device key is gone (app reinstalled or device restored); restore the secret from its backup".into())
                }
                errSecMissingEntitlement => return Err(MISSING_ENTITLEMENT.into()),
                s => return Err(format!("reading the vault key failed (OSStatus {s})")),
            }
            let key = Cf::new(out).ok_or("reading the vault key returned nothing")?;
            let bits = 256i32;
            let n = Cf(CFNumberCreate(std::ptr::null(), kCFNumberSInt32Type, &bits as *const i32 as *const c_void));
            let attrs = dict(&[(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom), (kSecAttrKeyClass, kSecAttrKeyClassPublic), (kSecAttrKeySizeInBits, n.0)]);
            let eph_data = data(eph_pub);
            let mut err: CFTypeRef = std::ptr::null();
            let peer = Cf::new(SecKeyCreateWithData(eph_data.0, attrs.0, &mut err)).ok_or_else(|| error_text(err, "reading the envelope key"))?;
            let params = dict(&[]);
            // The gated step: Face ID / Touch ID / passcode when required.
            let mut err: CFTypeRef = std::ptr::null();
            let shared = Cf::new(SecKeyCopyKeyExchangeResult(key.0, kSecKeyAlgorithmECDHKeyExchangeStandard, peer.0, params.0, &mut err))
                .ok_or_else(|| error_text(err, "unlocking the vault key"))?;
            let shared = data_bytes(&shared, true);
            Ok(derive(&shared, eph_pub, key_pub, entry_id))
        })
    }

    fn delete_key(&self, entry_id: &str) -> Result<(), String> {
        pool(|| unsafe {
            let t = tag(entry_id);
            let query = dict(&self.base_query(&t));
            match SecItemDelete(query.0) {
                0 | errSecItemNotFound => Ok(()),
                s => Err(format!("deleting the vault key failed (OSStatus {s})")),
            }
        })
    }
}
