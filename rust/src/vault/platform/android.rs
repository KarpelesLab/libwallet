//! Android backend: the Android Keystore, through the Flutter plugin's Kotlin
//! `VaultBridge` (dart/android/…/VaultBridge.kt), called over JNI.
//!
//! Each entry owns a non-exportable RSA-2048 Keystore key (StrongBox when
//! present, else the TEE). Rust generates the entry's 32-byte data key and has
//! the bridge encrypt it to the key's public half (RSA-OAEP: no
//! authentication, no prompt). Releasing it is the private-key decryption,
//! which for a user-presence entry the Keystore only performs after a
//! BiometricPrompt bound to that Cipher succeeds. Only the data key crosses
//! into the JVM; both Java arrays that carry it are zeroed here after use.
//!
//! The bridge reaches us when `VaultBridge.init` loads this library
//! (`JNI_OnLoad` records the VM) and calls `nativeInit` (we keep a global
//! reference to the class: a worker thread's `FindClass` would only see the
//! system class loader). Without the plugin — a plain Dart VM — there is no
//! backend and `Vault:capabilities` says why.

use std::sync::OnceLock;

use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jint, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM};
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::zeroize::Zeroizing;

use super::{Capabilities, Policy, SecureBackend};

static VM: OnceLock<JavaVM> = OnceLock::new();
static BRIDGE: OnceLock<GlobalRef> = OnceLock::new();

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    if let Ok(vm) = unsafe { JavaVM::from_raw(vm) } {
        let _ = VM.set(vm);
    }
    JNI_VERSION_1_6
}

#[no_mangle]
pub extern "system" fn Java_com_karpeleslabs_libwallet_VaultBridge_nativeInit(mut env: JNIEnv, class: JClass) {
    if VM.get().is_none() {
        if let Ok(vm) = env.get_java_vm() {
            let _ = VM.set(vm);
        }
    }
    if let Ok(g) = env.new_global_ref(&class) {
        let _ = BRIDGE.set(g);
    }
}

struct Android;

static B: Android = Android;

pub(super) fn backend() -> Option<&'static dyn SecureBackend> {
    Some(&B)
}

/// Run `f` with a JNI env on this thread and the bridge class; a pending Java
/// exception becomes an `Err` with its message.
fn with_bridge<R>(f: impl FnOnce(&mut JNIEnv, &JClass) -> jni::errors::Result<R>) -> Result<R, String> {
    let (vm, bridge) = match (VM.get(), BRIDGE.get()) {
        (Some(v), Some(b)) => (v, b),
        _ => return Err(NOT_REGISTERED.into()),
    };
    let mut env = vm.attach_current_thread().map_err(|e| format!("jni attach: {e}"))?;
    let class: &JClass = bridge.as_obj().into();
    match f(&mut env, class) {
        Ok(r) => Ok(r),
        Err(jni::errors::Error::JavaException) => Err(take_exception(&mut env)),
        Err(e) => Err(format!("jni: {e}")),
    }
}

const NOT_REGISTERED: &str = "the libwallet Android plugin is not registered (run inside a Flutter app with the libwallet package)";

/// Clear the pending exception and return its message.
fn take_exception(env: &mut JNIEnv) -> String {
    let Ok(ex) = env.exception_occurred() else { return "java exception".into() };
    let _ = env.exception_clear();
    let msg = env
        .call_method(&ex, "getMessage", "()Ljava/lang/String;", &[])
        .and_then(|v| v.l())
        .ok()
        .filter(|o| !o.is_null())
        .and_then(|o| env.get_string(&JString::from(o)).ok().map(String::from));
    let _ = env.exception_clear();
    msg.unwrap_or_else(|| "java exception".into())
}

/// Copy a Java byte[] out and zero it.
fn take_bytes(env: &mut JNIEnv, arr: &JByteArray) -> jni::errors::Result<Zeroizing<Vec<u8>>> {
    let out = Zeroizing::new(env.convert_byte_array(arr)?);
    let zeros = vec![0i8; out.len()];
    env.set_byte_array_region(arr, 0, &zeros)?;
    Ok(out)
}

fn alias_arg<'a>(env: &mut JNIEnv<'a>, id: &str) -> jni::errors::Result<JObject<'a>> {
    Ok(env.new_string(id)?.into())
}

impl SecureBackend for Android {
    fn provider(&self) -> &str {
        "android-keystore"
    }

    fn capabilities(&self) -> Capabilities {
        let json = with_bridge(|env, cls| {
            let s = env.call_static_method(cls, "capabilities", "()Ljava/lang/String;", &[])?.l()?;
            Ok(String::from(env.get_string(&JString::from(s))?))
        });
        match json.and_then(|j| serde_json::from_str::<serde_json::Value>(&j).map_err(|e| e.to_string())) {
            Ok(v) => Capabilities {
                secure: v["Secure"].as_bool().unwrap_or(false),
                hardware: v["Hardware"].as_bool().unwrap_or(false),
                biometry: v["Biometry"].as_str().unwrap_or("none").into(),
                provider: v["Provider"].as_str().unwrap_or("").into(),
                reason: v["Reason"].as_str().unwrap_or("").into(),
            },
            Err(reason) => Capabilities { secure: false, hardware: false, biometry: "none".into(), provider: String::new(), reason },
        }
    }

    fn seal_key(&self, entry_id: &str, policy: &Policy) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), String> {
        let mut dek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *dek);
        // What `wrap` threw, if it did: taken (and cleared) inside the closure,
        // because no JNI call but the exception ones may be made while an
        // exception is pending, and the dek copy is zeroed with one.
        let mut thrown: Option<String> = None;
        let wrapped = with_bridge(|env, cls| {
            let id = alias_arg(env, entry_id)?;
            env.call_static_method(cls, "generateKey", "(Ljava/lang/String;Z)V", &[JValue::Object(&id), JValue::Bool(policy.user_presence as u8)])?;
            let arg = env.byte_array_from_slice(&*dek)?;
            let out = env.call_static_method(cls, "wrap", "(Ljava/lang/String;[B)[B", &[JValue::Object(&id), JValue::Object(&arg)]);
            if matches!(out, Err(jni::errors::Error::JavaException)) {
                thrown = Some(take_exception(env));
            }
            // Zero our copy of the dek in the JVM whatever happened.
            let zeros = [0i8; 32];
            let _ = env.set_byte_array_region(&arg, 0, &zeros);
            let out = JByteArray::from(out?.l()?);
            env.convert_byte_array(&out)
        });
        let wrapped = match (wrapped, thrown) {
            (Ok(w), _) => w,
            (Err(_), Some(msg)) => return Err(msg),
            (Err(e), None) => return Err(e),
        };
        Ok((dek, wrapped))
    }

    fn open_key(&self, entry_id: &str, wrapped: &[u8], reason: &str) -> Result<Zeroizing<[u8; 32]>, String> {
        let bytes = with_bridge(|env, cls| {
            let id = alias_arg(env, entry_id)?;
            let w = env.byte_array_from_slice(wrapped)?;
            let r: JObject = env.new_string(reason)?.into();
            let out = env.call_static_method(cls, "unwrap", "(Ljava/lang/String;[BLjava/lang/String;)[B", &[JValue::Object(&id), JValue::Object(&w), JValue::Object(&r)])?;
            take_bytes(env, &JByteArray::from(out.l()?))
        })?;
        let dek: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "vault key: unexpected data key size".to_string())?;
        Ok(Zeroizing::new(dek))
    }

    fn cancel_prompts(&self) {
        let _ = with_bridge(|env, cls| {
            env.call_static_method(cls, "cancelPending", "()V", &[])?;
            Ok(())
        });
    }

    fn delete_key(&self, entry_id: &str) -> Result<(), String> {
        with_bridge(|env, cls| {
            let id = alias_arg(env, entry_id)?;
            env.call_static_method(cls, "deleteKey", "(Ljava/lang/String;)V", &[JValue::Object(&id)])?;
            Ok(())
        })
    }
}
