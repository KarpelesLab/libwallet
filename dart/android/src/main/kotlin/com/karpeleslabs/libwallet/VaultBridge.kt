package com.karpeleslabs.libwallet

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * The Android Keystore half of libwallet's vault (`android-keystore`
 * provider). Called from Rust over JNI — see
 * `rust/src/vault/platform/android.rs`; nothing in Dart calls this.
 *
 * Each vault entry owns one non-exportable RSA-2048 key (StrongBox when the
 * device has it, else the TEE). Rust generates the entry's 32-byte data key
 * and hands it here once to be encrypted with the key's public half
 * ([wrap] — public-key encryption, so it needs no authentication), and later
 * asks for it back ([unwrap]): the private-key decryption, which — when the
 * entry requires user presence — only the Keystore can perform after a
 * BiometricPrompt bound to that exact Cipher succeeds. The entry's secret
 * itself never comes here; only the data key passes through, and every
 * array holding it is zeroed after use.
 */
object VaultBridge {
    private const val TAG = "libwallet.vault"
    private const val STORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

    @Volatile private var context: Context? = null
    @Volatile var activity: Activity? = null
    @Volatile private var loaded = false

    /** The prompt currently on screen, if any (see [cancelPending]). */
    @Volatile private var pending: BiometricPrompt? = null

    /** How long an unanswered prompt may hold a libwallet worker. */
    private const val PROMPT_TIMEOUT_MINUTES = 5L

    /** Load libwallet into this class loader so JNI can resolve [nativeInit]. */
    fun init(ctx: Context) {
        context = ctx.applicationContext
        if (loaded) return
        // The Dart build hook bundles liblibwallet-android-<abi>-v<version>.so;
        // dev builds and the test app ship plain liblibwallet.so.
        val abi = when (Build.SUPPORTED_ABIS.firstOrNull()) {
            "arm64-v8a" -> "arm64"
            "armeabi-v7a" -> "arm"
            "x86_64" -> "x64"
            "x86" -> "x86"
            else -> null
        }
        val names = listOfNotNull(
            abi?.let { "libwallet-android-$it-v${BuildConfig.LIBWALLET_VERSION}" },
            "libwallet",
        )
        for (name in names) {
            try {
                System.loadLibrary(name)
                nativeInit()
                loaded = true
                return
            } catch (e: UnsatisfiedLinkError) {
                Log.d(TAG, "lib$name.so: ${e.message}")
            }
        }
        Log.w(TAG, "libwallet native library not found; secure vault entries are unavailable")
    }

    @JvmStatic private external fun nativeInit()

    private fun alias(id: String) = "libwallet.vault.$id"

    private fun keyStore(): KeyStore = KeyStore.getInstance(STORE).apply { load(null) }

    private fun oaep() = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    private fun hasStrongBox(ctx: Context) =
        Build.VERSION.SDK_INT >= 28 && ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /** `Vault:capabilities` as JSON. */
    @JvmStatic
    fun capabilities(): String {
        val ctx = context
        val o = JSONObject()
        if (ctx == null || Build.VERSION.SDK_INT < 23) {
            o.put("Secure", false).put("Hardware", false).put("Biometry", "none").put("Provider", "")
            o.put("Reason", if (ctx == null) "the libwallet Android plugin is not registered" else "Android 6.0 (API 23) or later is required")
            return o.toString()
        }
        val bio = BiometricManager.from(ctx).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        val keyguard = ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val biometry = when {
            bio -> "biometric"
            keyguard.isDeviceSecure -> "passcode"
            else -> "none"
        }
        o.put("Secure", true)
        o.put("Hardware", hasStrongBox(ctx) || probeHardware())
        o.put("Biometry", biometry)
        o.put("Provider", "android-keystore")
        if (biometry == "none") o.put("Reason", "no screen lock is set: entries requiring user presence cannot be created")
        return o.toString()
    }

    @Volatile private var hardware: Boolean? = null

    /** Whether Keystore keys land in secure hardware (TEE): one probe key. */
    private fun probeHardware(): Boolean {
        hardware?.let { return it }
        val probe = alias("probe")
        val result = try {
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, STORE)
            kpg.initialize(KeyGenParameterSpec.Builder(probe, KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).build())
            val pair = kpg.generateKeyPair()
            val info = KeyFactory.getInstance(pair.private.algorithm, STORE).getKeySpec(pair.private, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= 31) {
                info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                @Suppress("DEPRECATION")
                info.isInsideSecureHardware
            }
        } catch (e: Exception) {
            false
        } finally {
            try { keyStore().deleteEntry(probe) } catch (_: Exception) {}
        }
        hardware = result
        return result
    }

    /** Create entry [id]'s key; with [userPresence], each use needs auth. */
    @JvmStatic
    fun generateKey(id: String, userPresence: Boolean) {
        val ctx = context ?: throw IllegalStateException("the libwallet Android plugin is not registered")
        // "Unlocked device required" means nothing without a secure lock
        // screen, and some Keystore versions refuse the key outright then.
        val secured = (ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias(id), KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            if (userPresence) {
                b.setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= 30) {
                    b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                }
                // Losing every vaulted secret when a fingerprint is added is
                // worse for a wallet than the attack this would prevent.
                if (Build.VERSION.SDK_INT >= 24) b.setInvalidatedByBiometricEnrollment(false)
            }
            if (Build.VERSION.SDK_INT >= 28) {
                if (secured) b.setUnlockedDeviceRequired(true)
                if (strongBox) b.setIsStrongBoxBacked(true)
            }
            return b.build()
        }
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, STORE)
        if (hasStrongBox(ctx)) {
            try {
                kpg.initialize(spec(true))
                kpg.generateKeyPair()
                return
            } catch (e: StrongBoxUnavailableException) {
                Log.i(TAG, "StrongBox refused the key, using the TEE")
            }
        }
        try {
            kpg.initialize(spec(false))
            kpg.generateKeyPair()
        } catch (e: Exception) {
            throw IllegalStateException("creating the vault key failed: ${causes(e)}", e)
        }
    }

    /** An exception and its causes, for an error message that says why. */
    private fun causes(e: Throwable): String =
        generateSequence(e) { it.cause }.take(4).joinToString(": ") { it.message ?: it.javaClass.simpleName }

    /** Encrypt [dek] to entry [id]'s public key (no authentication needed). */
    @JvmStatic
    fun wrap(id: String, dek: ByteArray): ByteArray {
        val cert = keyStore().getCertificate(alias(id)) ?: throw IllegalStateException("vault key $id not found")
        // A software copy of the public key: public-key encryption needs no
        // Keystore round trip (or authentication).
        val pub = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(cert.publicKey.encoded))
        val c = Cipher.getInstance(TRANSFORMATION)
        c.init(Cipher.ENCRYPT_MODE, pub, oaep())
        return c.doFinal(dek)
    }

    /**
     * Decrypt entry [id]'s data key, showing BiometricPrompt titled [reason]
     * first when the key requires it. Blocks the calling (libwallet worker)
     * thread until the user answers. Throws "user cancelled" on cancel.
     */
    @JvmStatic
    fun unwrap(id: String, wrapped: ByteArray, reason: String): ByteArray {
        val key = keyStore().getKey(alias(id), null) as? PrivateKey
            ?: throw IllegalStateException("this vault entry's device key is gone (app reinstalled or data cleared); restore the secret from its backup")
        val info = KeyFactory.getInstance(key.algorithm, STORE).getKeySpec(key, KeyInfo::class.java)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, oaep())
        if (!info.isUserAuthenticationRequired) return cipher.doFinal(wrapped)

        val act = activity as? FragmentActivity
            ?: throw IllegalStateException("a user-presence vault entry needs a FragmentActivity for BiometricPrompt: make MainActivity extend FlutterFragmentActivity")
        val latch = CountDownLatch(1)
        var result: ByteArray? = null
        var error: String? = null
        act.runOnUiThread {
            try {
                val prompt = BiometricPrompt(act, ContextCompat.getMainExecutor(act), object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        try {
                            result = r.cryptoObject?.cipher?.doFinal(wrapped) ?: throw IllegalStateException("no cipher after authentication")
                        } catch (e: Exception) {
                            error = "unlocking the vault key failed: ${e.message}"
                        }
                        latch.countDown()
                    }

                    override fun onAuthenticationError(code: Int, msg: CharSequence) {
                        error = when (code) {
                            BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED -> "user cancelled"
                            else -> "authentication failed: $msg"
                        }
                        latch.countDown()
                    }
                })
                val builder = BiometricPrompt.PromptInfo.Builder().setTitle(reason)
                if (Build.VERSION.SDK_INT >= 30) {
                    builder.setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                } else {
                    builder.setAllowedAuthenticators(BIOMETRIC_STRONG).setNegativeButtonText("Cancel")
                }
                pending = prompt
                prompt.authenticate(builder.build(), BiometricPrompt.CryptoObject(cipher))
            } catch (e: Exception) {
                error = "could not show the authentication prompt: ${e.message}"
                latch.countDown()
            }
        }
        val answered = latch.await(PROMPT_TIMEOUT_MINUTES, TimeUnit.MINUTES)
        pending = null
        if (!answered) {
            cancelPending()
            throw IllegalStateException("timed out waiting for authentication")
        }
        error?.let { throw IllegalStateException(it) }
        return result!!
    }

    /**
     * Dismiss the prompt on screen, if any; its caller gets "user cancelled".
     * Rust calls this when the vault locks (Vault:lock, app backgrounded).
     */
    @JvmStatic
    fun cancelPending() {
        val p = pending ?: return
        activity?.runOnUiThread { p.cancelAuthentication() }
    }

    /** Destroy entry [id]'s key (idempotent). */
    @JvmStatic
    fun deleteKey(id: String) {
        keyStore().deleteEntry(alias(id))
    }
}
