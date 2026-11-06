package com.karpeleslabs.libwallet

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding

/**
 * Registers the vault bridge with the engine: loads the libwallet native
 * library into the app's class loader (so Rust can call back into
 * [VaultBridge] over JNI) and tracks the current Activity, which
 * BiometricPrompt needs. No method channel: Dart talks to libwallet over FFI.
 */
class LibwalletPlugin : FlutterPlugin, ActivityAware {
    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        VaultBridge.init(binding.applicationContext)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {}

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        VaultBridge.activity = binding.activity
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        VaultBridge.activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        VaultBridge.activity = null
    }

    override fun onDetachedFromActivity() {
        VaultBridge.activity = null
    }
}
