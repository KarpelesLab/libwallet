package com.karpeleslabs.libwallet.libwallet_test_app

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import com.karpeleslabs.libwallet.Libwallet

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            "com.libwallet"
        ).setMethodCallHandler { call, result ->
            if (call.method == "makeSocket") {
                val path = call.argument<String>("path")
                val appDir = call.argument<String>("appDir")
                try {
                    Libwallet.showDebug()
                    Libwallet.makeSocket(appDir, path)
                    result.success(true)
                } catch (e: Exception) {
                    result.error("MAKE_SOCKET_FAILED", e.message, null)
                }
            } else {
                result.notImplemented()
            }
        }
    }
}
