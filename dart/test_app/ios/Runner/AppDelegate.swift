import Flutter
import UIKit
import Libwallet

@main
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    let controller = window?.rootViewController as! FlutterViewController
    let channel = FlutterMethodChannel(
      name: "com.libwallet",
      binaryMessenger: controller.binaryMessenger
    )

    channel.setMethodCallHandler { (call: FlutterMethodCall, result: FlutterResult) in
      guard call.method == "makeSocket" else {
        result(FlutterMethodNotImplemented)
        return
      }
      if let args = call.arguments as? Dictionary<String, Any>,
         let path = args["path"] as? String,
         let appDir = args["appDir"] as? String {
        var error: NSError?
        LibwalletMakeSocket(appDir, path, &error)
        if let error = error {
          result(FlutterError(
            code: "MAKE_SOCKET_FAILED",
            message: error.localizedDescription,
            details: nil
          ))
          return
        }
        result(true)
      } else {
        result(FlutterError(
          code: "BAD_ARGS",
          message: "Missing path or appDir",
          details: nil
        ))
      }
    }

    GeneratedPluginRegistrant.register(with: self)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}
