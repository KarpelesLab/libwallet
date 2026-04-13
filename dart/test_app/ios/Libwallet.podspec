Pod::Spec.new do |s|
  s.name         = 'Libwallet'
  s.version      = '0.1.0'
  s.summary      = 'libwallet Go c-archive for FFI'
  s.homepage     = 'https://github.com/KarpelesLab/libwallet'
  s.license      = { :type => 'Proprietary' }
  s.author       = 'Karpeles Lab Inc'
  s.source       = { :path => '.' }
  s.ios.deployment_target = '13.0'
  # CI places liblibwallet.a here before building
  s.vendored_libraries = 'liblibwallet.a'
  # Force-load in the app target so the linker doesn't strip FFI symbols
  s.user_target_xcconfig = {
    'OTHER_LDFLAGS' => '-force_load $(PODS_ROOT)/../liblibwallet.a'
  }
  # CoreFoundation, Security, and resolv needed by Go runtime
  s.frameworks = 'CoreFoundation', 'Security'
  s.libraries = 'resolv'
end
