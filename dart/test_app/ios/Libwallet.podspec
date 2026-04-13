Pod::Spec.new do |s|
  s.name         = 'Libwallet'
  s.version      = '0.1.0'
  s.summary      = 'libwallet Go library built via gomobile'
  s.homepage     = 'https://github.com/KarpelesLab/libwallet'
  s.license      = { :type => 'Proprietary' }
  s.author       = 'Karpeles Lab Inc'
  s.source       = { :path => '.' }
  s.ios.deployment_target = '13.0'
  s.vendored_frameworks = 'Libwallet.xcframework'
end
