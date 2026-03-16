#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint barnard.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'barnard'
  s.version          = '0.0.1-alpha.1'
  s.summary          = 'Barnard BLE Transport for Flutter (GATT-first RPID).'
  s.description      = <<-DESC
Barnard BLE Transport for Flutter (GATT-first RPID).
                       DESC
  s.homepage         = 'https://github.com/thegreeting/barnard'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Your Company' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.source_files = 'barnard/Sources/barnard/**/*'
  s.dependency 'Flutter'
  # NOTE: Minimum iOS version is 14.0 for CryptoKit HKDF support.
  s.platform = :ios, '14.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  s.resource_bundles = {'barnard_privacy' => ['barnard/Sources/barnard/PrivacyInfo.xcprivacy']}
end
