// swift-tools-version: 6.4

import PackageDescription

let package = Package(
  name: "BarnardAndroidLogicProbe",
  products: [
    .library(
      name: "BarnardAndroidLogicProbe",
      type: .dynamic,
      targets: ["BarnardAndroidLogicProbe"]
    )
  ],
  targets: [
    .target(name: "BarnardAndroidLogicProbe"),
    .testTarget(
      name: "BarnardAndroidLogicProbeTests",
      dependencies: ["BarnardAndroidLogicProbe"]
    ),
  ]
)
