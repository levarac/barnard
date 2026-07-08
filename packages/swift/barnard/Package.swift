// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Barnard",
    platforms: [
        .iOS("14.0")
    ],
    products: [
        .library(name: "Barnard", targets: ["Barnard"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "Barnard",
            dependencies: [],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        ),
        .testTarget(
            name: "BarnardTests",
            dependencies: ["Barnard"]
        )
    ]
)
