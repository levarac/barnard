// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "barnard",
    platforms: [
        .iOS("14.0")
    ],
    products: [
        .library(name: "barnard", targets: ["barnard"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "barnard",
            dependencies: [],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        )
    ]
)
