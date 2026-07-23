// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Barnard",
    platforms: [
        .iOS("14.0")
    ],
    products: [
        .library(name: "Barnard", targets: ["Barnard"]),
        .library(name: "BarnardCore", targets: ["BarnardCore"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "Barnard",
            dependencies: ["BarnardCore"],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        ),
        .target(
            name: "BarnardCore",
            dependencies: []
        ),
        .testTarget(
            name: "BarnardTests",
            dependencies: ["Barnard"]
        ),
        .testTarget(
            name: "BarnardCoreTests",
            dependencies: ["BarnardCore"]
        )
    ]
)
