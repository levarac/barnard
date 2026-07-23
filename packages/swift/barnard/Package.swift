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
        .library(name: "BarnardCore", targets: ["BarnardCore"]),
        // Dynamic on purpose: this is the .so/.dylib consumed over the C ABI
        // by non-Swift hosts (Kotlin/JNI on Android, C, ...). See issue #78.
        .library(name: "BarnardCoreC", type: .dynamic, targets: ["BarnardCoreC"])
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
        .target(
            name: "BarnardCoreC",
            dependencies: ["BarnardCore"]
        ),
        .testTarget(
            name: "BarnardTests",
            dependencies: ["Barnard"]
        ),
        .testTarget(
            name: "BarnardCoreTests",
            dependencies: ["BarnardCore"]
        ),
        .testTarget(
            name: "BarnardCoreCTests",
            dependencies: ["BarnardCoreC"]
        )
    ]
)
