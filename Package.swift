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
            path: "packages/swift/barnard/Sources/Barnard",
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        ),
        .target(
            name: "BarnardCore",
            dependencies: [],
            path: "packages/swift/barnard/Sources/BarnardCore"
        ),
        .target(
            name: "BarnardCoreC",
            dependencies: ["BarnardCore"],
            path: "packages/swift/barnard/Sources/BarnardCoreC"
        ),
        .testTarget(
            name: "BarnardTests",
            dependencies: ["Barnard"],
            path: "packages/swift/barnard/Tests/BarnardTests"
        ),
        .testTarget(
            name: "BarnardCoreTests",
            dependencies: ["BarnardCore"],
            path: "packages/swift/barnard/Tests/BarnardCoreTests"
        ),
        .testTarget(
            name: "BarnardCoreCTests",
            dependencies: ["BarnardCoreC"],
            path: "packages/swift/barnard/Tests/BarnardCoreCTests"
        )
    ]
)
