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
            name: "CSecp256k1",
            exclude: [
                "vendor/src/asm",
                "vendor/src/bench.c", "vendor/src/bench_ecmult.c",
                "vendor/src/bench_internal.c", "vendor/src/ctime_tests.c",
                "vendor/src/precompute_ecmult.c", "vendor/src/precompute_ecmult_gen.c",
                "vendor/src/secp256k1.c", "vendor/src/tests.c",
                "vendor/src/tests_exhaustive.c"
            ],
            cSettings: [.define("ENABLE_MODULE_RECOVERY")]
        ),
        .target(
            name: "Barnard",
            dependencies: ["BarnardCore"],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        ),
        .target(
            name: "BarnardCore",
            dependencies: ["CSecp256k1"],
            // Explicit backend selection: mirrored builds without this define
            // (Flutter/CocoaPods) compile the pure-Swift path.
            swiftSettings: [.define("BARNARD_LIBSECP256K1")]
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
            dependencies: ["BarnardCore", "BarnardCoreC"]
        )
    ]
)
