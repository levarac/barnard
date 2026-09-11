// swift-tools-version: 5.9

import PackageDescription

// SwiftPM only, matching examples/macos-lab-runner: this is a macOS CLI, not an Xcode project.
let package = Package(
    name: "VenueEnvelopeProducer",
    // 12.0 is the floor the Barnard package declares (barnard#192).
    platforms: [.macOS(.v12)],
    dependencies: [
        .package(path: "../../packages/swift/barnard")
    ],
    targets: [
        .target(
            name: "VenueEnvelopeProducerKit",
            dependencies: [
                .product(name: "Barnard", package: "barnard"),
                .product(name: "BarnardCore", package: "barnard")
            ]
        ),
        .executableTarget(
            name: "VenueEnvelopeProducer",
            dependencies: ["VenueEnvelopeProducerKit"]
        ),
        .testTarget(
            name: "VenueEnvelopeProducerKitTests",
            dependencies: [
                "VenueEnvelopeProducerKit",
                .product(name: "Barnard", package: "barnard"),
                .product(name: "BarnardCore", package: "barnard")
            ]
        )
    ]
)
