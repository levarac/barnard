// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "B005EnvelopeVerifier",
    platforms: [.macOS(.v12)],
    products: [
        .executable(name: "B005EnvelopeVerifier", targets: ["B005EnvelopeVerifier"])
    ],
    dependencies: [
        .package(path: "../../packages/swift/barnard")
    ],
    targets: [
        .target(
            name: "B005EnvelopeVerifierKit",
            dependencies: [
                .product(name: "Barnard", package: "barnard"),
                .product(name: "BarnardCore", package: "barnard")
            ]
        ),
        .executableTarget(
            name: "B005EnvelopeVerifier",
            dependencies: ["B005EnvelopeVerifierKit"]
        ),
        .testTarget(
            name: "B005EnvelopeVerifierTests",
            dependencies: ["B005EnvelopeVerifierKit"]
        )
    ]
)
