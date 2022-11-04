// swift-tools-version:5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-libp2p-noise",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LibP2PNoise",
            targets: ["LibP2PNoise"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        
        // Swift NIO for all things networking
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.0.0"),
        
        // LibP2P Core Modules
        .package(url: "https://github.com/swift-libp2p/swift-libp2p.git", .upToNextMajor(from: "0.1.0")),
        
        // Noise (Security Protocol)
        .package(url: "https://github.com/swift-libp2p/swift-noise.git", .upToNextMajor(from: "0.0.1")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "LibP2PNoise",
            dependencies: [
                .product(name: "NIOExtras", package: "swift-nio-extras"),
                .product(name: "LibP2P", package: "swift-libp2p"),
                .product(name: "Noise", package: "swift-noise"),
            ],
            resources: [
              .copy("Protobuf/NoiseHandshakePayload.proto"),
            ]),
        .testTarget(
            name: "LibP2PNoiseTests",
            dependencies: ["LibP2PNoise"]),
    ]
)
