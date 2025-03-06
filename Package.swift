// swift-tools-version:5.5
//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2025 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "swift-libp2p-noise",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LibP2PNoise",
            targets: ["LibP2PNoise"]
        )
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.

        // Swift NIO for all things networking
        .package(url: "https://github.com/apple/swift-nio-extras.git", .upToNextMajor(from: "1.0.0")),

        // LibP2P Core Modules
        .package(url: "https://github.com/swift-libp2p/swift-libp2p.git", .upToNextMinor(from: "0.2.0")),

        // Noise (Security Protocol)
        .package(url: "https://github.com/swift-libp2p/swift-noise.git", .upToNextMinor(from: "0.0.1")),
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
                .copy("Protobuf/NoiseHandshakePayload.proto")
            ]
        ),
        .testTarget(
            name: "LibP2PNoiseTests",
            dependencies: ["LibP2PNoise"]
        ),
    ]
)
