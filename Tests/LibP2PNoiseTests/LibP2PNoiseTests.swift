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

import LibP2P
import Testing

@testable import LibP2PNoise

@Suite("Libp2p Noise Tests")
struct LibP2PNoiseTests {
    @Test func testAppConfiguration() throws {
        let app = try Application(.detect())
        app.security.use(.noise)
        #expect(app.security.available.map { $0.description } == ["/noise"])
        let _ = try #require(app.security.upgrader(for: NoiseUpgrader.self))
        let _ = try #require(app.security.upgrader(forKey: NoiseUpgrader.key))
    }
}
