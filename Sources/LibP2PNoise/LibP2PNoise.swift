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

public struct NoiseUpgrader: SecurityUpgrader {

    public static let key: String = "/noise"
    let application: Application

    public func upgradeConnection(
        _ conn: Connection,
        position: ChannelPipeline.Position,
        securedPromise: EventLoopPromise<Connection.SecuredResult>
    ) -> EventLoopFuture<Void> {
        // Given a ChannelHandlerContext Configure and Install our HandshakeHandler onto the pipeline
        let handshake = InboundNoiseHandshakeHandler(
            peerID: conn.localPeer,
            mode: conn.mode,
            logger: conn.logger,
            secured: securedPromise,
            expectedRemotePeerID: conn.expectedRemotePeer?.b58String
        )

        return conn.channel.pipeline.addHandler(handshake, position: position)
    }

    public func printSelf() {
        application.logger.notice("Hi I'm the NOISE security protocol")
    }
}
