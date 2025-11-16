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

import Logging
import NIOCore
import Noise

// Noise XX Outbound Data Encrypter
internal final class InboundNoiseDecryptionHandler: ChannelInboundHandler, Sendable {
    public typealias InboundIn = ByteBuffer  //Encrypted ciphertext data
    public typealias InboundOut = ByteBuffer  //Plaintext data

    /// Do we need to encrypt and decrypt with AD? Or can we just use the CipherState without the running Hash (h)?
    /// The JS implementation just passes an empty buffer into the AD. Let's try the same...
    private let cs: Noise.CipherState
    private let logger: Logger

    public init(cipherState: Noise.CipherState, logger: Logger) {
        var logger = logger
        logger[metadataKey: "NOISE"] = .string("Decrypter")

        self.logger = logger
        self.cs = cipherState
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bufferIn = unwrapInboundIn(data)

        do {

            let plaintext = try cs.decrypt(ciphertext: Array(bufferIn.readableBytesView))

            let bufferOut = context.channel.allocator.buffer(bytes: plaintext)

            logger.trace("--- 🔓 Inbound Data Decryption Complete 🔓 ---")
            context.fireChannelRead(wrapInboundOut(bufferOut))

        } catch {

            // Do we propogate the error with a fireErrorCaught() ??
            logger.error("Error: \(error)")
            context.close(promise: nil)

        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        // Is this what we actually want to do??
        context.fireChannelReadComplete()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Error: \(error)")

        context.close(promise: nil)
    }
}
