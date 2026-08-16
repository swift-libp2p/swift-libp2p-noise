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
internal final class OutboundNoiseEncryptionHandler: ChannelOutboundHandler, Sendable {
    public typealias OutboundIn = ByteBuffer  //Plaintext data
    public typealias OutboundOut = ByteBuffer  //Encrypted Ciphertext data

    /// Do we need to encrypt and decrypt with AD? Or can we just use the CipherState without the running Hash (h)?
    /// The JS implementation just passes an empty buffer into the AD. Let's try the same...
    private let cs: Noise.CipherState
    private let logger: Logger

    /// Maximum plaintext we can seal into a single Noise transport message.
    ///
    /// All Noise messages MUST be <= 65535 bytes on the wire.
    /// Subtracting the 16-byte AEAD tag (Poly1305 / GCM) leaves 65519 bytes of plaintext per message.
    /// Larger writes are split across multiple transport messages.
    private static let maxTransportPlaintext = 65_535 - 16

    public init(cipherState: Noise.CipherState, logger: Logger) {
        var logger = logger
        logger[metadataKey: "NOISE"] = .string("Encrypter")

        self.logger = logger
        self.cs = cipherState
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var bufferIn = unwrapOutboundIn(data)

        do {

            // Split writes larger than a single Noise message into multiple writes.
            while bufferIn.readableBytes > Self.maxTransportPlaintext {
                let chunk = bufferIn.readSlice(length: Self.maxTransportPlaintext)!
                let ciphertext = try cs.encrypt(plaintext: Array(chunk.readableBytesView))
                // dont pass the write promise into these writes (save it for the final write below)
                context.write(wrapOutboundOut(context.channel.allocator.buffer(bytes: ciphertext)), promise: nil)
            }

            let ciphertext = try cs.encrypt(plaintext: Array(bufferIn.readableBytesView))
            let bufferOut = context.channel.allocator.buffer(bytes: ciphertext)

            logger.trace("--- 🔒 Outbound Data Encryption Complete 🔒 ---")
            context.write(wrapOutboundOut(bufferOut), promise: promise)

        } catch {

            logger.error("Error: \(error)")
            // Fail the caller's promise so awaited writes are notified, then tear down the channel.
            promise?.fail(error)
            context.close(promise: nil)

        }
    }

    // Flush it out. This can make use of gathering writes if multiple buffers are pending
    public func channelWriteComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Error: \(error)")

        context.close(promise: nil)
    }
}
