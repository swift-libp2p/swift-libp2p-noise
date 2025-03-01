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

import Noise
import Crypto
import NIOCore
import Logging
import LibP2PCore

// Noise XX Outbound Data Encrypter
internal final class OutboundNoiseEncryptionHandler: ChannelOutboundHandler {
    public typealias OutboundIn = ByteBuffer //Plaintext data
    public typealias OutboundOut = ByteBuffer //Encrypted Ciphertext data
    
    /// Do we need to encrypt and decrypt with AD? Or can we just use the CipherState without the running Hash (h)?
    /// The JS implementation just passes an empty buffer into the AD. Let's try the same...
    private let cs:Noise.CipherState
    private var logger:Logger
    
    public init(cipherState:Noise.CipherState, logger:Logger) {
        self.logger = logger 
        self.cs = cipherState
        
        self.logger[metadataKey: "NOISE"] = .string("Encrypter")
    }
    
    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let bufferIn = unwrapOutboundIn(data)

        do {

            let ciphertext = try cs.encrypt(plaintext: Array(bufferIn.readableBytesView))

            let bufferOut = context.channel.allocator.buffer(bytes: ciphertext)

            logger.trace("--- 🔒 Outbound Data Encryption Complete 🔒 ---")
            context.write( wrapOutboundOut(bufferOut), promise: nil)

        } catch {

            // Do we propogate the error with a fireErrorCaught() ??
            logger.error("Error: \(error)")
            context.close(promise: nil)

        }
    }
    
    // Flush it out. This can make use of gathering writes if multiple buffers are pending
    public func channelWriteComplete(context: ChannelHandlerContext) {
        //logger.info("Write Complete")
        context.flush()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Error: \(error)")
        
        context.close(promise: nil)
    }
}
