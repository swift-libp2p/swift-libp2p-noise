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

import Crypto
import Foundation
import LibP2PCore
import Logging
import NIOCore
import NIOExtras
import Noise
import PeerID

public enum NoiseErrors: Error {
    case invalidNoiseHandshakeMessage
    case remotePeerMismatch
    case invalidSignature
    case failedToInstantiateCipherStates
    case invalidIdentityKey
    case invalidRemoteStaticKey
    case invalidSignaturePrefix
}

/// Noise XX
///
/// Should we have a seperate Handler responsible for the Handshake that installs the Encrypter and Decrypter once complete?
internal final class InboundNoiseHandshakeHandler: ChannelInboundHandler, RemovableChannelHandler {
    public typealias InboundIn = ByteBuffer  //Noise Handshake Message, or Ciphertext post handkshake
    public typealias InboundOut = ByteBuffer  //Plaintext post handshake
    public typealias OutboundOut = ByteBuffer  //Noise Handshake Message

    private let channelSecuredCallback: EventLoopPromise<Connection.SecuredResult>

    private let payloadSigPrefix = "noise-libp2p-static-key:"

    private enum State {
        case handshakeInProgress
        case secured
    }
    private var state: State

    private let handshakeState: Noise.HandshakeState
    private let staticNoiseKey: Curve25519.KeyAgreement.PrivateKey

    private var logger: Logger
    private let localPeerInfo: PeerID
    private var remotePeerInfo: PeerID? = nil
    private var expectedRemotePeerID: String? = nil
    private let mode: LibP2PCore.Mode

    private var messagesWritten: Int = 0
    private var lengthEncoder: LengthFieldPrepender
    private var lengthDecoder: LengthFieldBasedFrameDecoder

    private var shouldWarn: Bool = false

    /// - TODO: Include a param for the Remote PeerID when we're the dialer so we can compare the NoiseHandshakePayload public key to the peer dialed.
    public init(
        peerID: PeerID,
        mode: LibP2PCore.Mode,
        logger: Logger,
        secured: EventLoopPromise<Connection.SecuredResult>,
        expectedRemotePeerID: String?
    ) {
        self.localPeerInfo = peerID
        self.remotePeerInfo = nil
        self.expectedRemotePeerID = expectedRemotePeerID
        self.state = .handshakeInProgress
        self.logger = logger
        self.mode = mode

        // An MSS Callback that we can use to notify it once the handshake is complete and the channel is secured
        self.channelSecuredCallback = secured

        // Do we need to hold an external reference the static noise key? Or should we just let it reside in the HandshakeState?
        self.staticNoiseKey = Curve25519.KeyAgreement.PrivateKey()

        // Prepare our HandshakeState
        self.handshakeState = try! Noise.HandshakeState(
            config:
                Noise.Config(
                    cipherSuite: Noise.CipherSuite(
                        keyCurve: .ed25519,
                        cipher: .ChaChaPoly1305,
                        hashFunction: .sha256
                    ),
                    handshake: mode == .initiator ? .XX_Initiator : .XX_Responder,
                    staticKeypair: staticNoiseKey
                )
        )

        self.lengthDecoder = LengthFieldBasedFrameDecoder(lengthFieldBitLength: .twoBytes, lengthFieldEndianness: .big)
        self.lengthEncoder = LengthFieldPrepender(lengthFieldBitLength: .twoBytes, lengthFieldEndianness: .big)

        self.logger[metadataKey: "NOISE"] = .string("\(mode.rawValue)")
    }

    public func handlerAdded(context: ChannelHandlerContext) {

        // NOISE Requires 2 byte, big endian length based frame encoding/decoding
        // Lets, install these handlers now before we start sending / receiving messages...
        let additionalHandlers: [ChannelHandler] = [
            // Length Based Prefix Decoder (splits/groups incoming messages by a message length prefix)
            ByteToMessageHandler(self.lengthDecoder),
            self.lengthEncoder,
        ]
        logger.trace("Installing Additional Handlers: \(additionalHandlers.map { "\($0)" }.joined(separator: "\n") )")
        let _ = context.pipeline.addHandlers(additionalHandlers, position: .before(self)).whenSuccess { _ in
            self.logger.trace("Installed our Length Based Frame Encoder / Decoder Handlers")

            //If we're the initiator, then we should take this opportunity to kick off the XX handshake by sending the first message...
            if self.mode == .initiator {
                self.logger.trace(
                    "Handler Added: Because we're the initiator, we're kicking off the handshake by sending Message A"
                )

                // Prepare our first message. The first message doesn't include our HandshakePaylad due to it being sent in plaintext
                let (msg0, _, _) = try! self.handshakeState.writeMessage(payload: [])

                // Increment our local message counter
                self.messagesWritten += 1

                // Send our first handshake message off to the remote peer...
                context.writeAndFlush(self.wrapOutboundOut(context.channel.allocator.buffer(bytes: msg0)), promise: nil)
            }
        }
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch state {
        case .handshakeInProgress:
            // Parse the incomming data and handle it accordingly
            switch mode {
            case .initiator:
                switch messagesWritten {
                case 1:
                    do {
                        // Parse Message B
                        let d = unwrapInboundIn(data)

                        // Consume Message B
                        let (payload, _, _) = try self.handshakeState.readMessage(Array(d.readableBytesView))

                        // Verify the responders(listeners) signature payload with their Public PeerID
                        guard payload.count > 0 else {
                            logger.error(
                                "Invalid Noise Handshake Message Received. Aborting Handshake and closing connection..."
                            )
                            return abort(context: context, error: NoiseErrors.invalidNoiseHandshakeMessage)
                        }

                        // Reconstruct Listeners Handshake Payload
                        //logger.info("Attempting to decode NoiseHandshakePayload")
                        let lnhp = try NoiseHandshakePayload(contiguousBytes: payload)
                        //logger.info("Attempting to instantiate Remote PeerID from NoiseHandshakePayload IdentityKey")
                        //logger.info("Identity Key: \(lnhp.identityKey.asString(base: .base16))")

                        let rpi = try PeerID(marshaledPublicKey: lnhp.identityKey)
                        //logger.info("Remote Peer: \(rpi.b58String)")

                        // This is kinda redundant but just to make sure we parsed/reconstructed the Remote PeerID correctly...
                        // if (try? rpi.marshalPublicKey()) == lnhp.identityKey.bytes {
                        //     logger.info("The remote PeerID that we instantiated matches the identity key we were sent")
                        // }

                        // If we know who we dialed, then compare the returned identity public key with the p2p peer ID that we expect.
                        // - Note: It seems that only a few nodes abide by this rule. The libp2p ipfs bootstrap nodes seem to
                        //   but most of the peers discovered throughout the kad dht fail this check (might be due to old peer records)
                        if let remote = remotePeerInfo {
                            guard remote.b58String == rpi.b58String else {
                                //logger.error("Listeners Noise Handshake Identity Key does not match the Peer we dialed. Aborting Handshake and closing connection... (RemotePeerInfo)")
                                //logger.error("\(remote.b58String) =/= \(rpi.b58String)" )
                                return abort(context: context, error: NoiseErrors.remotePeerMismatch)
                            }
                            logger.trace(
                                "Validated the dialed peer! \(rpi.b58String) is in fact who they claim to be..."
                            )
                        } else if let remoteID = expectedRemotePeerID, let rid = try? PeerID(cid: remoteID) {
                            guard rid.id == rpi.id else {
                                logger.error(
                                    "Listeners Noise Handshake Identity Key does not match the Peer we dialed. Aborting Handshake and closing connection...(ExpectedRemotePeerID)"
                                )
                                logger.error("Expected: b58: \(rid.b58String), cid: \(rid.cidString)")
                                logger.error("=/=")
                                logger.error("Provided: b58: \(rpi.b58String), cid: \(rpi.cidString)")
                                logger.error(
                                    "Expected Key Type: \(rid.type), \(String(describing: rid.keyPair?.keyType))"
                                )
                                logger.error(
                                    "Provided Key Type: \(rpi.type), \(String(describing: rpi.keyPair?.keyType))"
                                )
                                return abort(context: context, error: NoiseErrors.remotePeerMismatch)
                            }
                            logger.trace(
                                "Validated the dialed peer! \(rpi.b58String) is in fact who they claim to be..."
                            )
                        } else {
                            logger.warning(
                                "Skipping Remote PeerID IdentityKey Check due to remote peer info being nil..."
                            )
                            self.shouldWarn = true
                        }

                        // Construct the data we expect the signature to be valid for
                        let expectedSignedData =
                            try! payloadSigPrefix.data(using: .utf8)!
                            + self.handshakeState.peerStatic().rawRepresentation
                        //logger.info("Checking identitySig against the PeerID we instantiated to verify signature")
                        guard try rpi.isValidSignature(lnhp.identitySig, for: expectedSignedData) else {
                            logger.error(
                                "Listeners Noise Handshake Signature Verification failed. Aborting Handshake and closing connection..."
                            )
                            return abort(context: context, error: NoiseErrors.invalidSignature)
                        }

                        // If we made it this far, then everything checks out!
                        //logger.info("Everything Checks Out. Lets proceed with writting Message C")

                        // Construct Initiators Handshake Signature Payload
                        let nhp = try createPayload()

                        // Write Message C (including our signed handshake payload)
                        //logger.info("Writting Message C")
                        let (msg2, cs1, cs2) = try self.handshakeState.writeMessage(payload: nhp)

                        // Ensure we have our split CipherStates
                        guard let outboundCipherState = cs1, let inboundCipherState = cs2 else {
                            logger.error(
                                "Failed to instantiate CipherStates after processing message C. Aborting Handshake and closing connection..."
                            )
                            return abort(context: context, error: NoiseErrors.failedToInstantiateCipherStates)
                        }

                        context.writeAndFlush(
                            wrapOutboundOut(context.channel.allocator.buffer(bytes: msg2)),
                            promise: nil
                        )

                        // Upgrade the channel with the encrypter / decrypter handlers
                        self.state = .secured
                        self.remotePeerInfo = rpi

                        logger.trace("Channel Secured! Attempting to install Encryption and Decryption Handlers")

                        // Now that our Handshake has completed successfully we
                        // - install our Encyrption & Decryption handlers with their respective CipherStates
                        // - remove this handler from the pipeline
                        // - complete our channelSecureCallback so our Channel is notified of the result
                        channelSecuredCallback.completeWith(
                            //Listener uses cs1 for inbound, Initiator uses cs2 for inbound
                            //Listener uses cs2 for outbound, Initiator uses cs1 for outbound
                            //installEncryptionHandlersAndRemoveSelf(context, inboundCipherState: cs2!, outboundCipherState: cs1!)
                            context.pipeline.addHandlers(
                                [
                                    //Inbound Decryption Handler
                                    //Listener uses cs1 for inbound, Initiator uses cs2 for inbound
                                    InboundNoiseDecryptionHandler(cipherState: inboundCipherState, logger: self.logger),
                                    //Outbound Encryption Handler
                                    //Listener uses cs2 for outbound, Initiator uses cs1 for outbound
                                    OutboundNoiseEncryptionHandler(
                                        cipherState: outboundCipherState,
                                        logger: self.logger
                                    ),
                                ],
                                position: .after(self)
                            ).flatMap { _ -> EventLoopFuture<Connection.SecuredResult> in
                                self.logger.trace(
                                    "Encryption and Decryption Handlers Installed! Uninstalling self (handshake handler)"
                                )
                                return context.pipeline.removeHandler(self).map { _ -> Connection.SecuredResult in
                                    self.logger.debug("Channel Secured 🔐")
                                    return (
                                        NoiseUpgrader.key,
                                        remotePeer: self.remotePeerInfo,
                                        warning: self.shouldWarn ? SecurityWarnings.skippedRemotePeerValidation : nil
                                    )
                                }
                            }
                        )

                    } catch {
                        logger.error("Error: \(error)")
                        return abort(context: context, error: error)
                    }

                default:
                    return
                }
            case .listener:
                switch messagesWritten {
                case 0:
                    // Parse Message A
                    let d = unwrapInboundIn(data)

                    guard d.readableBytes > 0 else {
                        self.logger.debug("Received zero length message, waiting for more data...")
                        return
                    }

                    do {
                        // Consume Message A
                        let _ = try self.handshakeState.readMessage(Array(d.readableBytesView))

                        // Construct Listeners Handshake Signature Payload
                        let nhp = try createPayload()

                        // Write Message B
                        let (msg1, _, _) = try self.handshakeState.writeMessage(payload: nhp)

                        context.writeAndFlush(
                            wrapOutboundOut(context.channel.allocator.buffer(bytes: msg1)),
                            promise: nil
                        )

                        messagesWritten += 1
                    } catch {
                        logger.error("Error: \(error)")
                        return abort(context: context, error: error)
                    }
                case 1:
                    // Parse Message C
                    let d = unwrapInboundIn(data)

                    do {
                        //Consume Message C
                        let (payload, cs1, cs2) = try self.handshakeState.readMessage(Array(d.readableBytesView))

                        // Ensure we have our split CipherStates
                        guard let inboundCipherState = cs1, let outboundCipherState = cs2 else {
                            logger.error(
                                "Failed to instantiate CipherStates after processing message C. Aborting Handshake and closing connection..."
                            )
                            return abort(context: context, error: NoiseErrors.failedToInstantiateCipherStates)
                        }

                        // Verify the initiators signature payload with their Public PeerID
                        //logger.info("Verifying NoiesHandshakePayload")
                        let inhp = try NoiseHandshakePayload(contiguousBytes: payload)

                        // Initiate Remote PeerID from the payloads identityKey
                        guard let rpid = try? PeerID(marshaledPublicKey: inhp.identityKey) else {
                            logger.error(
                                "Could not instantiate PeerID from Initiators Identity Key. Aborting Handshake and closing connection..."
                            )
                            return abort(context: context, error: NoiseErrors.invalidIdentityKey)
                        }
                        guard let remoteStatic = try? self.handshakeState.peerStatic() else {
                            logger.error("Failed to access remote peers static noise key")
                            return abort(context: context, error: NoiseErrors.invalidRemoteStaticKey)
                        }
                        // Construct the data we expect the signature to be valid for
                        guard let sigPrefix = payloadSigPrefix.data(using: .utf8) else {
                            logger.error("Invalid Signature Prefix")
                            return abort(context: context, error: NoiseErrors.invalidSignaturePrefix)
                        }
                        let expectedSignedData = sigPrefix + remoteStatic.rawRepresentation
                        guard try rpid.isValidSignature(inhp.identitySig, for: expectedSignedData) else {
                            logger.error(
                                "Initiators Noise Handshake Signature Verification failed. Aborting Handshake and closing connection..."
                            )
                            return abort(context: context, error: NoiseErrors.invalidSignature)
                        }

                        // Upgrade the channel with the encrypter / decrypter handlers
                        self.state = .secured
                        self.remotePeerInfo = rpid

                        logger.trace("Channel Secured! Attempting to install Encryption and Decryption Handlers")

                        // Now that our Handshake has completed successfully we
                        // - install our Encryption & Decryption handlers with their respective CipherStates
                        // - remove this handler from the pipeline
                        // - complete our channelSecureCallback so our Channel is notified of the result
                        channelSecuredCallback.completeWith(
                            //Listener uses cs1 for inbound, Initiator uses cs2 for inbound
                            //Listener uses cs2 for outbound, Initiator uses cs1 for outbound
                            //installEncryptionHandlersAndRemoveSelf(context, inboundCipherState: cs1, outboundCipherState: cs2)
                            context.pipeline.addHandlers(
                                [
                                    //Inbound Decryption Handler
                                    //Listener uses cs1 for inbound, Initiator uses cs2 for inbound
                                    InboundNoiseDecryptionHandler(cipherState: inboundCipherState, logger: self.logger),
                                    //Outbound Encryption Handler
                                    //Listener uses cs2 for outbound, Initiator uses cs1 for outbound
                                    OutboundNoiseEncryptionHandler(
                                        cipherState: outboundCipherState,
                                        logger: self.logger
                                    ),
                                ],
                                position: .after(self)
                            ).flatMap { _ -> EventLoopFuture<Connection.SecuredResult> in
                                self.logger.trace(
                                    "Encryption and Decryption Handlers Installed! Uninstalling self (handshake handler)"
                                )
                                return context.pipeline.removeHandler(self).map { _ -> Connection.SecuredResult in
                                    self.logger.debug("Channel Secured 🔐")
                                    return (
                                        NoiseUpgrader.key,
                                        remotePeer: self.remotePeerInfo,
                                        warning: nil
                                    )
                                }
                            }
                        )

                    } catch {
                        logger.error("Error: \(error)")
                        self.abort(context: context, error: error)
                    }

                default:
                    return
                }
            }

        case .secured:
            // Decrypt and forward the data along the pipeline  through our Decryptor and Encryptor handlers
            //logger.info("--- 🔓 Inbound Data Decryption Complete 🔓 ---")
            context.fireChannelRead(wrapInboundOut(unwrapInboundIn(data)))
        }
    }

    // private func abort(context:ChannelHandlerContext) {
    //     channelSecuredCallback(false, nil)
    //     context.close(mode: .all, promise: nil)
    // }

    private func abort(context: ChannelHandlerContext, error: Error) {
        // channelSecuredCallback.completeWith(
        //     context.close(mode: .all).map { _ -> (Bool, PeerID?) in
        //         return (false, nil)
        //     }
        // )
        context.close(mode: .all).whenComplete { _ in
            self.channelSecuredCallback.fail(error)
        }

    }

    private func createPayload() throws -> [UInt8] {
        // Construct Handshake Signature Payload
        var nhp = NoiseHandshakePayload()
        // The identity_key field contains a serialized PublicKey message as defined in the peer id spec.
        nhp.identityKey = try Data(localPeerInfo.marshalPublicKey())  //PeerID public key
        // The identity_sig field is produced using the libp2p identity private key according to the signing rules in the peer id spec.
        // The data to be signed is the UTF-8 string `noise-libp2p-static-key:`, followed by the Noise static public key, encoded according to the rules defined in section 5 of RFC 7748.
        nhp.identitySig = try localPeerInfo.signature(
            for: payloadSigPrefix.data(using: .utf8)! + staticNoiseKey.publicKey.rawRepresentation
        )

        return try Array(nhp.serializedData())
    }

    //    private func installEncryptionHandlersAndRemoveSelf(_ context:ChannelHandlerContext, inboundCipherState:Noise.CipherState, outboundCipherState:Noise.CipherState) -> EventLoopFuture<(Bool, PeerID?)> {
    //        context.pipeline.addHandlers([
    //            //Inbound Decryption Handler
    //            InboundNoiseDecryptionHandler(cipherState: inboundCipherState), //Listener uses cs1 for inbound, Initiator uses cs2 for inbound
    //            //Outbound Encryption Handler
    //            OutboundNoiseEncryptionHandler(cipherState: outboundCipherState) //Listener uses cs2 for outbound, Initiator uses cs1 for outbound
    //            ], position: .after(self)
    //        ).flatMap { _ -> EventLoopFuture<(Bool, PeerID?)> in
    //            self.logger.info("Encryption and Decryption Handlers Installed! Uninstalling self (handshake handler)")
    //            return context.pipeline.removeHandler(self).map { _ -> (Bool, PeerID?) in
    //                (true, self.remotePeerInfo)
    //            }
    //        }
    //    }

    // Flush it out. This can make use of gathering writes if multiple buffers are pending
    public func channelReadComplete(context: ChannelHandlerContext) {
        switch state {
        case .handshakeInProgress:
            return
        case .secured:
            // Is this what we actually want to do??
            context.fireChannelReadComplete()
        }
        //context.flush()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Error: \(error)")
        /// Do we propogate this message along the pipeline?
        //context.fireErrorCaught(error)
        context.close(mode: .all, promise: nil)
    }
}
