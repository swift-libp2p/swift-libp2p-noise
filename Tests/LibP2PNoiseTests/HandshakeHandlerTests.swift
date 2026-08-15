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
import LibP2PCore
import Logging
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import PeerID
import Testing

@testable import LibP2PNoise

/// Drives the `InboundNoiseHandshakeHandler` directly over a pair of `EmbeddedChannel`s so we can
/// exercise the full XX handshake and the post-handshake transport encryption in isolation.
@Suite("Noise Handshake Handler")
struct HandshakeHandlerTests {

    @Test("Full XX handshake completes and both peers learn each other's identity")
    func fullHandshakeCompletes() throws {
        let (initiator, listener) = try handshake()

        let initiatorResult = try #require(initiator.result.withLockedValue { $0 })
        let listenerResult = try #require(listener.result.withLockedValue { $0 })

        if case .success(let secured) = initiatorResult {
            #expect(secured.remotePeer == listener.peer)
        } else {
            Issue.record("initiator did not secure")
        }
        if case .success(let secured) = listenerResult {
            #expect(secured.remotePeer == initiator.peer)
        } else {
            Issue.record("listener did not secure")
        }

        initiator.teardown()
        listener.teardown()
    }

    @Test("Handshake succeeds when the initiator's expected remote peer matches the listener")
    func handshakeSucceedsWithMatchingExpectedPeer() throws {
        // Build the listener first so the initiator can be told exactly who it should be dialing.
        let listener = try makeEndpoint(mode: .listener)
        let initiator = try makeEndpoint(mode: .initiator, expectedRemotePeerID: listener.peer)

        try pump(initiator.channel, listener.channel)

        let res = try #require(initiator.result.withLockedValue { $0 }, "initiator handshake never completed")
        guard case .success(let secured) = res else {
            Issue.record("initiator handshake failed unexpectedly: \(res)")
            initiator.teardown()
            listener.teardown()
            return
        }
        #expect(secured.remotePeer == listener.peer)
        // A satisfied expectation must NOT raise the skipped-validation warning.
        #expect(secured.warning == nil)

        initiator.teardown()
        listener.teardown()
    }

    @Test("Handshake fails with .remotePeerMismatch when the expected remote peer is wrong")
    func handshakeFailsWithMismatchedExpectedPeer() throws {
        let listener = try makeEndpoint(mode: .listener)
        // Point the initiator at a completely unrelated identity, not the listener's.
        let unexpectedPeer = try PeerID(.Ed25519)
        let initiator = try makeEndpoint(mode: .initiator, expectedRemotePeerID: unexpectedPeer)

        try pump(initiator.channel, listener.channel)

        let res = try #require(initiator.result.withLockedValue { $0 }, "initiator handshake never settled")
        guard case .failure(let error) = res else {
            Issue.record("expected the handshake to fail with .remotePeerMismatch, but it succeeded")
            initiator.teardown()
            listener.teardown()
            return
        }

        #expect(error as? NoiseUpgrader.Error == .remotePeerMismatch)

        initiator.teardown()
        listener.teardown()
    }

    @Test("A small transport message round-trips after the handshake")
    func smallMessageRoundTrips() throws {
        let (initiator, listener) = try handshake()

        let payload = Array("hello noise".utf8)
        send(initiator.channel, payload)
        try pump(initiator.channel, listener.channel)

        #expect(try drainInboundPlaintext(listener.channel) == payload)

        initiator.teardown()
        listener.teardown()
    }

    @Test("A payload at the max single Noise message size (65519 bytes) round-trips")
    func maxSingleMessageRoundTrips() throws {
        let (initiator, listener) = try handshake()

        // 65535 (max Noise message) - 16 (Poly1305 tag) = 65519 bytes of plaintext.
        let payload = (0..<65_519).map { UInt8($0 & 0xff) }
        send(initiator.channel, payload)
        try pump(initiator.channel, listener.channel)

        #expect(try drainInboundPlaintext(listener.channel) == payload)

        initiator.teardown()
        listener.teardown()
    }

    @Test("A payload larger than one Noise message is split and reassembled")
    func largePayloadIsChunkedAndReassembled() throws {
        let (initiator, listener) = try handshake()

        // Larger than a single 65519-byte plaintext message: requires the encryption handler to
        // emit multiple Noise transport messages, each <= 65535 bytes on the wire.
        let payload = (0..<200_000).map { UInt8($0 & 0xff) }

        send(initiator.channel, payload)
        try? pump(initiator.channel, listener.channel)

        // Every framed transport message that reached the listener must be within spec.
        let received = try drainInboundPlaintext(listener.channel)
        #expect(received.count == payload.count, "expected \(payload.count) bytes, reassembled \(received.count)")
        #expect(received == payload, "the received payload did not match what we sent")

        initiator.teardown()
        listener.teardown()
    }

    @Test("securedPromise fails with .connectionClosedDuringHandshake when the connection drops")
    func promiseFailsOnConnectionDrop() throws {
        let initiator = try makeEndpoint(mode: .initiator)

        // The initiator has sent message A; drain it and simulate the remote vanishing.
        _ = try initiator.channel.readOutbound(as: ByteBuffer.self)
        initiator.channel.pipeline.fireChannelInactive()

        // Must settle (otherwise the dialer hangs), and with the proper connection-closed error.
        let res = try #require(
            initiator.result.withLockedValue { $0 },
            "securedPromise must be failed when the connection drops mid-handshake"
        )
        guard case .failure(let error) = res else {
            Issue.record("expected a failure, got \(res)")
            initiator.teardown()
            return
        }
        #expect(error as? NoiseUpgrader.Error == .connectionClosedDuringHandshake)

        initiator.teardown()
    }

    @Test("securedPromise fails with the caught error when an error is caught mid-handshake")
    func promiseFailsOnErrorCaught() throws {
        let initiator = try makeEndpoint(mode: .initiator)

        _ = try initiator.channel.readOutbound(as: ByteBuffer.self)
        struct Boom: Error {}
        initiator.channel.pipeline.fireErrorCaught(Boom())

        // Must settle (otherwise the dialer hangs), propagating the actual caught error.
        let res = try #require(
            initiator.result.withLockedValue { $0 },
            "securedPromise must be failed when an error is caught during the handshake"
        )
        guard case .failure(let error) = res else {
            Issue.record("expected a failure, got \(res)")
            initiator.teardown()
            return
        }
        #expect(error is Boom, "expected the caught Boom error to propagate, got \(error)")

        initiator.teardown()
    }

    // MARK: - Write promise plumbing (regression guard for the dropped-promise fix)

    @Test("An awaited transport write promise succeeds after the handshake")
    func writePromiseSucceeds() throws {
        let (initiator, listener) = try handshake()

        // Use the future-returning convenience so a real write promise flows through the
        // encryption handler. Before the fix this promise was dropped and never completed.
        let payload = Array("promise please".utf8)
        let outcome = NIOLockedValueBox<Result<Void, Error>?>(nil)
        initiator.channel.writeAndFlush(ByteBuffer(bytes: payload)).whenComplete { result in
            outcome.withLockedValue { $0 = result }
        }

        let settled = try #require(
            outcome.withLockedValue { $0 },
            "write promise never completed (regression: the encryption handler dropped the promise)"
        )
        guard case .success = settled else {
            Issue.record("write promise failed unexpectedly: \(settled)")
            initiator.teardown()
            listener.teardown()
            return
        }

        // The payload must still round-trip end-to-end.
        try pump(initiator.channel, listener.channel)
        #expect(try drainInboundPlaintext(listener.channel) == payload)

        initiator.teardown()
        listener.teardown()
    }

    @Test("A single write promise resolves once for a multi-message (chunked) payload")
    func writePromiseSucceedsForChunkedPayload() throws {
        let (initiator, listener) = try handshake()

        // Larger than one Noise message => multiple transport messages. The caller's promise rides
        // on the final chunk, so it must resolve exactly once after every chunk is written.
        let payload = (0..<200_000).map { UInt8($0 & 0xff) }
        let outcome = NIOLockedValueBox<Result<Void, Error>?>(nil)
        initiator.channel.writeAndFlush(ByteBuffer(bytes: payload)).whenComplete { result in
            outcome.withLockedValue { $0 = result }
        }

        let settled = try #require(
            outcome.withLockedValue { $0 },
            "chunked write promise never completed"
        )
        guard case .success = settled else {
            Issue.record("chunked write promise failed unexpectedly: \(settled)")
            initiator.teardown()
            listener.teardown()
            return
        }

        try pump(initiator.channel, listener.channel)
        #expect(try drainInboundPlaintext(listener.channel) == payload)

        initiator.teardown()
        listener.teardown()
    }

}

// MARK: - Test Harness
extension HandshakeHandlerTests {

    /// A single end of a Noise handshake, wired up to an in-memory channel.
    private final class Endpoint {
        let channel: EmbeddedChannel
        let peer: PeerID
        let promise: EventLoopPromise<Connection.SecuredResult>
        let result: NIOLockedValueBox<Result<Connection.SecuredResult, Error>?>

        init(
            channel: EmbeddedChannel,
            peer: PeerID,
            promise: EventLoopPromise<Connection.SecuredResult>,
            result: NIOLockedValueBox<Result<Connection.SecuredResult, Error>?>
        ) {
            self.channel = channel
            self.peer = peer
            self.promise = promise
            self.result = result
        }

        /// Whether the `securedPromise` has completed (successfully or not).
        var isSettled: Bool { result.withLockedValue { $0 != nil } }

        /// Tears down the channel, failing the `securedPromise` first if the handshake never
        /// settled it. An uncompleted promise would otherwise crash the test process on deinit.
        func teardown() {
            if !isSettled { promise.fail(CancellationError()) }
            _ = try? channel.finish()
        }
    }

    /// Builds an active `EmbeddedChannel` with a freshly generated Ed25519 identity and installs a
    /// handshake handler in the requested mode.
    private func makeEndpoint(mode: LibP2PCore.Mode, expectedRemotePeerID: PeerID? = nil) throws -> Endpoint {
        let peer = try PeerID(.Ed25519)
        let channel = EmbeddedChannel()
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()

        let box = NIOLockedValueBox<Result<Connection.SecuredResult, Error>?>(nil)
        let promise = channel.eventLoop.makePromise(of: Connection.SecuredResult.self)
        promise.futureResult.whenComplete { res in box.withLockedValue { $0 = res } }

        let handler = InboundNoiseHandshakeHandler(
            peerID: peer,
            mode: mode,
            logger: Logger(label: "noise.test.\(mode.rawValue)"),
            secured: promise,
            expectedRemotePeerID: expectedRemotePeerID
        )
        try channel.pipeline.addHandler(handler).wait()

        return Endpoint(channel: channel, peer: peer, promise: promise, result: box)
    }

    /// Shuttles framed bytes back and forth between two channels until neither has anything left to
    /// send. Returns once the exchange reaches a fixed point.
    private func pump(_ a: EmbeddedChannel, _ b: EmbeddedChannel) throws {
        var moved = true
        while moved {
            moved = false
            while let out = try a.readOutbound(as: ByteBuffer.self) {
                try b.writeInbound(out)
                moved = true
            }
            while let out = try b.readOutbound(as: ByteBuffer.self) {
                try a.writeInbound(out)
                moved = true
            }
        }
    }

    /// Runs a complete XX handshake and asserts both ends reach the secured state.
    private func handshake(
        initiatorExpects: PeerID? = nil
    ) throws -> (initiator: Endpoint, listener: Endpoint) {
        let initiator = try makeEndpoint(mode: .initiator, expectedRemotePeerID: initiatorExpects)
        let listener = try makeEndpoint(mode: .listener)

        try pump(initiator.channel, listener.channel)

        for (name, end) in [("initiator", initiator), ("listener", listener)] {
            let res = try #require(end.result.withLockedValue { $0 }, "\(name) handshake never completed")
            switch res {
            case .success(let secured):
                #expect(secured.securityCodec == NoiseUpgrader.key)
            case .failure(let error):
                Issue.record("\(name) handshake failed unexpectedly: \(error)")
            }
        }

        return (initiator, listener)
    }

    /// Sends plaintext out through the transport pipeline using a `nil` promise.
    ///
    /// Round-trip tests don't care about the write future, so they use a `nil` promise. The
    /// handler's promise-forwarding behavior is covered explicitly by `writePromise…` below.
    private func send(_ channel: EmbeddedChannel, _ bytes: [UInt8]) {
        channel.writeAndFlush(NIOAny(ByteBuffer(bytes: bytes)), promise: nil)
    }

    /// Drains and concatenates every inbound plaintext buffer currently queued on a channel.
    private func drainInboundPlaintext(_ channel: EmbeddedChannel) throws -> [UInt8] {
        var bytes: [UInt8] = []
        while let buf = try channel.readInbound(as: ByteBuffer.self) {
            bytes.append(contentsOf: buf.readableBytesView)
        }
        return bytes
    }
}
