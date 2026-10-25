import CryptoKit
import Foundation
import Testing
@testable import AppCore

final class Clock: @unchecked Sendable {
    var now = Date(timeIntervalSince1970: 1_000_000)
}

struct AuthenticatorTests {
    let clock = Clock()
    let authenticator: Authenticator
    let phoneKey = P256.Signing.PrivateKey()

    init() {
        let clock = clock
        authenticator = Authenticator(machineId: "machine-1") { clock.now }
    }

    func pairRequest(token: String, key: P256.Signing.PrivateKey? = nil) -> PairRequest {
        let invite = PairingInvite(machineId: "machine-1", machineName: "Mac", platform: "macOS", relay: Brand.relay, token: token)
        return PairRequest(invite: invite, deviceId: "phone-1", deviceName: "iPhone", publicKey: (key ?? phoneKey).publicKey.x963Representation)
    }

    func pair() throws -> PairedDevice {
        try authenticator.completePairing(pairRequest(token: authenticator.startPairing()))
    }

    func signedCommand(_ action: Action, nonce: String, key: P256.Signing.PrivateKey? = nil) throws -> CommandRequest {
        let message = SignedMessage.bytes(machineId: "machine-1", deviceId: "phone-1", action: action, nonce: nonce)
        let signature = try (key ?? phoneKey).signature(for: message).rawRepresentation
        return CommandRequest(deviceId: "phone-1", action: action, nonce: nonce, signature: signature.base64EncodedString())
    }

    @Test func pairingThenValidCommand() throws {
        let device = try pair()
        let nonce = authenticator.issueNonce(for: device.id)
        #expect(try authenticator.verify(signedCommand(.unlock, nonce: nonce), devices: [device]).id == "phone-1")
    }

    @Test func pairingTokenIsSingleUse() throws {
        let request = pairRequest(token: authenticator.startPairing())
        _ = try authenticator.completePairing(request)
        #expect(throws: AuthError.noPairingInProgress) { try authenticator.completePairing(request) }
    }

    @Test func pairingTokenExpires() {
        let token = authenticator.startPairing()
        clock.now += WireProtocol.pairingLifetime + 1
        #expect(throws: AuthError.pairingExpired) {
            try authenticator.completePairing(pairRequest(token: token))
        }
    }

    @Test func wrongPairingTokenRejected() {
        _ = authenticator.startPairing()
        #expect(throws: AuthError.badPairingToken) { try authenticator.completePairing(pairRequest(token: "nope")) }
    }

    @Test func swappedPublicKeyRejected() {
        // Someone on the network replaces the iPhone's key with their own but can't redo the proof without the token.
        var request = pairRequest(token: authenticator.startPairing())
        request.publicKey = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
        #expect(throws: AuthError.badPairingToken) { try authenticator.completePairing(request) }
    }

    @Test func invalidPublicKeyRejected() {
        let token = authenticator.startPairing()
        let publicKey = Data([1, 2, 3]).base64EncodedString()
        let proof = PairingProof.make(token: token, machineId: "machine-1", deviceId: "p", deviceName: "n", publicKey: publicKey)
        #expect(throws: AuthError.badPublicKey) {
            try authenticator.completePairing(PairRequest(deviceId: "p", deviceName: "n", publicKey: publicKey, proof: proof))
        }
    }

    @Test func nonceIsSingleUse() throws {
        let device = try pair()
        let nonce = authenticator.issueNonce(for: device.id)
        _ = try authenticator.verify(signedCommand(.unlock, nonce: nonce), devices: [device])
        #expect(throws: AuthError.unknownNonce) { try authenticator.verify(signedCommand(.unlock, nonce: nonce), devices: [device]) }
    }

    @Test func expiredNonceRejected() throws {
        let device = try pair()
        let nonce = authenticator.issueNonce(for: device.id)
        clock.now += WireProtocol.nonceLifetime + 1
        #expect(throws: AuthError.expiredNonce) { try authenticator.verify(signedCommand(.unlock, nonce: nonce), devices: [device]) }
    }

    @Test func wrongKeyRejected() throws {
        let device = try pair()
        let nonce = authenticator.issueNonce(for: device.id)
        #expect(throws: AuthError.badSignature) {
            try authenticator.verify(signedCommand(.unlock, nonce: nonce, key: P256.Signing.PrivateKey()), devices: [device])
        }
    }

    @Test func signatureForAnotherActionRejected() throws {
        let device = try pair()
        let nonce = authenticator.issueNonce(for: device.id)
        var request = try signedCommand(.lock, nonce: nonce)
        request.action = .unlock
        #expect(throws: AuthError.badSignature) { try authenticator.verify(request, devices: [device]) }
    }

    @Test func nonceIssuedToAnotherDeviceRejected() throws {
        let device = try pair()
        let nonce = authenticator.issueNonce(for: "someone-else")
        #expect(throws: AuthError.unknownNonce) { try authenticator.verify(signedCommand(.unlock, nonce: nonce), devices: [device]) }
    }

    @Test func unknownDeviceRejected() throws {
        let nonce = authenticator.issueNonce(for: "phone-1")
        #expect(throws: AuthError.unknownDevice) { try authenticator.verify(signedCommand(.unlock, nonce: nonce), devices: []) }
    }
}

struct ProtocolTests {
    @Test func inviteRoundTripsThroughURLAndBareCode() throws {
        let invite = PairingInvite(machineId: "m", machineName: "Ruben’s MacBook Pro", platform: "macOS",
                                   relay: Brand.relay, token: randomToken())
        #expect(PairingInvite(string: invite.url.absoluteString) == invite)
        let code = try #require(URLComponents(url: invite.url, resolvingAgainstBaseURL: false)?.queryItems?.first?.value)
        #expect(PairingInvite(string: "  \(code)\n") == invite)
        #expect(PairingInvite(string: "\(Brand.urlScheme)://pair?d=garbage") == nil)
    }

    // The same vectors are checked by the Go agent (linux/protocol_test.go), so both sides agree on the wire format.
    @Test func crossLanguageVectors() throws {
        let key = try P256.Signing.PublicKey(x963Representation: #require(Data(base64Encoded: Vectors.publicKey)))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: #require(Data(base64Encoded: Vectors.signature)))
        let message = SignedMessage.bytes(machineId: "machine-1", deviceId: "phone-1", action: .unlock, nonce: "nonce-1")
        #expect(key.isValidSignature(signature, for: message))
        #expect(PairingProof.make(token: "token-1", machineId: "machine-1", deviceId: "phone-1", deviceName: "iPhone",
                                  publicKey: Vectors.publicKey) == Vectors.proof)

        let device = PairedDevice(id: "phone-1", name: "iPhone", publicKey: try #require(Data(base64Encoded: Vectors.approvalPublicKey)),
                                  pairedAt: Date())
        var approval = Approval(id: "approval-1", title: "sudo pacman -Syu", detail: "ruben on pts/1", nonce: "nonce-1", expiresIn: 30)
        #expect(device.isValidSignature(Vectors.approvalSignature,
                                        for: ApprovalMessage.bytes(machineId: "machine-1", deviceId: "phone-1", approval: approval)))
        approval.title = "sudo rm -rf /"
        #expect(!device.isValidSignature(Vectors.approvalSignature,
                                         for: ApprovalMessage.bytes(machineId: "machine-1", deviceId: "phone-1", approval: approval)))
    }

    @Test func olderComputersStillDecode() throws {
        // A computer without approvals support answers hello without `locked` and `approvals`.
        let old = Data(#"{"machineId":"m","machineName":"Mac","nonce":"n"}"#.utf8)
        let hello = try JSONDecoder().decode(HelloResponse.self, from: old)
        #expect(hello.locked == nil && hello.approvals == nil)

        // And an older iPhone sends commands without `approvalId`.
        let command = Data(#"{"deviceId":"d","action":"unlock","nonce":"n","signature":"s"}"#.utf8)
        #expect(try JSONDecoder().decode(CommandRequest.self, from: command).approvalId == nil)
    }

    @Test func notifyTopics() {
        let topic = Notifications.newTopic()
        #expect(Notifications.isValidTopic(topic))
        #expect(!Notifications.isValidTopic("short"))
        #expect(!Notifications.isValidTopic("\(Brand.id)-abc/../../admin"))
        #expect(!Notifications.isValidTopic("\(Brand.id)-abcdefghij?x=1"))
    }
}

enum Vectors {
    static let publicKey = "BAgPR2YEAVXtH4FV5lz7GfgmXFGdGeSUbwNl/aQuMfhqUZBYED2VyexlxQ8BJj+derxoiayhgiX9Brpn8PSdlSo="
    static let signature = "/ZB+omIwMIBk3ZC8I6bqsnPVnoLG4nVQpBIHfBaibW/1X5xhPvSPrcEjDHbILAeiXRVhgVH5BHcirEgxlQqo2A=="
    static let proof = "ozz/3xgOMjJa3B9AFHhgoRBQrwoewVS2qZoU7kAXjYc="
    // Approval of "sudo pacman -Syu" (id approval-1, nonce nonce-1, detail "ruben on pts/1") on machine-1 by phone-1.
    static let approvalPublicKey = "BL6yw1jEZ48le5S3AmGdVzJQ+uE8yMhKPjoXpbbVZpQlIhZju4aFpgIFFKdm9YxAc985PsCyKqRQMovVORAeHKc="
    static let approvalSignature = "lT/6MJw2iN0NA/g4fMugjVeO+Zl5qPDtLLHXaupF0TDxWl1J9l8mbrnhha2zC3W8lW/C+Ism+Px5hp/w6PqG1Q=="
}
