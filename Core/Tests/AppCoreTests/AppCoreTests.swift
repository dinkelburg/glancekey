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

    @Test func waitIsSignedWithItsValue() throws {
        let device = try pair()
        func request(signed: Int, sent: Int) throws -> CommandRequest {
            let nonce = authenticator.issueNonce(for: device.id)
            let message = WaitMessage.bytes(machineId: "machine-1", deviceId: device.id, nonce: nonce, wait: signed)
            return CommandRequest(deviceId: device.id, action: .setWait, nonce: nonce,
                                  signature: try phoneKey.signature(for: message).rawRepresentation.base64EncodedString(), wait: sent)
        }
        #expect(try authenticator.verify(request(signed: 300, sent: 300), devices: [device]).id == device.id)
        // A relay that changes the value fails the signature.
        #expect(throws: AuthError.badSignature) { try authenticator.verify(request(signed: 300, sent: ApprovalWait.untilAnswered), devices: [device]) }
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

        #expect(hello.wantsPasswordKey == nil && hello.sealedPassword == nil)

        // And an older iPhone sends commands without `approvalId`, `passwordKey` or `wrappedKey`.
        let command = try JSONDecoder().decode(CommandRequest.self,
                                               from: Data(#"{"deviceId":"d","action":"unlock","nonce":"n","signature":"s"}"#.utf8))
        #expect(command.approvalId == nil && command.passwordKey == nil && command.wrappedKey == nil)

        // An invite from a computer that doesn't seal its password doesn't ask for a password key, and an invite
        // that does still opens in an older app (which ignores the field).
        let invite = PairingInvite(machineId: "m", machineName: "n", platform: "linux", relay: Brand.relay, token: "t")
        #expect(invite.wantsPasswordKey == nil && !invite.url.absoluteString.contains("wantsPasswordKey"))
    }

    // The Go agent checks the same values (linux/seal_test.go): it seals to the same bytes and opens the wrapped key.
    @Test func sealedPasswordVectors() throws {
        func key(_ byte: UInt8) throws -> P256.KeyAgreement.PrivateKey { try .init(rawRepresentation: Data(repeating: byte, count: 32)) }
        let phone = try key(0x11), session = try key(0x33)
        #expect(phone.publicKey.x963Representation.base64EncodedString() == SealVectors.passwordKey)
        #expect(session.publicKey.x963Representation.base64EncodedString() == SealVectors.sessionKey)

        let sealed = try PasswordSeal.seal(SealVectors.password, to: phone.publicKey.x963Representation, machineId: "machine-1",
                                           deviceId: "phone-1", ephemeral: key(0x22), aesNonce: AES.GCM.Nonce(data: Data(repeating: 0x55, count: 12)))
        #expect(sealed.key.base64EncodedString() == SealVectors.sealKey)
        #expect(sealed.box.base64EncodedString() == SealVectors.sealedBox)

        let passwordKey = PasswordSeal.passwordKey(
            sharedSecret: try phone.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: sealed.key)),
            sealKey: sealed.key, machineId: "machine-1", deviceId: "phone-1")
        let wrapped = try PasswordSeal.wrap(passwordKey, sessionKey: SealVectors.sessionKey, machineId: "machine-1", deviceId: "phone-1",
                                            nonce: "nonce-1", ephemeral: key(0x44), aesNonce: AES.GCM.Nonce(data: Data(repeating: 0x66, count: 12)))
        #expect(wrapped == WrappedKey(key: SealVectors.wrappedKey, box: SealVectors.wrappedBox))
        #expect(try PasswordSeal.open(sealed, wrapped: wrapped, session: session, machineId: "machine-1", deviceId: "phone-1",
                                      nonce: "nonce-1") == SealVectors.password)

        let signingKey = try P256.Signing.PublicKey(x963Representation: #require(Data(base64Encoded: SealVectors.signingKey)))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: #require(Data(base64Encoded: SealVectors.signature)))
        func message(sessionKey: String) -> Data {
            SignedMessage.bytes(machineId: "machine-1", deviceId: "phone-1", action: .unlock, nonce: "nonce-1",
                                sessionKey: sessionKey, passwordKey: SealVectors.passwordKey, wrappedKey: wrapped)
        }
        #expect(signingKey.isValidSignature(signature, for: message(sessionKey: SealVectors.sessionKey)))
        // A session key swapped in on the way doesn't match what the iPhone signed.
        #expect(!signingKey.isValidSignature(signature, for: message(sessionKey: SealVectors.sealKey)))

        #expect(PairingProof.make(token: "token-1", machineId: "machine-1", deviceId: "phone-1", deviceName: "iPhone",
                                  publicKey: SealVectors.signingKey, passwordKey: SealVectors.passwordKey) == SealVectors.proof)
        #expect(!PairingProof.isValid(SealVectors.proof, token: "token-1", machineId: "machine-1", deviceId: "phone-1", deviceName: "iPhone",
                                      publicKey: SealVectors.signingKey, passwordKey: SealVectors.sealKey))
    }

    // The same JSON is in the Go tests (TestSealedPasswordJSONMatchesSwift), so both sides use the same field names.
    @Test func sealedPasswordJSON() throws {
        let invite = try #require(PairingInvite(string: Data(#"{"v":2,"machineId":"m","machineName":"n","platform":"linux","relay":"https://r","token":"t","wantsPasswordKey":true}"#.utf8).base64URLEncodedString()))
        #expect(invite.wantsPasswordKey == true)
        let hello = try JSONDecoder().decode(HelloResponse.self, from: Data(#"{"machineId":"m","machineName":"n","nonce":"x","wantsPasswordKey":true,"sealedPassword":{"sealKey":"S","sessionKey":"T"}}"#.utf8))
        #expect(hello.wantsPasswordKey == true && hello.sealedPassword == SealedPasswordChallenge(sealKey: "S", sessionKey: "T"))

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let pair = PairRequest(deviceId: "d", deviceName: "iPhone", publicKey: "k", proof: "p", passwordKey: "P")
        #expect(String(decoding: try encoder.encode(pair), as: UTF8.self)
            == #"{"deviceId":"d","deviceName":"iPhone","passwordKey":"P","proof":"p","publicKey":"k"}"#)
        let command = CommandRequest(deviceId: "d", action: .unlock, nonce: "x", signature: "s", passwordKey: "P",
                                     wrappedKey: WrappedKey(key: "K", box: "B"))
        #expect(String(decoding: try encoder.encode(command), as: UTF8.self)
            == #"{"action":"unlock","deviceId":"d","nonce":"x","passwordKey":"P","signature":"s","wrappedKey":{"box":"B","key":"K"}}"#)
    }

    // The Mac app (Authenticator) verifies only v1, so a command without a password key or wrapped key must sign
    // exactly those bytes; Go treats an empty password key as none, and so must Swift.
    @Test func commandsWithoutPasswordKeysSignVersion1() {
        let v1 = SignedMessage.bytes(machineId: "m", deviceId: "d", action: .unlock, nonce: "n")
        #expect(SignedMessage.bytes(machineId: "m", deviceId: "d", action: .unlock, nonce: "n", sessionKey: "s",
                                    passwordKey: nil, wrappedKey: nil) == v1)
        #expect(SignedMessage.bytes(machineId: "m", deviceId: "d", action: .unlock, nonce: "n", sessionKey: nil,
                                    passwordKey: "", wrappedKey: nil) == v1)
        #expect(PairingProof.make(token: "t", machineId: "m", deviceId: "d", deviceName: "n", publicKey: "k", passwordKey: "")
            == PairingProof.make(token: "t", machineId: "m", deviceId: "d", deviceName: "n", publicKey: "k"))
    }

    @Test func sealedPasswordOnlyOpensForItsChallenge() throws {
        let phone = P256.KeyAgreement.PrivateKey(), session = P256.KeyAgreement.PrivateKey()
        let sealed = try PasswordSeal.seal("hunter2", to: phone.publicKey.x963Representation, machineId: "m", deviceId: "d")
        let passwordKey = PasswordSeal.passwordKey(
            sharedSecret: try phone.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: sealed.key)),
            sealKey: sealed.key, machineId: "m", deviceId: "d")
        let sessionKey = session.publicKey.x963Representation.base64EncodedString()
        let wrapped = try PasswordSeal.wrap(passwordKey, sessionKey: sessionKey, machineId: "m", deviceId: "d", nonce: "n")
        #expect(try PasswordSeal.open(sealed, wrapped: wrapped, session: session, machineId: "m", deviceId: "d", nonce: "n") == "hunter2")
        // Another challenge, another session key, or another computer can't open it.
        #expect(throws: (any Error).self) {
            try PasswordSeal.open(sealed, wrapped: wrapped, session: session, machineId: "m", deviceId: "d", nonce: "other")
        }
        #expect(throws: (any Error).self) {
            try PasswordSeal.open(sealed, wrapped: wrapped, session: P256.KeyAgreement.PrivateKey(), machineId: "m", deviceId: "d", nonce: "n")
        }
        let elsewhere = PasswordSeal.passwordKey(
            sharedSecret: try phone.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: sealed.key)),
            sealKey: sealed.key, machineId: "other", deviceId: "d")
        let wrong = try PasswordSeal.wrap(elsewhere, sessionKey: sessionKey, machineId: "m", deviceId: "d", nonce: "n")
        #expect(throws: (any Error).self) {
            try PasswordSeal.open(sealed, wrapped: wrong, session: session, machineId: "m", deviceId: "d", nonce: "n")
        }
    }

    // The same JSON is in the Go tests (TestCardJSONMatchesSwift), and the relay reads it (relay/tests).
    @Test func cardJSON() throws {
        let card = String(repeating: "ab", count: 32)
        let encoder = JSONEncoder()
        // Escaped or not, "/" reads the same; this pins the field names.
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let message = RelayCard(cards: [card], locked: true,
                                approvals: [RelayCard.Waiting(id: "a1", title: "sudo true", detail: "ruben on pts/1", expiresIn: 60)])
        #expect(String(decoding: try encoder.encode(message), as: UTF8.self)
            == #"{"card":{"approvals":[{"detail":"ruben on pts/1","expiresIn":60,"id":"a1","title":"sudo true"}],"cards":["\#(card)"],"locked":true}}"#)
        #expect(String(decoding: try encoder.encode(RelayCard(cards: [card], locked: nil, approvals: [])), as: UTF8.self)
            == #"{"card":{"approvals":[],"cards":["\#(card)"]}}"#)
        #expect(String(decoding: try encoder.encode(HelloRequest(deviceId: "d", cardId: card)), as: UTF8.self)
            == #"{"cardId":"\#(card)","deviceId":"d"}"#)

        var later = message
        later.card.approvals[0].expiresIn = 59
        #expect(later.isSame(as: message))
        later.card.locked = false
        #expect(!later.isSame(as: message))
    }

    // The same bytes are pinned in the Go tests (TestWaitMessageMatchesSwift).
    @Test func waitMessage() throws {
        #expect(String(decoding: WaitMessage.bytes(machineId: "m", deviceId: "d", nonce: "n", wait: 300), as: UTF8.self)
            == "faceunlock-wait/v1\nm\nd\nn\n300")
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        #expect(String(decoding: try encoder.encode(CommandRequest(deviceId: "d", action: .setWait, nonce: "n", signature: "s", wait: 300)),
                       as: UTF8.self) == #"{"action":"setWait","deviceId":"d","nonce":"n","signature":"s","wait":300}"#)
        #expect(ApprovalWait.name(30) == "30 seconds" && ApprovalWait.name(60) == "1 minute" && ApprovalWait.name(900) == "15 minutes")
    }

    @Test func cardIds() {
        let id = CardId.of(secret: "secret")
        #expect(id == "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b")
        #expect(CardId.isValid(id))
        #expect(!CardId.isValid(id.uppercased()))
        #expect(!CardId.isValid(String(id.dropLast())))
        #expect(!CardId.isValid(String(id.dropLast()) + "/"))
    }

    // linux/protocol_test.go pins the same.
    @Test func keyFingerprint() {
        #expect(PairedDevice.keyFingerprint(Data("test".utf8)) == "9F86-D081-884C")
    }

    @Test func notifyJSON() throws {
        let data = try JSONEncoder().encode(RelayNotification(machineName: "Mac", pushTokens: ["t"], expiresIn: 900))
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: [String: Any]])
        #expect(object["notify"]?["machineName"] as? String == "Mac")
        #expect(object["notify"]?["pushTokens"] as? [String] == ["t"])
        #expect(object["notify"]?["expiresIn"] as? Int == 900)
    }

    @Test func pushTokens() {
        let token = String(repeating: "0123456789abcdef", count: 4)
        #expect(PushToken.isValid(token))
        #expect(PushToken.isValid(token.uppercased()))
        #expect(!PushToken.isValid("abcdef"))
        #expect(!PushToken.isValid(token + "/../x"))
        #expect(!PushToken.isValid(String(repeating: "ａ", count: 64)))
    }
}

struct FreeTierTests {
    // What the relay sends (relay/tests); a limit it leaves out or sends as null is no limit.
    @Test func limitsJSON() throws {
        let decoder = JSONDecoder()
        #expect(try decoder.decode(FreeLimits.self, from: Data(#"{"computers":2,"perDay":15}"#.utf8)) == .standard)
        #expect(try decoder.decode(FreeLimits.self, from: Data(#"{"computers":null}"#.utf8)) == FreeLimits(computers: nil, perDay: nil))
    }

    @Test func dailyUseStartsAgainAtMidnight() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try #require(TimeZone(identifier: "Europe/Amsterdam"))
        let evening = try #require(calendar.date(from: DateComponents(year: 2026, month: 10, day: 28, hour: 23, minute: 50)))
        let night = evening.addingTimeInterval(20 * 60)

        var use = DailyUse()
        #expect(use.count(on: evening, calendar: calendar) == 0)
        use.add(1, on: evening, calendar: calendar)
        use.add(2, on: evening, calendar: calendar)
        #expect(use.count(on: evening, calendar: calendar) == 3)
        #expect(use.count(on: night, calendar: calendar) == 0)
        use.add(1, on: night, calendar: calendar)
        #expect(use == DailyUse(day: "2026-10-29", count: 1, earlier: ["2026-10-28": 3]))
    }

    // Moving the clock to another day and back doesn't give a new day's worth.
    @Test func dailyUseRemembersEarlierDays() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try #require(TimeZone(identifier: "Europe/Amsterdam"))
        let today = try #require(calendar.date(from: DateComponents(year: 2026, month: 10, day: 28, hour: 12)))
        let tomorrow = today.addingTimeInterval(24 * 3600)
        var use = DailyUse()
        use.add(15, on: today, calendar: calendar)
        use.add(15, on: tomorrow, calendar: calendar)
        #expect(use.count(on: today, calendar: calendar) == 15)
        use.add(1, on: today, calendar: calendar)
        #expect(use.count(on: today, calendar: calendar) == 16)
        #expect(use.count(on: tomorrow, calendar: calendar) == 15)
        // Only the last week is kept, and a count saved by an older version still reads.
        for day in 1...10 { use.add(1, on: today.addingTimeInterval(Double(day) * 24 * 3600), calendar: calendar) }
        #expect((use.earlier?.count ?? 0) == DailyUse.keptDays)
        let old = try JSONDecoder().decode(DailyUse.self, from: Data(#"{"day":"2026-10-28","count":4}"#.utf8))
        #expect(old.count(on: today, calendar: calendar) == 4)
    }
}

/// Made by CryptoKit from keys whose raw bytes are all 0x11 (iPhone's password key), 0x22 (seal), 0x33 (session),
/// 0x44 (wrap) and 0x77 (signing), with AES-GCM nonces of 0x55 (seal) and 0x66 (wrap); machine-1, phone-1, nonce-1.
enum SealVectors {
    static let password = "correct horse battery staple"
    static let passwordKey = "BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q="
    static let sessionKey = "BFGnWAgziY6hsYPL1zUKQJkHjG7xweGOlwzXaDA18l59ARBSJxKwtafP8IFoVIaYSpTmgx7axG5zYPqdg0p6gaE="
    static let sealKey = "BNZak5d8qj0bCBhS/1ennkZfFmBXcwS66tUF3TpIWJzzUBheiVNy32Ih6joTdVfkc/3bZ1XwW9UHw8Uz/OnJEoU="
    static let sealedBox = "VVVVVVVVVVVVVVVVDSFIX1bYxnvb+2RCqQpeh2FPuhlUCy/2ZlGbPV4EVJre1BD/9OD7UWgVDmg="
    static let wrappedKey = "BFs2iQ2svXyalrt0oe4os9LXW3LgmiDvJc+Ob9ip8DUNDhS+2NRoKjTYNTi9/1uW6JpmZuwNtXRdAvoSEAct91o="
    static let wrappedBox = "ZmZmZmZmZmZmZmZmBqoiN6viHPwBy8Tb6PhiiOq+F9l6JCoi/Tlia5A9u9srfDhbzMgc59lM5WGgn6La"
    static let signingKey = "BORQVOtbGr2XZlD385W/UdDY3Rk+AXTnoUocjBJ/vfLbrv4yk7BEXz+Sv44QggLgCUFciZSZYgxxt/bfkCETLJw="
    // Over the v2 SignedMessage for unlock with sessionKey, passwordKey and the wrapped key above.
    static let signature = "/sz4g7aULdEIQ9+nSBRu0O5vqJYoi27erdL8QLnE3HtEDDY83docWnPwXr+85DXMdNSjsAZLeLFUxq6mGAJjyw=="
    // v2 pairing proof for token-1, deviceName "iPhone", publicKey signingKey and passwordKey.
    static let proof = "4oi3gBnMscPvs7i3pHKT/t4JitYW/oswzpVx8YkWwcI="
}

enum Vectors {
    static let publicKey = "BAgPR2YEAVXtH4FV5lz7GfgmXFGdGeSUbwNl/aQuMfhqUZBYED2VyexlxQ8BJj+derxoiayhgiX9Brpn8PSdlSo="
    static let signature = "/ZB+omIwMIBk3ZC8I6bqsnPVnoLG4nVQpBIHfBaibW/1X5xhPvSPrcEjDHbILAeiXRVhgVH5BHcirEgxlQqo2A=="
    static let proof = "ozz/3xgOMjJa3B9AFHhgoRBQrwoewVS2qZoU7kAXjYc="
    // Approval of "sudo pacman -Syu" (id approval-1, nonce nonce-1, detail "ruben on pts/1") on machine-1 by phone-1.
    static let approvalPublicKey = "BL6yw1jEZ48le5S3AmGdVzJQ+uE8yMhKPjoXpbbVZpQlIhZju4aFpgIFFKdm9YxAc985PsCyKqRQMovVORAeHKc="
    static let approvalSignature = "lT/6MJw2iN0NA/g4fMugjVeO+Zl5qPDtLLHXaupF0TDxWl1J9l8mbrnhha2zC3W8lW/C+Ism+Px5hp/w6PqG1Q=="
}
