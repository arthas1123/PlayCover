import Foundation

@main
struct KeyCoverCryptoTests {
    // swiftlint:disable:next function_body_length
    static func main() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("keycover-tests-\(UUID())")
        try manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        let plain = root.appendingPathComponent("login.db")
        let encrypted = root.appendingPathComponent("login.keyCover")
        let payload = Data("SQLite format 3\0test credential data".utf8)
        let password = "test-only $() ' 密碼 with spaces"
        var count = 0

        func check(_ condition: @autoclosure () throws -> Bool, _ name: String) throws {
            guard try condition() else { throw NSError(domain: name, code: 1) }
            count += 1
            print("PASS: \(name)")
        }
        func expectFailure(_ name: String, _ body: () throws -> Void) throws {
            do { try body() } catch { count += 1; print("PASS: \(name)"); return }
            throw NSError(domain: "Expected failure: \(name)", code: 1)
        }
        func legacyConvert(_ source: URL, _ destination: URL, decrypt: Bool) throws {
            // Fixtures only: exercise the original -k format using a non-secret test password.
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            process.arguments = ["enc", "-aes-256-cbc", "-A"] + (decrypt ? ["-d"] : [])
                + ["-in", source.path, "-out", destination.path, "-k", password]
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw NSError(domain: "legacy fixture", code: 1) }
        }

        try payload.write(to: plain)
        try legacyConvert(plain, encrypted, decrypt: false)
        try manager.removeItem(at: plain)
        try KeyCoverCrypto.convert(source: encrypted, destination: plain, password: password, decrypt: true)
        try check(Data(contentsOf: plain) == payload, "decrypt existing legacy database")
        try check(!manager.fileExists(atPath: encrypted.path), "delete encrypted source after success")

        try KeyCoverCrypto.convert(source: plain, destination: encrypted, password: password, decrypt: false)
        try check(!manager.fileExists(atPath: plain.path), "delete plaintext after encryption success")
        let attributes = try manager.attributesOfItem(atPath: encrypted.path)
        try check((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "private output permissions")
        try legacyConvert(encrypted, plain, decrypt: true)
        try check(Data(contentsOf: plain) == payload, "new encryption remains legacy compatible")

        let savedCiphertext = try Data(contentsOf: encrypted)
        try expectFailure("wrong password fails") {
            try KeyCoverCrypto.convert(source: encrypted, destination: plain, password: "wrong", decrypt: true)
        }
        try check(Data(contentsOf: encrypted) == savedCiphertext, "wrong password preserves encrypted source")
        try check(Data(contentsOf: plain) == payload, "wrong password preserves existing destination")

        try Data("corrupted".utf8).write(to: encrypted)
        try expectFailure("corrupted ciphertext fails") {
            try KeyCoverCrypto.convert(source: encrypted, destination: plain, password: password, decrypt: true)
        }
        try check(Data(contentsOf: encrypted) == Data("corrupted".utf8), "corruption preserves source")
        try check(Data(contentsOf: plain) == payload, "corruption preserves destination")

        try expectFailure("missing source fails") {
            try KeyCoverCrypto.convert(source: root.appendingPathComponent("missing"), destination: encrypted,
                                       password: password, decrypt: false)
        }
        try check(Data(contentsOf: encrypted) == Data("corrupted".utf8), "failed encryption preserves destination")

        let blocked = root.appendingPathComponent("directory")
        try manager.createDirectory(at: blocked, withIntermediateDirectories: false)
        try expectFailure("publication failure reported") {
            try KeyCoverCrypto.convert(source: plain, destination: blocked, password: password, decrypt: false)
        }
        try check(Data(contentsOf: plain) == payload, "publication failure preserves source")

        try expectFailure("same input and output rejected") {
            try KeyCoverCrypto.convert(source: plain, destination: plain, password: password, decrypt: false)
        }
        try check(Data(contentsOf: plain) == payload, "same path preserves source")

        for invalidPassword in ["line\nbreak", "carriage\rreturn", "null\0byte", String(repeating: "x", count: 4096)] {
            try expectFailure("unrepresentable password rejected") {
                try KeyCoverCrypto.convert(source: plain, destination: encrypted,
                                           password: invalidPassword, decrypt: false)
            }
            try check(Data(contentsOf: plain) == payload, "invalid password preserves source")
        }

        let nonDatabase = root.appendingPathComponent("not-sqlite")
        try Data("not a database".utf8).write(to: nonDatabase)
        try legacyConvert(nonDatabase, encrypted, decrypt: false)
        let invalidDatabaseCiphertext = try Data(contentsOf: encrypted)
        try expectFailure("valid padding without SQLite header rejected") {
            try KeyCoverCrypto.convert(source: encrypted, destination: plain, password: password, decrypt: true)
        }
        try check(Data(contentsOf: encrypted) == invalidDatabaseCiphertext, "invalid database preserves ciphertext")
        try check(Data(contentsOf: plain) == payload, "invalid database preserves previous plaintext")

        let largePayload = payload + Data(repeating: 0x41, count: 2 * 1024 * 1024)
        try largePayload.write(to: plain)
        try KeyCoverCrypto.convert(source: plain, destination: encrypted, password: password, decrypt: false)
        try KeyCoverCrypto.convert(source: encrypted, destination: plain, password: password, decrypt: true)
        try check(Data(contentsOf: plain) == largePayload, "large database round trip and destination replacement")
        let leftovers = try manager.contentsOfDirectory(atPath: root.path).filter { $0.hasPrefix(".keycover-") }
        try check(leftovers.isEmpty, "temporary outputs cleaned up on success and failure")
        print("\(count) checks passed")
    }
}
