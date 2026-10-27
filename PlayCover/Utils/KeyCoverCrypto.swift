import Darwin
import Foundation

/// Keeps the existing OpenSSL format so previously saved PlayChain databases remain readable.
enum KeyCoverCrypto {
    private static let lock = NSLock()
    private static let sqliteHeader = Data("SQLite format 3\0".utf8)

    enum Failure: LocalizedError {
        case invalidPassword, conversionFailed, invalidDatabase

        var errorDescription: String? {
            switch self {
            case .invalidPassword:
                return "KeyCover passwords cannot contain line breaks or null characters."
            case .conversionFailed:
                return "KeyCover could not convert the database. The source file was kept."
            case .invalidDatabase:
                return "KeyCover could not read the database. The encrypted file was kept."
            }
        }
    }

    static func convert(source: URL, destination: URL, password: String, decrypt: Bool) throws {
        // OpenSSL's stdin password reader consumes one line. Reject truncation rather than
        // silently using a different password; never put the password in argv or the environment.
        guard !password.contains("\n"), !password.contains("\r"), !password.contains("\0") else {
            throw Failure.invalidPassword
        }
        let passwordData = Data((password + "\n").utf8)
        // OpenSSL has a fixed password buffer. Also keep the write below a pipe buffer
        // so it cannot block if the child exits without consuming its input.
        guard passwordData.count <= 1024, source.standardizedFileURL != destination.standardizedFileURL else {
            throw Failure.conversionFailed
        }

        lock.lock()
        defer { lock.unlock() }

        let manager = FileManager.default
        let temporaryDirectory = destination.deletingLastPathComponent()
            .appendingPathComponent(".keycover-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: temporaryDirectory, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        defer { try? manager.removeItem(at: temporaryDirectory) }

        let output = temporaryDirectory.appendingPathComponent("output")
        guard manager.createFile(atPath: output.path, contents: nil,
                                 attributes: [.posixPermissions: 0o600]) else {
            throw Failure.conversionFailed
        }

        try runOpenSSL(source: source, output: output, passwordData: passwordData, decrypt: decrypt)

        if decrypt {
            let handle = try FileHandle(forReadingFrom: output)
            defer { try? handle.close() }
            guard try handle.read(upToCount: sqliteHeader.count) == sqliteHeader else {
                throw Failure.invalidDatabase
            }
        }

        // Both paths are on the same filesystem. Publish atomically without first
        // deleting the old destination; only discard the source after publication.
        guard rename(output.path, destination.path) == 0 else {
            throw Failure.conversionFailed
        }
        try manager.removeItem(at: source)
    }

    private static func runOpenSSL(source: URL, output: URL, passwordData: Data, decrypt: Bool) throws {
        let input = Pipe()
        let errors = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["enc", "-aes-256-cbc", "-A"] + (decrypt ? ["-d"] : [])
            + ["-in", source.path, "-out", output.path, "-pass", "stdin"]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errors
        try process.run()

        do {
            try input.fileHandleForWriting.write(contentsOf: passwordData)
            try input.fileHandleForWriting.close()
        } catch {
            try? input.fileHandleForWriting.close()
            _ = errors.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            throw Failure.conversionFailed
        }

        // Drain stderr before waiting, so a full pipe cannot deadlock the child.
        // Do not log crypto-tool diagnostics or any credential material.
        _ = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw Failure.conversionFailed
        }
    }
}
