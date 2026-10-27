# KeyCover crypto regression checks

On macOS with Swift command line tools installed, run from the repository root:

```sh
sh Tests/run-keycover-crypto-tests.sh
```

The executable compiles the production KeyCoverCrypto implementation directly, without
requiring Xcode, application signing, third-party dependencies, or access to real credentials.
Fixtures live in a temporary directory and use a public, test-only password.

Coverage includes legacy OpenSSL compatibility in both directions, output permissions,
wrong passwords, corrupt ciphertext, missing input, failed publication, invalid passwords,
identical input/output paths, non-SQLite decrypted output, large files, and temporary-file cleanup.

The production change retains AES-256-CBC and the existing OpenSSL key derivation for
compatibility. It does not migrate to authenticated encryption, and the SQLite header check
is only a sanity check, not cryptographic authentication or full database validation.
Password rotation, Keychain master-key storage, and the complete App UI need separate
integration testing. A full PlayCover build still requires Xcode and its normal dependencies.
