# 🔐 Sign Ur Code

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security: High](https://img.shields.io/badge/Security-High-green.svg)](src/crypto.rs)

**The "Must-Have" Cyber Security Tool for Code Signing.**

`sign_ur_code` is a high-security command-line interface (CLI) and Graphical User Interface (GUI) tool written in pure Rust, designed to protect your software supply chain. It allows you to generate secure keys, sign assets, and verify signatures with state-of-the-art cryptography.


## 🛡️ Security Architecture

This tool is built with a "paranoic" security mindset:

*   **🔒 Authenticated Encryption**: Private keys are **never** stored in plaintext. They are encrypted using **XChaCha20Poly1305** (AEAD), ensuring both confidentiality and integrity.
*   **🧠 Robust Key Derivation**: Passphrases are hardened using **Argon2id** (Winner of the Password Hashing Competition), configured with high memory parameters (64MB) to resist GPU brute-force attacks.
*   **🧹 Memory Safety**: Utilizing the `zeroize` crate, all sensitive key material is securely wiped from RAM immediately after use, protecting against cold boot attacks and memory dumps.
*   **⚡ Modern Primitive**: Signatures are generated using **Ed25519**, offering high performance and strong security (128-bit security level) without the pitfalls of older standards like RSA.

## 🚀 Installation

Ensure you have Rust installed. Clone the repository and build the release version:

```bash
git clone https://github.com/voidsponge/sign_ur_code.git
cd sign_ur_code
cargo build --release
```

The binary will be available in `target/release/sign_ur_code`.

## 📖 Usage

### 1. Generate High-Security Keys 🔑
Generate a new Ed25519 keypair. You will be prompted for a strong passphrase.

```bash
cargo run -- keygen --out keys
```
*   **Output**:
    *   `keys/private.enc.key`: The encrypted private key (Keep this safe! 🛑).
    *   `keys/public.key`: The public key (Share this with the world 🌍).

### 2. Sign an Artifact ✍️
Sign a file (e.g., a binary, zip, or configuration file).

```bash
cargo run -- sign --key keys/private.enc.key --file release.zip
```
*   Prompts for your passphrase to temporarily decrypt the key in memory.
*   **Output**: `release.zip.sig` (The detached signature).

### 3. Verify a Signature ✅
Verify that a file has not been tampered with.

```bash
cargo run -- verify --key keys/public.key --file release.zip
```
*   **Output**:
    *   `✅ Verification SUCCESS: Signature is valid.`
    *   `❌ Verification FAILED`: The file is corrupted or the signature is invalid.

### 4. Graphical Interface (GUI) 🖥️
Prefer a visual interface? Launch the secure GUI mode:

```bash
cargo run --bin gui
# Or release mode:
cargo run --release --bin gui
```

## 📦 Project Structure

*   `src/lib.rs`: The shared library exposing core logic.
*   `src/crypto.rs`: The secure core. Handles Argon2id derivation, XChaCha20Poly1305 encryption, and Ed25519 operations with strict memory zeroization.
*   `src/keystore.rs`: Defines the secure JSON storage format for encrypted keys.
*   `src/bin/cli.rs`: The CLI entry point.
*   `src/bin/gui.rs`: The GUI entry point (eframe/egui).

---
## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## ⚠️ Verified Security

This tool uses:
- **Argon2id**: v0.5.3 (m=64MB, t=3, p=4)
- **XChaCha20Poly1305**: v0.10.1 (IETF standard)
- **Ed25519-Dalek**: v2.2.0 (Verified assembly backend)
- **Zeroize**: v1.8.2 (Memory clearing on drop)

*Built with ❤️ and Rust.*
