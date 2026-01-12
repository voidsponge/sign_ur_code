# 🔐 Sign Ur Code

**The "Must-Have" Cyber Security Tool for Code Signing.**

`sign_ur_code` is a high-security command-line interface (CLI) tool written in Rust, designed to protect your software supply chain. It allows you to generate secure keys, sign assets, and verify signatures with state-of-the-art cryptography.

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

## 📦 Project Structure

*   `src/crypto.rs`: The secure core. Handles Argon2id derivation, XChaCha20Poly1305 encryption, and Ed25519 operations with strict memory zeroization.
*   `src/keystore.rs`: Defines the secure JSON storage format for encrypted keys.
*   `src/main.rs`: The CLI entry point handling user interaction and command dispatch.

---
*Built with ❤️ and Rust.*