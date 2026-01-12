use crate::keystore::{Argon2Params, EncryptedKeyFile};
use anyhow::{Context, Result};
use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn encrypt_private_key(key: &SigningKey, password: &str) -> Result<EncryptedKeyFile> {
    let salt = SaltString::generate(&mut OsRng);

    // Argon2id parameters
    let params = Params::new(65536, 3, 4, None)
        .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?; // 64MB, 3 iterations, 4 lanes
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    // Derive KEK (Key Encryption Key)
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Argon2 error: {}", e))?;

    // Use the hash output as the key for XChaCha20Poly1305 (32 bytes required)
    let kek = password_hash.hash.context("Failed to get hash output")?;
    let mut key_bytes = [0u8; 32];
    if kek.len() != 32 {
        return Err(anyhow::anyhow!("Derived key length is not 32 bytes"));
    }
    key_bytes.copy_from_slice(kek.as_bytes());
    let kek_zeroizing = Zeroizing::new(key_bytes);

    // Encrypt
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*kek_zeroizing));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24 bytes
    let ciphertext = cipher
        .encrypt(&nonce, key.to_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failure: {}", e))?;

    Ok(EncryptedKeyFile {
        kdf_params: Argon2Params {
            salt: salt.as_str().to_string(),
            iterations: params.t_cost(),
            memory: params.m_cost(),
            parallelism: params.p_cost(),
        },
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
}

pub fn decrypt_private_key(encrypted: &EncryptedKeyFile, password: &str) -> Result<SigningKey> {
    // Reconstruct salt and params
    let salt = SaltString::from_b64(&encrypted.kdf_params.salt)
        .map_err(|e| anyhow::anyhow!("Invalid salt: {}", e))?;

    let params = Params::new(
        encrypted.kdf_params.memory,
        encrypted.kdf_params.iterations,
        encrypted.kdf_params.parallelism,
        None,
    )
    .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Derive KEK
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Argon2 error: {}", e))?;

    let kek = password_hash.hash.context("Failed to get hash")?;
    if kek.len() != 32 {
        return Err(anyhow::anyhow!("Derivation mismatch"));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(kek.as_bytes());
    let kek_zeroizing = Zeroizing::new(key_bytes);

    // Decrypt
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*kek_zeroizing));
    let nonce_bytes = BASE64.decode(&encrypted.nonce)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = BASE64.decode(&encrypted.ciphertext)?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Invalid password or corrupted key"))?;

    let signing_key_bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    Ok(signing_key)
}

pub fn sign_data(key: &SigningKey, data: &[u8]) -> Signature {
    key.sign(data)
}

pub fn verify_signature(key: &VerifyingKey, data: &[u8], sig: &Signature) -> Result<()> {
    key.verify(data, sig)
        .map_err(|e| anyhow::anyhow!("Verification failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        let key = generate_keypair();
        let data = b"Hello, world!";
        let sig = sign_data(&key, data);
        assert!(verify_signature(&key.verifying_key(), data, &sig).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_keypair();
        let password = "strong_password";
        let encrypted = encrypt_private_key(&key, password).expect("Encryption failed");
        let decrypted = decrypt_private_key(&encrypted, password).expect("Decryption failed");
        assert_eq!(key.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_bad_password() {
        let key = generate_keypair();
        let password = "correct";
        let encrypted = encrypt_private_key(&key, password).unwrap();
        let result = decrypt_private_key(&encrypted, "wrong");
        assert!(result.is_err());
    }
}
