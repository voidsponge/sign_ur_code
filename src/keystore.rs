use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct Argon2Params {
    pub salt: String, // Base64 encoded
    pub iterations: u32,
    pub memory: u32,
    pub parallelism: u32,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    pub kdf_params: Argon2Params,
    pub nonce: String, // Base64 encoded
    pub ciphertext: String, // Base64 encoded
}

impl Drop for EncryptedKeyFile {
    fn drop(&mut self) {
        // Best effort clearing
        // Strings in Rust are hard to zeroize reliably on drop if they reallocate, 
        // but this struct mostly holds public params + ciphertext. 
        // The sensitive one is the decrypted key, which we handle elsewhere.
    }
}
