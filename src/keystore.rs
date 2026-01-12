use serde::{Deserialize, Serialize};

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
    pub nonce: String,      // Base64 encoded
    pub ciphertext: String, // Base64 encoded
}


