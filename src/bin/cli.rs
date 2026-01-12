use sign_ur_code::{crypto, keystore};

use anyhow::{Context, Result};

use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use std::fs;

use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sign_ur_code")]
#[command(about = "A high-security code signing tool in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new encrypted keypair
    Keygen {
        /// Output directory for keys
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
    },
    /// Sign a file
    Sign {
        /// Path to the encrypted private key
        #[arg(short, long)]
        key: PathBuf,
        /// File to sign
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Verify a signature
    Verify {
        /// Path to the public key
        #[arg(short, long)]
        key: PathBuf,
        /// File to verify
        #[arg(short, long)]
        file: PathBuf,
        /// Signature file (defaults to file.sig)
        #[arg(short, long)]
        sig: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out } => {
            println!("Generating new high-security Ed25519 keypair...");
            let password = rpassword::prompt_password("Enter passphrase to encrypt private key: ")?;
            let confirm = rpassword::prompt_password("Confirm passphrase: ")?;

            if password != confirm {
                anyhow::bail!("Passphrases do not match!");
            }

            if password.len() < 8 {
                println!("Warning: Passphrase is short. Recommend 12+ characters.");
            }

            let keypair = crypto::generate_keypair();
            let encrypted = crypto::encrypt_private_key(&keypair, &password)?;

            fs::create_dir_all(&out)?;

            // Save Private Key
            let priv_path = out.join("private.enc.key");
            let priv_json = serde_json::to_string_pretty(&encrypted)?;
            fs::write(&priv_path, priv_json)?;
            println!("Saved encrypted private key to: {:?}", priv_path);

            // Save Public Key
            let pub_path = out.join("public.key");
            let pub_key_bytes = keypair.verifying_key().to_bytes();
            let pub_hex = hex::encode(pub_key_bytes);
            fs::write(&pub_path, pub_hex)?;
            println!("Saved public key to: {:?}", pub_path);
        }
        Commands::Sign { key, file } => {
            let password = rpassword::prompt_password("Enter passphrase for private key: ")?;

            let key_content = fs::read_to_string(&key).context("Failed to read key file")?;
            let encrypted_key: keystore::EncryptedKeyFile =
                serde_json::from_str(&key_content).context("Failed to parse key file format")?;

            let signing_key = crypto::decrypt_private_key(&encrypted_key, &password)
                .context("Failed to decrypt key (wrong password?)")?;

            let data = fs::read(&file).context("Failed to read target file")?;
            let signature = crypto::sign_data(&signing_key, &data); // signing_key is zeroized on drop

            let sig_path = format!("{}.sig", file.display());
            let sig_hex = hex::encode(signature.to_bytes());
            fs::write(&sig_path, sig_hex)?;
            println!("File signed successfully. Signature saved to: {}", sig_path);
        }
        Commands::Verify { key, file, sig } => {
            let pub_content = fs::read_to_string(&key).context("Failed to read public key")?;
            let pub_bytes = hex::decode(pub_content.trim()).context("Invalid public key hex")?;
            let pub_key = VerifyingKey::from_bytes(
                &pub_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
            )?;

            let data = fs::read(&file).context("Failed to read target file")?;

            let sig_path = sig.unwrap_or_else(|| PathBuf::from(format!("{}.sig", file.display())));
            let sig_content =
                fs::read_to_string(&sig_path).context("Failed to read signature file")?;
            let sig_bytes = hex::decode(sig_content.trim()).context("Invalid signature hex")?;
            let signature = ed25519_dalek::Signature::from_bytes(
                &sig_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid signature length"))?,
            );

            match crypto::verify_signature(&pub_key, &data, &signature) {
                Ok(_) => println!("✅ Verification SUCCESS: Signature is valid."),
                Err(e) => {
                    println!("❌ Verification FAILED: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
