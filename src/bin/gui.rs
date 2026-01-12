use eframe::egui;
use rfd::FileDialog;
use sign_ur_code::{crypto, keystore};
use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([600.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Sign Ur Code - Secure GUI",
        options,
        Box::new(|_cc| Ok(Box::new(SignerApp::default()))),
    )
}

#[derive(Default)]
struct SignerApp {
    tab: AppTab,
    // Keygen State
    keygen_out_dir: Option<PathBuf>,
    keygen_pass: String,
    keygen_confirm: String,
    keygen_status: String,

    // Sign State
    sign_key_path: Option<PathBuf>,
    sign_file_path: Option<PathBuf>,
    sign_pass: String,
    sign_status: String,

    // Verify State
    verify_key_path: Option<PathBuf>,
    verify_file_path: Option<PathBuf>,
    verify_status: String,
}

#[derive(Default, PartialEq)]
enum AppTab {
    #[default]
    Keygen,
    Sign,
    Verify,
}

impl eframe::App for SignerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 Sign Ur Code");
            ui.separator();

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, AppTab::Keygen, "Gen Keys");
                ui.selectable_value(&mut self.tab, AppTab::Sign, "Sign File");
                ui.selectable_value(&mut self.tab, AppTab::Verify, "Verify");
            });
            ui.separator();

            match self.tab {
                AppTab::Keygen => self.ui_keygen(ui),
                AppTab::Sign => self.ui_sign(ui),
                AppTab::Verify => self.ui_verify(ui),
            }
        });
    }
}

impl SignerApp {
    fn ui_keygen(&mut self, ui: &mut egui::Ui) {
        ui.label("Generate new high-security Ed25519 keys.");

        if ui.button("Select Output Directory").clicked()
            && let Some(path) = FileDialog::new().pick_folder() {
                self.keygen_out_dir = Some(path);
            }
        if let Some(path) = &self.keygen_out_dir {
            ui.label(format!("Output: {:?}", path));
        }

        ui.add(
            egui::TextEdit::singleline(&mut self.keygen_pass)
                .password(true)
                .hint_text("Passphrase"),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.keygen_confirm)
                .password(true)
                .hint_text("Confirm Passphrase"),
        );

        if ui.button("Generate Keys").clicked() {
            if self.keygen_pass != self.keygen_confirm {
                self.keygen_status = "❌ Passphrases do not match!".to_string();
                return;
            }
            if self.keygen_pass.len() < 8 {
                self.keygen_status = "❌ Passphrase too short!".to_string();
                return;
            }
            if let Some(out_dir) = &self.keygen_out_dir {
                let res = std::thread::scope(|_| {
                    let keypair = crypto::generate_keypair();
                    let encrypted = crypto::encrypt_private_key(&keypair, &self.keygen_pass)?;

                    let priv_path = out_dir.join("private.enc.key");
                    let priv_json = serde_json::to_string_pretty(&encrypted)?;
                    std::fs::write(&priv_path, priv_json)?;

                    let pub_path = out_dir.join("public.key");
                    let pub_key_bytes = keypair.verifying_key().to_bytes();
                    let pub_hex = hex::encode(pub_key_bytes);
                    std::fs::write(&pub_path, pub_hex)?;
                    Ok::<_, anyhow::Error>(())
                });

                match res {
                    Ok(_) => self.keygen_status = "✅ Keys generated successfully!".to_string(),
                    Err(e) => self.keygen_status = format!("❌ Error: {}", e),
                }
            } else {
                self.keygen_status = "❌ Select output directory first.".to_string();
            }
        }
        ui.label(&self.keygen_status);
    }

    fn ui_sign(&mut self, ui: &mut egui::Ui) {
        if ui.button("Select Encrypted Key").clicked()
            && let Some(path) = FileDialog::new().add_filter("Key", &["key"]).pick_file() {
                self.sign_key_path = Some(path);
            }
        if let Some(path) = &self.sign_key_path {
            ui.label(format!("Key: {:?}", path));
        }

        if ui.button("Select File to Sign").clicked()
            && let Some(path) = FileDialog::new().pick_file() {
                self.sign_file_path = Some(path);
            }
        if let Some(path) = &self.sign_file_path {
            ui.label(format!("File: {:?}", path));
        }

        ui.add(
            egui::TextEdit::singleline(&mut self.sign_pass)
                .password(true)
                .hint_text("Key Passphrase"),
        );

        if ui.button("Sign File").clicked() {
            if let (Some(key_path), Some(file_path)) = (&self.sign_key_path, &self.sign_file_path) {
                let key_content_res = std::fs::read_to_string(key_path);

                match key_content_res {
                    Ok(content) => {
                        let parse_res: Result<keystore::EncryptedKeyFile, _> =
                            serde_json::from_str(&content);
                        match parse_res {
                            Ok(enc_key) => {
                                let decrypt_res =
                                    crypto::decrypt_private_key(&enc_key, &self.sign_pass);
                                match decrypt_res {
                                    Ok(signing_key) => {
                                        match std::fs::read(file_path) {
                                            Ok(data) => {
                                                use ed25519_dalek::Signer; // Import trait
                                                let sig = signing_key.sign(&data);
                                                let sig_path =
                                                    format!("{}.sig", file_path.display());
                                                if std::fs::write(
                                                    &sig_path,
                                                    hex::encode(sig.to_bytes()),
                                                ).is_ok() {
                                                    self.sign_status =
                                                        format!("✅ Signed: {}", sig_path);
                                                } else {
                                                    self.sign_status =
                                                        "❌ Failed to write signature".to_string();
                                                }
                                            }
                                            Err(e) => {
                                                self.sign_status =
                                                    format!("❌ File read error: {}", e)
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        self.sign_status =
                                            "❌ Wrong password or corrupt key".to_string()
                                    }
                                }
                            }
                            Err(_) => self.sign_status = "❌ Invalid key file format".to_string(),
                        }
                    }
                    Err(_) => self.sign_status = "❌ Could not read key file".to_string(),
                }
            } else {
                self.sign_status = "❌ Select key and file first.".to_string();
            }
        }
        ui.label(&self.sign_status);
    }

    fn ui_verify(&mut self, ui: &mut egui::Ui) {
        if ui.button("Select Public Key").clicked()
            && let Some(path) = FileDialog::new().add_filter("Key", &["key"]).pick_file() {
                self.verify_key_path = Some(path);
            }
        if let Some(path) = &self.verify_key_path {
            ui.label(format!("Pub Key: {:?}", path));
        }

        if ui.button("Select File to Verify").clicked()
            && let Some(path) = FileDialog::new().pick_file() {
                self.verify_file_path = Some(path);
            }
        if let Some(path) = &self.verify_file_path {
            ui.label(format!("File: {:?}", path));
        }

        if ui.button("Verify Signature").clicked() {
            if let (Some(key_path), Some(file_path)) =
                (&self.verify_key_path, &self.verify_file_path)
            {
                // Try to find sig automatically if not selected (simplified GUI logic)
                let sig_path = PathBuf::from(format!("{}.sig", file_path.display()));

                if sig_path.exists() {
                    // Verify logic
                    let pub_res = std::fs::read_to_string(key_path);
                    let sig_res = std::fs::read_to_string(&sig_path);
                    let data_res = std::fs::read(file_path);

                    if let (Ok(pub_hex), Ok(sig_hex), Ok(data)) = (pub_res, sig_res, data_res) {
                        if let (Ok(pub_bytes), Ok(sig_bytes)) =
                            (hex::decode(pub_hex.trim()), hex::decode(sig_hex.trim()))
                        {
                            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                            let vk_res =
                                VerifyingKey::from_bytes(&pub_bytes.try_into().unwrap_or([0; 32]));
                            let sig =
                                Signature::from_bytes(&sig_bytes.try_into().unwrap_or([0; 64]));

                            if let Ok(vk) = vk_res {
                                match vk.verify(&data, &sig) {
                                    Ok(_) => self.verify_status = "✅ Valid Signature!".to_string(),
                                    Err(_) => {
                                        self.verify_status = "❌ Invalid Signature".to_string()
                                    }
                                }
                            } else {
                                self.verify_status = "❌ Invalid Key/Sig Format".to_string();
                            }
                        } else {
                            self.verify_status = "❌ Hex Decode Error".to_string();
                        }
                    } else {
                        self.verify_status = "❌ File Read Error".to_string();
                    }
                } else {
                    self.verify_status = "❌ Signature file (.sig) not found".to_string();
                }
            } else {
                self.verify_status = "❌ Select key and file first".to_string();
            }
        }
        ui.label(&self.verify_status);
    }
}
