use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose;
use clap::{Parser, Subcommand};
use orion::aead;
use orion::kdf::{self, Password, Salt};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufReader, Write},
    path::PathBuf,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Vault {
    id: usize,
    service: String,
    username: String,
    password: String,
}

impl Vault {
    fn new(id: usize, service: String, username: String, password: String) -> Self {
        Self {
            id,
            service,
            username,
            password,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    next_id: usize,
    vault_items: Vec<Vault>,
}

impl Store {
    fn load(path: &PathBuf, master: &str) -> Self {
        if !path.exists() {
            return Store {
                next_id: 1,
                vault_items: vec![],
            };
        }
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                return Store {
                    next_id: 1,
                    vault_items: vec![],
                };
            }
        };
        let reader = BufReader::new(file);
        match serde_json::from_reader::<_, EncryptedFile>(reader) {
            Ok(enc) => decrypt_store(&enc, master).unwrap_or_else(|e| {
                eprintln!("{e}");
                Store {
                    next_id: 1,
                    vault_items: vec![],
                }
            }),
            Err(_) => {
                let file = match File::open(path) {
                    Ok(f) => f,
                    Err(_) => {
                        return Store {
                            next_id: 1,
                            vault_items: vec![],
                        };
                    }
                };
                let reader = BufReader::new(file);
                serde_json::from_reader(reader).unwrap_or(Store {
                    next_id: 1,
                    vault_items: vec![],
                })
            }
        }
    }

    fn save(&self, path: &PathBuf, master: &str) -> std::io::Result<()> {
        let enc = encrypt_store(self, master)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let json = serde_json::to_vec_pretty(&enc).expect("serialize_error");

        let tmp = path.with_extension("json.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&json)?;
            f.flush()?;
        }
        fs::rename(tmp, path)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    salt_b64: String,
    kdf_iterations: u32,
    kdf_memory_kib: u32,
    blob_b64: String,
}

fn encrypt_store(store: &Store, master: &str) -> anyhow::Result<EncryptedFile> {
    let salt = Salt::default();
    let iters = 3;
    let memory_kib = 1 << 16;

    let password = Password::from_slice(master.as_bytes())?;
    let dk = kdf::derive_key(&password, &salt, iters, memory_kib, 32)?;
    let key = orion::aead::SecretKey::from_slice(dk.unprotected_as_bytes())?;

    let plaintext = serde_json::to_vec(store).context("serialize_store")?;

    let blob = aead::seal(&key, &plaintext).context("encryption_failed")?;

    Ok(EncryptedFile {
        salt_b64: general_purpose::STANDARD.encode(salt.as_ref()),
        kdf_iterations: iters,
        kdf_memory_kib: memory_kib,
        blob_b64: general_purpose::STANDARD.encode(&blob),
    })
}

fn decrypt_store(enc: &EncryptedFile, master: &str) -> anyhow::Result<Store> {
    let salt_bytes = general_purpose::STANDARD
        .decode(&enc.salt_b64)
        .context("decoded_salt")?;
    let salt = Salt::from_slice(&salt_bytes)?;
    let blob = general_purpose::STANDARD
        .decode(&enc.blob_b64)
        .context("decode_blob")?;

    let password = Password::from_slice(master.as_bytes())?;
    let dk = kdf::derive_key(&password, &salt, enc.kdf_iterations, enc.kdf_memory_kib, 32)?;
    let key = orion::aead::SecretKey::from_slice(dk.unprotected_as_bytes())?;

    let plaintext = aead::open(&key, &blob).context("decryption_failed")?;

    Ok(serde_json::from_slice(&plaintext).context("deserialize error")?)
}

#[derive(Debug, Parser)]
#[command(name = "locbox", version, about = "Lightweight CLI password manager.")]
struct Cli {
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Add {
        service: String,
        username: String,
        password: String,
    },
    Remove {
        id: usize,
    },
    List,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.unwrap_or_else(|| PathBuf::from("db.json"));

    let mut master = prompt_password("Master password: ")?;
    let mut store = Store::load(&db_path, &master);

    match cli.command {
        Commands::Add {
            service,
            username,
            password,
        } => {
            let id = store.next_id;
            store.next_id += 1;
            store
                .vault_items
                .push(Vault::new(id, service, username, password));
            let pushed = store.vault_items.last().expect("Just pushed");
            println!(
                "
            Added the following:\nID: {}\nService: {}\nUsername: {}\nPassword: {}
                ",
                pushed.id, pushed.service, pushed.username, pushed.password
            );
            store.save(&db_path, &master)?;
        }
        Commands::Remove { id } => {
            if let Some(pos) = store.vault_items.iter().position(|v| v.id == id) {
                store.vault_items.remove(pos);
                store.save(&db_path, &master)?;
                println!("Removed Service with ID: {id}");
            } else {
                println!("Unable to find service with the ID: {id}");
            }
        }
        Commands::List => {
            for i in &store.vault_items {
                println!("{} | {} | {} | {}", i.id, i.service, i.username, i.password);
            }
        }
    }

    Ok(())
}
