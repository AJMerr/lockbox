use clap::{Parser, Subcommand};
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
    fn load(path: &PathBuf) -> Self {
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
        serde_json::from_reader(reader).unwrap_or_else(|_| Store {
            next_id: 1,
            vault_items: vec![],
        })
    }

    fn save(&self, path: &PathBuf) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self).expect("serialize_error");
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.unwrap_or_else(|| PathBuf::from("db.json"));

    let mut store = Store::load(&db_path);

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
            Added the following\nID: {}\nService: {}\nUsername: {}\nPassword: {}
                ",
                pushed.id, pushed.service, pushed.username, pushed.password
            );
            store.save(&db_path)?;
        }
    }

    Ok(())
}
