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

fn main() {}
