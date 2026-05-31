//! crypty-keygen — Generate and manage Arsenic X25519 keypairs.
//!
//! Usage
//! -----
//! ```
//! # Generate to stdout:
//! crypty-keygen -n alice
//!
//! # Save directly to the shared keystore (~/.config/cryptyrust/keys/):
//! crypty-keygen -n alice --store
//!
//! # Save to a specific file:
//! crypty-keygen -n alice -o alice.key
//!
//! # List all keys in the keystore:
//! crypty-keygen --list
//!
//! # Convert an identity file to its public key:
//! crypty-keygen -y alice.key
//! ```

use anyhow::{Context, Result};
use arsenic::{
    encode_pubkey,
    keystore::{keys_dir, load_keystore, save_key, KeyEntry},
};
use clap::Parser;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

// ── CLI definition ────────────────────────────────────────────────────────────

/// Generate and manage Arsenic X25519 keypairs.
#[derive(Parser)]
#[clap(name = "crypty-keygen", version, author)]
struct Cli {
    /// Name to embed in the key file.
    #[clap(short, long, value_name = "NAME", default_value = "")]
    name: String,

    /// Save the new keypair directly to the shared keystore
    /// (`{config}/cryptyrust/keys/`).  Implies the key is also
    /// available to the GUI and CLI without specifying `-i`.
    #[clap(short, long)]
    store: bool,

    /// Write the identity file to OUTPUT instead of stdout.
    /// The file is created with 0600 permissions on Unix.
    #[clap(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// List all keypairs stored in the shared keystore and exit.
    #[clap(short, long)]
    list: bool,

    /// Convert identity file(s) to their public keys and print to stdout.
    /// Pass `-` to read from stdin.
    #[clap(short = 'y', long = "to-public", value_name = "IDENTITY", num_args = 1..)]
    to_public: Vec<String>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list {
        return cmd_list();
    }

    if !cli.to_public.is_empty() {
        return cmd_to_public(&cli.to_public);
    }

    cmd_generate(&cli)
}

// ── List stored keys ──────────────────────────────────────────────────────────

fn cmd_list() -> Result<()> {
    let keys = load_keystore();
    if keys.is_empty() {
        let dir = keys_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".into());
        println!("No keypairs found in keystore ({dir}).");
        return Ok(());
    }
    println!("{:<20} {}", "Name", "Public key");
    println!("{}", "─".repeat(80));
    for key in &keys {
        println!("{:<20} {}", key.name, encode_pubkey(&key.public_key));
    }
    Ok(())
}

// ── Generate ──────────────────────────────────────────────────────────────────

fn cmd_generate(cli: &Cli) -> Result<()> {
    let name = if cli.store && cli.name.is_empty() {
        // Require a name when storing to keystore
        return Err(anyhow::anyhow!(
            "--name is required when using --store"
        ));
    } else {
        cli.name.clone()
    };

    let mut entry = KeyEntry::generate(name.clone());
    let pub_enc = encode_pubkey(&entry.public_key);

    if cli.store {
        save_key(&mut entry).map_err(|e| anyhow::anyhow!(e))?;
        let path = entry.file_path.as_ref().unwrap();
        eprintln!("Identity written to: {}", path.display());
        eprintln!("Public key: {pub_enc}");
    } else if let Some(path) = &cli.output {
        let content = arsenic::keystore::serialize_identity(&entry);
        write_identity_file(path, &content)
            .with_context(|| format!("cannot write to {}", path.display()))?;
        eprintln!("Identity written to: {}", path.display());
        eprintln!("Public key: {pub_enc}");
    } else {
        let content = arsenic::keystore::serialize_identity(&entry);
        print!("{content}");
        eprintln!("Public key: {pub_enc}");
    }

    Ok(())
}

// ── Convert identity → public key ─────────────────────────────────────────────

fn cmd_to_public(sources: &[String]) -> Result<()> {
    for source in sources {
        let content = if source == "-" {
            let stdin = io::stdin();
            stdin.lock().lines().collect::<io::Result<Vec<_>>>()?.join("\n")
        } else {
            std::fs::read_to_string(source)
                .with_context(|| format!("cannot read {source}"))?
        };

        let path = std::path::PathBuf::from(source);
        let entry = arsenic::keystore::parse_identity(&content, path)
            .ok_or_else(|| anyhow::anyhow!("no valid private key found in {source}"))?;
        println!("{}", encode_pubkey(&entry.public_key));
    }
    Ok(())
}

// ── File writing (0600 on Unix) ───────────────────────────────────────────────

#[cfg(unix)]
fn write_identity_file(path: &std::path::Path, content: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true).create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_identity_file(path: &std::path::Path, content: &str) -> Result<()> {
    if path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }
    std::fs::write(path, content)?;
    Ok(())
}
