// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use configuration::UserConf;
use pgmoneta_mcp::configuration;
use pgmoneta_mcp::security::SecurityUtil;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(
    name = "pgmoneta-mcp-admin",
    about = "Administration utility for pgmoneta-mcp",
    version
)]
struct Args {
    /// The user configuration file
    #[arg(short = 'f', long)]
    file: Option<String>,

    /// The user name
    #[arg(short = 'U', long)]
    user: Option<String>,

    /// The password for the user
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Generate a password
    #[arg(short = 'g', long)]
    generate: bool,

    /// Password length (default: 64)
    #[arg(short = 'l', long, default_value = "64")]
    length: usize,

    /// Output format
    #[arg(short = 'F', long, value_enum, default_value = "text")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create or update the master key
    MasterKey,
    /// Manage a specific user
    User {
        #[command(subcommand)]
        action: UserAction,
    },
}

#[derive(Subcommand, Debug)]
enum UserAction {
    /// Add a new user to configuration file
    Add,
    /// Remove an existing user
    Del,
    /// Change the password for an existing user
    Edit,
    /// List all available users
    Ls,
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminResponse {
    command: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    users: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_password: Option<String>,
}
fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::MasterKey => {
            MasterKey::set_master_key()?;
        }
        Commands::User { action } => {
            let file = args
                .file
                .as_ref()
                .ok_or_else(|| anyhow!("Missing required argument: -f, --file <FILE>"))?;

            match action {
                UserAction::Add => {
                    let user = args
                        .user
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing required argument: -U, --user <USER>"))?;
                    let password = args.password.as_deref().ok_or_else(|| {
                        anyhow!("Missing required argument: -P, --password <PASSWORD>")
                    })?;
                    User::set_user(file, user, password)?;
                }
                UserAction::Del => return Err(anyhow!("User del is not implemented yet")),
                UserAction::Edit => return Err(anyhow!("User edit is not implemented yet")),
                UserAction::Ls => return Err(anyhow!("User ls is not implemented yet")),
            }
        }
    }

    Ok(())
}

struct User;
impl User {
    pub fn set_user(file: &str, user: &str, password: &str) -> Result<()> {
        let path = Path::new(file);
        let sutil = SecurityUtil::new();
        let mut conf: UserConf;
        let master_key = sutil.load_master_key().map_err(|e| {
            anyhow!(
                "Unable to load the master key, needed for adding user: {:?}",
                e
            )
        })?;
        let password_str = sutil.encrypt_to_base64_string(password.as_bytes(), &master_key[..])?;

        if !path.exists() || path.is_dir() {
            conf = HashMap::new();
            let mut user_conf: HashMap<String, String> = HashMap::new();
            user_conf.insert(user.to_string(), password_str);
            conf.insert("admins".to_string(), user_conf);
        } else {
            conf = configuration::load_user_configuration(file)?;
            if let Some(user_conf) = conf.get_mut("admins") {
                user_conf.insert(user.to_string(), password_str);
            } else {
                return Err(anyhow!("Unable to find admins in user configuration"));
            }
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conf_str = serde_ini::to_string(&conf)?;
        fs::write(file, &conf_str)?;

        Ok(())
    }
}

struct MasterKey;

impl MasterKey {
    pub fn set_master_key() -> Result<()> {
        let sutil = SecurityUtil::new();
        let master_key = prompt_password("Please enter your master key").unwrap();
        let m = prompt_password("Please enter your master key again").unwrap();

        if master_key != m {
            return Err(anyhow!("Passwords do not match"));
        }

        sutil.write_master_key(&master_key)
    }
}
