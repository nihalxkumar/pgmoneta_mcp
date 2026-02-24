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
                UserAction::Del => {
                    let user = args
                        .user
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing required argument: -U, --user <USER>"))?;
                    User::remove_user(file, user)?;
                }
                UserAction::Edit => {
                    let user = args
                        .user
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing required argument: -U, --user <USER>"))?;
                    let password = args.password.as_deref().ok_or_else(|| {
                        anyhow!("Missing required argument: -P, --password <PASSWORD>")
                    })?;
                    User::edit_user(file, user, password)?;
                }
                UserAction::Ls => {
                    User::list_users(file)?;
                }
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

    pub fn remove_user(file: &str, user: &str) -> Result<()> {
        let path = Path::new(file);

        if !path.exists() {
            return Err(anyhow!("User file '{}' does not exist", file));
        }

        let mut conf = configuration::load_user_configuration(file)?;

        if let Some(user_conf) = conf.get_mut("admins") {
            if user_conf.remove(user).is_none() {
                return Err(anyhow!("User '{}' not found", user));
            }
        } else {
            return Err(anyhow!(
                "Unable to find admins section in user configuration"
            ));
        }

        let conf_str = serde_ini::to_string(&conf)?;
        fs::write(file, &conf_str)?;

        Ok(())
    }

    pub fn edit_user(file: &str, user: &str, password: &str) -> Result<()> {
        let path = Path::new(file);
        let sutil = SecurityUtil::new();

        if !path.exists() {
            return Err(anyhow!("User file '{}' does not exist", file));
        }

        let master_key = sutil.load_master_key().map_err(|e| {
            anyhow!(
                "Unable to load the master key, needed for editing user: {:?}",
                e
            )
        })?;

        let password_str = sutil.encrypt_to_base64_string(password.as_bytes(), &master_key[..])?;

        let mut conf = configuration::load_user_configuration(file)?;

        if let Some(user_conf) = conf.get_mut("admins") {
            if user_conf.get(user).is_none() {
                return Err(anyhow!("User '{}' not found", user));
            }
            user_conf.insert(user.to_string(), password_str);
        } else {
            return Err(anyhow!(
                "Unable to find admins section in user configuration"
            ));
        }

        let conf_str = serde_ini::to_string(&conf)?;
        fs::write(file, &conf_str)?;

        Ok(())
    }

    pub fn list_users(file: &str) -> Result<()> {
        let path = Path::new(file);

        if !path.exists() {
            return Ok(());
        }

        let conf = configuration::load_user_configuration(file)?;
        let users: Vec<String> = conf
            .get("admins")
            .map(|user_conf| user_conf.keys().cloned().collect())
            .unwrap_or_default();

        for user in users {
            println!("{}", user);
        }

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
