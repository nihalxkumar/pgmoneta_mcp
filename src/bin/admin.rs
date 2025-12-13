// Copyright (C) 2025 The pgmoneta community
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
use anyhow::Result;
use clap::{Parser, Subcommand};
use pgmoneta_mcp::constant::*;

#[derive(Parser, Debug)]
#[command(
    name = "pgmoneta-mcp-admin",
    about = "Pgmoneta-mcp admin tool"
)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// User related operations
    User {
        /// The user configuration file
        #[arg(short, long, default_value = DEFAULT_USER_CONF)]
        file: String,
        #[command(subcommand)]
        action: UserAction,
        /// The admin user
        #[arg(short = 'U', long)]
        user: String,
    },
    MasterKey,
}

#[derive(Subcommand, Debug)]
enum UserAction {
    /// Add a new user to configuration file, the file will be automatically created if not exist.
    /// If the user exists, new password will be set to the existing user.
    Add {
        /// The admin user password
        #[arg(short, long)]
        password: String,
    }
}
fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::User { action, user, file } => {
            match action {
                UserAction::Add { password } => {
                    User::set_user(&file, &user, &password)?
                }
            }
        }
        Commands::MasterKey => {}
    }
    Ok(())
}

struct User;
impl User {
    pub fn set_user(file: &str, user: &str, password: &str) -> Result<()> {
        Ok(())
    }
}

struct MasterKey;

impl MasterKey {
    pub fn set_master_key(master_key: &str) -> Result<()> {
        Ok(())
    }
}