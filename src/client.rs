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

mod info;

use anyhow::anyhow;
use serde::Serialize;
use super::constant::*;
use chrono::Local;
use tokio::net::TcpStream;
use super::security::SecurityUtil;
use super::configuration::CONFIG;

#[derive(Serialize, Clone)]
struct RequestHeader {
    #[serde(rename = "Command")]
    command: u32,
    #[serde(rename = "ClientVersion")]
    client_version: String,
    #[serde(rename = "Output")]
    output_format: u8,
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "Compression")]
    compression: u8,
    #[serde(rename = "Encryption")]
    encryption: u8,
}

#[derive(Serialize, Clone)]
struct PgmonetaRequest<R>
where
    R: Serialize + Clone,
{
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: R,
}

pub struct PgmonetaClient;
impl PgmonetaClient {
    fn build_request_header(command: u32) -> RequestHeader {
        let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();
        RequestHeader {
            command,
            client_version: CLIENT_VERSION.to_string(),
            output_format: Format::JSON,
            timestamp,
            compression: Compression::NONE,
            encryption: Encryption::NONE,
        }
    }

    async fn connect_to_server(username: &str) -> anyhow::Result<TcpStream> {
        let config = CONFIG.get().expect("Configuration should be enabled");
        let security_util = SecurityUtil::new();

        if !config.admins.contains_key(username) {
            return Err(anyhow!("request_backup_info: unable to find user {username}"));
        }

        let password_encrypted = config.admins.get(username).expect("Username should be found");
        let master_key = security_util.load_master_key()?;
        let password = String::from_utf8(security_util.decrypt_from_base64_string(password_encrypted, &master_key[..])?)?;
        let stream =
            SecurityUtil::connect_to_server(&config.pgmoneta.host, config.pgmoneta.port, username, &password).await?;
        Ok(stream)
    }
}