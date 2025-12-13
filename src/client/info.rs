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

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::constant::Command;
use super::{PgmonetaClient, PgmonetaRequest};

#[derive(Serialize, Clone)]
struct InfoRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Backup")]
    backup: String,
}

impl PgmonetaClient {
    pub async fn request_backup_info(username: &str, server: &str, backup: &str) -> anyhow::Result<String> {
        let info_request = InfoRequest {
            server: server.to_string(),
            backup: backup.to_string(),
        };
        let mut stream = Self::connect_to_server(username).await?;
        let header = Self::build_request_header(Command::INFO);
        let request = PgmonetaRequest {
            request: info_request,
            header,
        };
        let request_str = serde_json::to_string(&request)?;
        stream.write_all(request_str.as_bytes()).await?;

        let mut response_str = String::new();
        stream.read_to_string(&mut response_str).await?;

        Ok(response_str)
    }
}
