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

use super::PgmonetaClient;
use crate::constant::Command;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
struct InfoRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Backup")]
    backup: String,
}

#[derive(Serialize, Clone, Debug)]
struct ListBackupsRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Sort")]
    sort: String,
}

impl PgmonetaClient {
    pub async fn request_backup_info(
        username: &str,
        server: &str,
        backup: &str,
    ) -> anyhow::Result<String> {
        let info_request = InfoRequest {
            server: server.to_string(),
            backup: backup.to_string(),
        };
        Self::forward_request(username, Command::INFO, info_request).await
    }

    pub async fn request_list_backups(
        username: &str,
        server: &str,
        sort: &str,
    ) -> anyhow::Result<String> {
        let list_backup_request = ListBackupsRequest {
            server: server.to_string(),
            sort: sort.to_string(),
        };
        Self::forward_request(username, Command::LIST_BACKUP, list_backup_request).await
    }
}
