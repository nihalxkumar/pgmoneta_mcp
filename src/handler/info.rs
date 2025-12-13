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

use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;
use super::PgmonetaClient;
use super::PgmonetaHandler;
use rmcp::{ErrorData as McpError};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InfoRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
}

impl PgmonetaHandler {
    pub(super) async fn _get_backup_info(&self, request: InfoRequest) -> Result<CallToolResult, McpError> {
        let result = PgmonetaClient::request_backup_info(&request.username, &request.server, &request.backup_id).await.map_err(|e| {
            McpError::internal_error(format!("Failed to retrieve backup information: {:?}", e), None)
        })?;
        Self::_check_result(&result)?;
        Ok(CallToolResult::success(vec![Content::text(result)]))
    }
}
