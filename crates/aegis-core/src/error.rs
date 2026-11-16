use aegis_config::ConfigError;
use serde::Serialize;

pub type Result<T, E = CoreError> = std::result::Result<T, E>;

/// Errors surfaced to the UI. Messages must explain how to resolve the
/// problem and must never contain key material.
#[derive(Debug, Clone, thiserror::Error, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CoreError {
    #[error("{0}")]
    Config(ConfigError),
    #[error("profile not found")]
    NotFound,
    #[error("another operation is in progress; wait for it to finish or cancel it")]
    Busy,
    #[error("operation cancelled")]
    Cancelled,
    #[error("timed out after {seconds}s: {what}")]
    Timeout { what: String, seconds: u64 },
    #[error("{message}")]
    Invalid { message: String },
    #[error("not supported here: {message}")]
    Unsupported { message: String },
    #[error("permission denied: {message}")]
    PermissionDenied { message: String },
    #[error("backend error: {message}")]
    Backend { message: String },
    #[error("storage error: {message}")]
    Storage { message: String },
}

impl CoreError {
    pub fn backend(m: impl std::fmt::Display) -> Self {
        Self::Backend {
            message: m.to_string(),
        }
    }
    pub fn invalid(m: impl Into<String>) -> Self {
        Self::Invalid { message: m.into() }
    }
    pub fn unsupported(m: impl Into<String>) -> Self {
        Self::Unsupported { message: m.into() }
    }
    pub fn storage(m: impl std::fmt::Display) -> Self {
        Self::Storage {
            message: m.to_string(),
        }
    }
}

impl From<ConfigError> for CoreError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}
