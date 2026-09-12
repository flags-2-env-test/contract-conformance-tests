use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),
    #[error("JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    #[error("validator failed: {0}")]
    Validator(String),
}
